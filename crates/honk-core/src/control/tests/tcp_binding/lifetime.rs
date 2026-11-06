//! Lifetime authority comes from real accepted-FD adoption, never a fabricated pin.

use super::*;
use crate::control::connection::handoff::TcpFlowGuard;
use honk_ebpf_common::{
    RedirectEntry,
    conn::{TCP_CONN_STATE_CLOSING_TIMEOUT_NS, TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS, TcpState},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const UP: &[u8] = b"client bytes after native metadata age";
const DOWN: &[u8] = b"accepted child bytes after native metadata age";

/// A real accepted child that already exchanged bytes in both directions but is not
/// adopted, so it holds no native pin.
struct Settled {
    client: TcpStream,
    source: SocketAddr,
    key: TuplesKey,
    incarnation: u64,
    pins: HashMap<aya::maps::MapData, u64, u8>,
    syn: Vec<u8>,
    inject: Wire,
}

/// `aged` waits until the real boot clock can represent an expired tuple; `reuse` lets
/// the client rebind its source for a later SYN on the same tuple.
async fn settle(lab: &Lab, aged: bool, reuse: bool) -> anyhow::Result<(Settled, TcpStream)> {
    if aged {
        await_established_age().await?;
    }
    let mut hs = Handshake::open(lab, reuse).await?;
    let Child {
        stream: mut accepted,
        mut client,
        peer: source,
    } = hs.release().await?;
    accepted.set_nodelay(true)?;
    client.set_nodelay(true)?;
    // Establish that these exact sockets exchange real application bytes before
    // age manipulation. Drain ACKs before every backdate, not a guessed sleep.
    transfer(&mut client, &mut accepted, UP).await?;
    transfer(&mut accepted, &mut client, DOWN).await?;
    quiesce(&accepted, &client).await?;
    let (key, incarnation) = (hs.key, hs.original.incarnation);
    let pins = live_pins()?;
    ensure!(
        pins.get(&incarnation, 0).is_err(),
        "unadopted child was pinned"
    );
    let settled = Settled {
        client,
        source,
        key,
        incarnation,
        pins,
        syn: hs.syn,
        inject: hs.inject,
    };
    Ok((settled, accepted))
}

impl Settled {
    async fn adopt(&self, lab: &Lab, accepted: TcpStream) -> anyhow::Result<TcpFlowGuard> {
        let flow = adopt(&lab.handle, accepted, self.key).await?;
        ensure!(
            self.pins.get(&self.incarnation, 0)? == 1,
            "adoption did not pin exact incarnation"
        );
        ensure!(
            lab.handle.tcp_flow_pins.contains(&self.key),
            "adoption lost local tuple pin"
        );
        Ok(flow)
    }

    async fn finish(self, lab: &Lab, mut flow: TcpFlowGuard) -> anyhow::Result<()> {
        quiesce(flow.stream_mut(), &self.client).await?;
        ensure!(
            self.pins.get(&self.incarnation, 0)? == 1,
            "live transfer lost native owner"
        );
        assert_authority(&self.key, self.incarnation)?;
        close_and_retire(&lab.handle, flow, self.client, &self.key, self.incarnation).await
    }
}

pub(super) fn idle(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let (mut s, accepted) = settle(lab, true, false).await?;
        let mut flow = s.adopt(lab, accepted).await?;
        backdate(&lab.handle, &s.key, false).await?;
        transfer(&mut s.client, flow.stream_mut(), UP).await?;
        quiesce(flow.stream_mut(), &s.client).await?;
        backdate(&lab.handle, &s.key, false).await?;
        transfer(flow.stream_mut(), &mut s.client, DOWN).await?;
        s.finish(lab, flow).await
    })
}

pub(super) fn client_fin(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let (mut s, accepted) = settle(lab, true, false).await?;
        let mut flow = s.adopt(lab, accepted).await?;
        half_close(&mut s.client, flow.stream_mut()).await?;
        backdate(&lab.handle, &s.key, true).await?;
        transfer(flow.stream_mut(), &mut s.client, DOWN).await?;
        s.finish(lab, flow).await
    })
}

pub(super) fn server_fin(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let (mut s, accepted) = settle(lab, true, false).await?;
        let mut flow = s.adopt(lab, accepted).await?;
        half_close(flow.stream_mut(), &mut s.client).await?;
        backdate(&lab.handle, &s.key, true).await?;
        transfer(&mut s.client, flow.stream_mut(), UP).await?;
        s.finish(lab, flow).await
    })
}

pub(super) fn unowned_redirect(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab| unowned(lab, false).await)
}

pub(super) fn unowned_closing(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab| unowned(lab, true).await)
}

/// An aged tuple whose child was never adopted has no native pin: refusal must not
/// delete or refresh anything.
async fn unowned(lab: &Lab, closing: bool) -> anyhow::Result<()> {
    let (mut s, mut accepted) = settle(lab, true, false).await?;
    if closing {
        half_close(&mut s.client, &mut accepted).await?;
    }
    backdate(&lab.handle, &s.key, closing).await?;
    // Keep the real retirement worker from reclaiming an expiry hint while
    // checking the kernel's non-deletion contract; packets still execute TC.
    let backend = lab.handle.ebpf.read().await;
    let before = metadata(&s.key)?;
    if closing {
        refused(&mut accepted, &mut s.client, DOWN).await?;
    } else {
        refused(&mut s.client, &mut accepted, UP).await?;
    }
    assert_refused_metadata(&s.key, &before, closing)?;
    ensure!(
        s.pins.get(&s.incarnation, 0).is_err(),
        "refusal invented a pin"
    );
    drop(backend);
    Ok(())
}

pub(super) fn other_incarnation(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let (mut s, accepted) = settle(lab, true, false).await?;
        let mut flow = s.adopt(lab, accepted).await?;
        half_close(&mut s.client, flow.stream_mut()).await?;
        let newer = supersede(&lab.handle, &s.key).await?;
        ensure!(newer != s.incarnation && s.pins.get(&newer, 0).is_err());
        backdate(&lab.handle, &s.key, true).await?;
        let backend = lab.handle.ebpf.read().await;
        let before = metadata(&s.key)?;
        refused(flow.stream_mut(), &mut s.client, DOWN).await?;
        assert_refused_metadata(&s.key, &before, true)?;
        ensure!(
            s.pins.get(&s.incarnation, 0)? == 1,
            "foreign refusal removed old pin"
        );
        drop(backend);
        // Drop is exact-key cleanup even though tuple authority has moved.
        drop(flow);
        ensure!(
            s.pins.get(&s.incarnation, 0).is_err(),
            "old native pin leaked"
        );
        ensure!(
            !lab.handle.tcp_flow_pins.contains(&s.key),
            "old local pin leaked"
        );
        Ok(())
    })
}

pub(super) fn cancel(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let (mut s, accepted) = settle(lab, true, false).await?;
        let duplicate = duplicate_stream(&accepted)?;
        let mut flow = s.adopt(lab, accepted).await?;
        let result = adopt(&lab.handle, duplicate, s.key).await;
        ensure!(
            result.is_err(),
            "same real child admitted a second native owner"
        );
        ensure!(
            s.pins.get(&s.incarnation, 0)? == 1,
            "duplicate refusal damaged original pin"
        );
        ensure!(lab.handle.tcp_flow_pins.contains(&s.key));
        transfer(&mut s.client, flow.stream_mut(), UP).await?;
        quiesce(flow.stream_mut(), &s.client).await?;
        let before = metadata(&s.key)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let slot = sender.clone().reserve_owned().await?;
        let original_sink = lab.handle.retirement.sink.lock().replace(sender);
        let mut retirement = Box::pin(flow.retire(Default::default()));
        tokio::select! {
            biased;
            result = &mut retirement => anyhow::bail!("retirement crossed full admission: {result}"),
            _ = tokio::task::yield_now() => {}
        }
        ensure!(
            s.pins.get(&s.incarnation, 0)? == 1,
            "pending admission released native pin"
        );
        drop(retirement);
        *lab.handle.retirement.sink.lock() = original_sink;
        drop(slot);
        drop(receiver);
        // No await separates cancellation from these exact native/local checks.
        ensure!(
            s.pins.get(&s.incarnation, 0).is_err(),
            "cancelled admission leaked native pin"
        );
        ensure!(
            !lab.handle.tcp_flow_pins.contains(&s.key),
            "cancelled admission leaked local refcount"
        );
        assert_authority(&s.key, before.0.incarnation)
    })
}

pub(super) fn new_syn(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let (s, accepted) = settle(lab, true, true).await?;
        let flow = s.adopt(lab, accepted).await?;
        superseding_syn(lab, flow, s).await
    })
}

/// The SYN's ISN returns on a tuple whose old child is gone but still natively pinned:
/// the pin must force a fresh incarnation without moving to it. A real RST would also
/// leave Closing, which alone makes the SYN fresh, so Active is restored first.
pub(super) fn pinned_same_isn(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let (s, accepted) = settle(lab, false, false).await?;
        let flow = s.adopt(lab, accepted).await?;
        let Settled {
            client,
            key,
            incarnation,
            pins,
            syn,
            inject,
            ..
        } = s;
        let isn = syn_isn(&syn, lab.target.is_ipv6())?;
        reset_close(client)?;
        await_conn(&lab.handle, &key, "real RST reached Closing", |conn| {
            conn.state == TcpState::TcpStateClosing as u8
        })
        .await?;
        mutate_conn(&lab.handle, &key, |conn| {
            conn.state = TcpState::TcpStateActive as u8;
        })
        .await?;
        inject.replay(&syn)?;
        let fresh = await_conn(&lab.handle, &key, "pinned tuple got a fresh SYN", |conn| {
            conn.incarnation != incarnation
        })
        .await?;
        ensure!(
            fresh.tcp_syn_isn == isn,
            "fresh publication lost the SYN's ISN"
        );
        ensure!(
            pins.get(&incarnation, 0)? == 1 && pins.get(&fresh.incarnation, 0).is_err(),
            "the fresh incarnation moved or inherited the old native pin"
        );
        ensure!(
            lab.handle.tcp_flow_pins.contains(&key),
            "fresh SYN dropped the old local pin"
        );
        drop(flow);
        ensure!(
            pins.get(&incarnation, 0).is_err(),
            "old native pin outlived its guard"
        );
        ensure!(
            !lab.handle.tcp_flow_pins.contains(&key),
            "old local pin leaked"
        );
        Ok(())
    })
}

async fn adopt(
    handle: &ControlPlaneHandle,
    stream: TcpStream,
    key: TuplesKey,
) -> anyhow::Result<TcpFlowGuard> {
    let ownership = handle
        .ebpf
        .read()
        .await
        .tcp_socket_ownership(stream.as_fd())?;
    ensure!(
        matches!(ownership, TcpSocketOwnership::Kernel(_)),
        "real FD has no kernel proof"
    );
    #[cfg(feature = "native-api")]
    let observation = crate::control::connection::observation::ConnectionObservation::default();
    let (flow, handoff) = handle
        .adopt_tcp_flow(
            stream,
            key,
            #[cfg(feature = "native-api")]
            &observation,
        )
        .await?;
    ensure!(handoff.is_some(), "real adoption lost immutable handoff");
    Ok(flow)
}

fn live_pins() -> anyhow::Result<HashMap<aya::maps::MapData, u64, u8>> {
    Ok(HashMap::try_from(pinned_map(
        Path::new(ROOT),
        "TCP_LIVE_PINS",
    )?)?)
}

pub(super) fn pin_drop_error(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Manual, async |lab| {
        native_pin_error(lab, false).await
    })
}

pub(super) fn pin_retire_error(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Manual, async |lab| {
        native_pin_error(lab, true).await
    })
}

/// Keep an actually adopted guard across replacement of the real removal
/// worker. Only the exact native pin key is removed to force kernel ENOENT.
async fn native_pin_error(lab: &Lab, retire: bool) -> anyhow::Result<()> {
    let (s, accepted) = settle(lab, false, false).await?;
    let (handle, key, incarnation) = (&lab.handle, s.key, s.incarnation);
    let TestRetirement {
        task: old_task,
        fatal: mut old_fatal,
    } = TestRetirement::start(handle);
    let flow = adopt(handle, accepted, key).await?;
    let mut pins = live_pins()?;
    ensure!(
        pins.get(&incarnation, 0)? == 1,
        "real adoption did not retain native pin"
    );
    // A stale guard-captured sender must not be able to deliver the later error.
    old_fatal.close();
    drop(old_fatal);
    let (handoff_tx, handoff_rx) = tokio::sync::mpsc::channel(1);
    handle.udp_pool.set_remove_sink(handoff_tx);
    handle.retirement.sink.lock().take();
    let hints = tokio::time::timeout(NETNS_TEST_TIMEOUT, old_task).await??;
    *handle.retirement.hints.lock() = hints;
    let TestRetirement {
        task: current_task,
        fatal: mut current_fatal,
    } = TestRetirement::start(handle);
    drop(handoff_rx);
    {
        let _backend = handle.ebpf.write().await;
        pins.remove(&incarnation)?;
    }
    if retire {
        ensure!(
            !flow.retire(Default::default()).await,
            "native release failure was confirmed retired"
        );
    } else {
        // No queue admission occurred: this exercises TcpKernelPin::Drop, not
        // the worker's explicit release path or a manually echoed sender error.
        drop(flow);
    }
    let error = tokio::time::timeout(NETNS_TEST_TIMEOUT, current_fatal.recv())
        .await?
        .context("current removal epoch lost native pin release failure")?;
    ensure!(
        error.chain().any(|cause| cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.raw_os_error() == Some(libc::ENOENT))),
        "native release lost kernel ENOENT source: {error:#}"
    );
    ensure!(
        !handle.tcp_flow_pins.contains(&key),
        "failed native release leaked local owner"
    );
    ensure!(
        pins.get(&incarnation, 0).is_err(),
        "failed release recreated native pin"
    );
    // Join the actual worker so a late duplicate Drop report cannot hide behind
    // scheduling. Consumed explicit release must not retry/report again on Drop.
    let shutdown = handle.udp_pool.shutdown().await;
    handle.retirement.sink.lock().take();
    tokio::time::timeout(NETNS_TEST_TIMEOUT, current_task).await??;
    ensure!(
        shutdown.joined,
        "native release fixture did not drain UDP owner"
    );
    ensure!(
        current_fatal.try_recv().is_err(),
        "native release failure was reported twice"
    );
    assert_authority(&key, incarnation)?;
    Ok(())
}

fn metadata(key: &TuplesKey) -> anyhow::Result<(ConnState, RoutingHandoffEntry, RedirectEntry)> {
    let root = Path::new(ROOT);
    let flags = aya_obj::generated::BPF_F_LOCK as u64;
    let conns =
        pinned_hash_snapshot::<TuplesKey, FlowMapValue<ConnState>>(root, "CONN_STATE_MAP", flags)?;
    let handoffs = pinned_hash_snapshot::<TuplesKey, FlowMapValue<RoutingHandoffEntry>>(
        root,
        "ROUTING_HANDOFF_MAP",
        flags,
    )?;
    let redirects = pinned_hash_snapshot::<RedirectTuple, FlowMapValue<RedirectEntry>>(
        root,
        "REDIRECT_TRACK",
        flags,
    )?;
    let redirect_key = RedirectTuple::from_tuples(key);
    Ok((
        conns
            .into_iter()
            .find(|(candidate, _)| {
                super::super::support::bytes_of(candidate) == super::super::support::bytes_of(key)
            })
            .context("missing conn metadata")?
            .1
            .value,
        handoffs
            .into_iter()
            .find(|(candidate, _)| {
                super::super::support::bytes_of(candidate) == super::super::support::bytes_of(key)
            })
            .context("missing handoff metadata")?
            .1
            .value,
        redirects
            .into_iter()
            .find(|(candidate, _)| {
                super::super::support::bytes_of(candidate)
                    == super::super::support::bytes_of(&redirect_key)
            })
            .context("missing redirect metadata")?
            .1
            .value,
    ))
}

async fn backdate(
    handle: &ControlPlaneHandle,
    key: &TuplesKey,
    closing: bool,
) -> anyhow::Result<()> {
    let _backend = handle.ebpf.write().await;
    let (mut conn, mut handoff, mut redirect) = metadata(key)?;
    let now = monotonic_ns()?;
    let old_aux = now
        .checked_sub(TCP_CONN_STATE_ESTABLISHED_TIMEOUT_NS + 1)
        .context("kernel uptime too short to backdate actual redirect")?;
    // Preserve the real protocol state: Closing must have come from a FIN/RST.
    if closing {
        ensure!(
            conn.state == TcpState::TcpStateClosing as u8,
            "fixture never reached real Closing"
        );
        conn.last_seen_ns = now
            .checked_sub(TCP_CONN_STATE_CLOSING_TIMEOUT_NS + 1)
            .context("kernel uptime too short for Closing")?;
    } else {
        ensure!(
            conn.state == TcpState::TcpStateActive as u8,
            "idle fixture not ACTIVE"
        );
        conn.last_seen_ns = old_aux;
    }
    handoff.last_seen_ns = old_aux;
    redirect.last_seen_ns = old_aux;
    let root = Path::new(ROOT);
    let flags = 2 | aya_obj::generated::BPF_F_LOCK as u64;
    HashMap::<_, TuplesKey, FlowMapValue<ConnState>>::try_from(pinned_map(
        root,
        "CONN_STATE_MAP",
    )?)?
    .insert(key, &FlowMapValue::new(conn), flags)?;
    HashMap::<_, TuplesKey, FlowMapValue<RoutingHandoffEntry>>::try_from(pinned_map(
        root,
        "ROUTING_HANDOFF_MAP",
    )?)?
    .insert(key, &FlowMapValue::new(handoff), flags)?;
    HashMap::<_, RedirectTuple, FlowMapValue<RedirectEntry>>::try_from(pinned_map(
        root,
        "REDIRECT_TRACK",
    )?)?
    .insert(
        &RedirectTuple::from_tuples(key),
        &FlowMapValue::new(redirect),
        flags,
    )?;
    Ok(())
}

async fn transfer(
    sender: &mut TcpStream,
    receiver: &mut TcpStream,
    bytes: &[u8],
) -> anyhow::Result<()> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        sender.write_all(bytes).await?;
        let mut received = vec![0; bytes.len()];
        receiver.read_exact(&mut received).await?;
        ensure!(
            received == bytes,
            "aged live owner changed application bytes"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("aged live owner blackholed application bytes")?
}

async fn refused(
    sender: &mut TcpStream,
    receiver: &mut TcpStream,
    bytes: &[u8],
) -> anyhow::Result<()> {
    sender.write_all(bytes).await?;
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_millis(350), receiver.read(&mut byte)).await;
    ensure!(
        result.is_err(),
        "aged unowned tuple delivered data/EOF instead of refusing: {result:?}"
    );
    // A real TCP segment remains unacknowledged, not merely an unpolled write.
    ensure!(
        unacked(sender)? > 0,
        "negative fixture did not leave an actual unacknowledged segment"
    );
    Ok(())
}

fn assert_authority(key: &TuplesKey, incarnation: u64) -> anyhow::Result<()> {
    let (conn, handoff, redirect) = metadata(key)?;
    ensure!(
        conn.incarnation == incarnation
            && handoff.incarnation == incarnation
            && redirect.incarnation == incarnation,
        "packet/refusal deleted or rebound authoritative metadata"
    );
    Ok(())
}

fn assert_refused_metadata(
    key: &TuplesKey,
    before: &(ConnState, RoutingHandoffEntry, RedirectEntry),
    closing: bool,
) -> anyhow::Result<()> {
    assert_authority(key, before.0.incarnation)?;
    let after = metadata(key)?;
    if closing {
        ensure!(
            after.0.last_seen_ns == before.0.last_seen_ns,
            "unowned Closing was refreshed"
        );
    } else {
        ensure!(
            after.2.last_seen_ns == before.2.last_seen_ns,
            "unowned aged redirect was refreshed"
        );
    }
    Ok(())
}

async fn half_close(sender: &mut TcpStream, receiver: &mut TcpStream) -> anyhow::Result<()> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        sender.shutdown().await?;
        let mut byte = [0];
        ensure!(
            receiver.read(&mut byte).await? == 0,
            "real FIN did not reach peer EOF"
        );
        quiesce(sender, receiver).await
    })
    .await
    .context("actual half-close did not reach peer EOF")?
}

fn unacked(stream: &TcpStream) -> anyhow::Result<u32> {
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&info) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                (&mut info as *mut libc::tcp_info).cast(),
                &mut length,
            )
        } == 0,
        "TCP_INFO: {}",
        std::io::Error::last_os_error()
    );
    Ok(info.tcpi_unacked)
}

async fn quiesce(left: &TcpStream, right: &TcpStream) -> anyhow::Result<()> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        loop {
            if unacked(left)? == 0 && unacked(right)? == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("application/FIN ACKs did not drain before backdating")?
}

fn duplicate_stream(stream: &TcpStream) -> anyhow::Result<TcpStream> {
    let fd = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    ensure!(
        fd >= 0,
        "duplicate accepted FD: {}",
        std::io::Error::last_os_error()
    );
    Ok(TcpStream::from_std(unsafe {
        std::net::TcpStream::from_raw_fd(fd)
    })?)
}

async fn close_and_retire(
    handle: &ControlPlaneHandle,
    mut flow: TcpFlowGuard,
    mut client: TcpStream,
    key: &TuplesKey,
    incarnation: u64,
) -> anyhow::Result<()> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        client.shutdown().await?;
        let mut rest = Vec::new();
        flow.stream_mut().read_to_end(&mut rest).await?;
        ensure!(rest.is_empty(), "unexpected trailing client bytes");
        flow.stream_mut().shutdown().await?;
        client.read_to_end(&mut rest).await?;
        ensure!(rest.is_empty(), "unexpected trailing server bytes");
        ensure!(
            flow.retire(Default::default()).await,
            "normal worker retirement was not confirmed"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("normal TCP closure/retirement did not complete")??;
    ensure!(
        live_pins()?.get(&incarnation, 0).is_err(),
        "normal closure leaked native pin"
    );
    ensure!(
        !handle.tcp_flow_pins.contains(key),
        "normal closure leaked local tuple pin"
    );
    let backend = handle.ebpf.read().await;
    ensure!(
        backend.conn_state_lookup(key)?.is_none(),
        "normal retirement retained conn"
    );
    ensure!(
        backend.routing_handoff_lookup(key)?.is_none(),
        "normal retirement retained handoff"
    );
    ensure!(
        backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(key))?
            .is_none(),
        "normal retirement retained redirect"
    );
    Ok(())
}

/// A real RST frees the client's tuple without waiting for TIME_WAIT, while the accepted
/// FD and any native guard on it stay alive.
fn reset_close(client: TcpStream) -> anyhow::Result<()> {
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    ensure!(
        unsafe {
            libc::setsockopt(
                client.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&linger as *const libc::linger).cast(),
                std::mem::size_of_val(&linger) as _,
            )
        } == 0,
        "set client RST close"
    );
    drop(client);
    Ok(())
}

async fn superseding_syn(lab: &Lab, old: TcpFlowGuard, s: Settled) -> anyhow::Result<()> {
    let (handle, listener, client_ns) = (&lab.handle, &lab.listener, &lab.client_ns);
    let target = lab.target;
    let Settled {
        client,
        source,
        key,
        incarnation: old_incarnation,
        ..
    } = s;
    reset_close(client)?;
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        while metadata(&key)?.0.state != TcpState::TcpStateClosing as u8 {
            tokio::task::yield_now().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("real old-client RST did not reach TC")??;
    let socket = in_test_netns(client_ns, || -> anyhow::Result<_> {
        let socket = if source.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        socket.set_reuseaddr(true)?;
        socket.bind(source)?;
        Ok(socket)
    })?;
    let mut client = tokio::time::timeout(NETNS_TEST_TIMEOUT, socket.connect(target)).await??;
    let (mut accepted, peer) =
        tokio::time::timeout(NETNS_TEST_TIMEOUT, listener.accept()).await??;
    ensure!(
        peer == source && accepted.local_addr()? == target,
        "superseding SYN changed tuple"
    );
    client.set_nodelay(true)?;
    accepted.set_nodelay(true)?;
    let newer = metadata(&key)?.0.incarnation;
    ensure!(
        newer != 0 && newer != old_incarnation,
        "ordinary SYN reused old incarnation"
    );
    let pins = live_pins()?;
    ensure!(
        pins.get(&old_incarnation, 0)? == 1 && pins.get(&newer, 0).is_err(),
        "new SYN inherited old pin"
    );
    transfer(&mut client, &mut accepted, UP).await?;
    quiesce(&accepted, &client).await?;
    backdate(handle, &key, false).await?;
    {
        let _backend = handle.ebpf.read().await;
        let before = metadata(&key)?;
        refused(&mut client, &mut accepted, UP).await?;
        assert_refused_metadata(&key, &before, false)?;
    }
    let mut new = adopt(handle, accepted, key).await?;
    ensure!(
        pins.get(&old_incarnation, 0)? == 1 && pins.get(&newer, 0)? == 1,
        "independent child adoption did not retain both incarnations"
    );
    // The refused segment must now arrive on retransmission using the new
    // child's own pin; do not rewrite timestamps or replay application bytes.
    let mut received = vec![0; UP.len()];
    tokio::time::timeout(
        NETNS_TEST_TIMEOUT,
        new.stream_mut().read_exact(&mut received),
    )
    .await??;
    ensure!(
        received == UP,
        "new native owner failed to resume refused real TCP bytes"
    );
    ensure!(
        old.retire(Default::default()).await,
        "superseded old owner retirement failed"
    );
    ensure!(
        pins.get(&old_incarnation, 0).is_err() && pins.get(&newer, 0)? == 1,
        "old retirement removed/leaked an incarnation pin"
    );
    ensure!(
        handle.tcp_flow_pins.contains(&key),
        "old retirement removed newer tuple-local owner"
    );
    assert_authority(&key, newer)?;
    quiesce(new.stream_mut(), &client).await?;
    backdate(handle, &key, false).await?;
    transfer(new.stream_mut(), &mut client, DOWN).await?;
    close_and_retire(handle, new, client, &key, newer).await
}
