//! The exact TC action for a SYN whose tuple already has a publication. TC never reads the
//! kernel's request, so each case pins Cached, Fresh or refusal by what the SYN leaves behind
//! (incarnation, ISN, whether the daens ever saw it), not by "anything but Cached".

use super::*;
use honk_ebpf_common::conn::{ROUTING_HANDOFF_TIMEOUT_NS, TCP_SYN_ORIGINAL_INTERCEPT, TcpState};

/// Far outside any receive window, so the kernel keeps its request for the original ISN
/// when a SYN with this distance arrives.
const OTHER_ISN_DISTANCE: u32 = 0x4000_0000;

impl Handshake<'_> {
    fn collect_syns(&mut self) -> anyhow::Result<()> {
        let syns = self.tap.drain_syns(self.source.ip(), self.lab.target)?;
        self.arrived.extend(syns);
        Ok(())
    }

    fn syn_count(&self, port: u16, isn: u32) -> usize {
        self.arrived
            .iter()
            .filter(|seen| **seen == (port, isn))
            .count()
    }

    /// Waits until `count` SYNs carrying `isn` have crossed host TC into the daens.
    async fn await_syns(&mut self, isn: u32, count: usize) -> anyhow::Result<()> {
        let port = self.source.port();
        let deadline = tokio::time::Instant::now() + NETNS_TEST_TIMEOUT;
        loop {
            self.collect_syns()?;
            if self.syn_count(port, isn) >= count {
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "the daens never saw {count} SYN(s) with ISN {isn:#x}: {:x?}",
                self.arrived
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// TC must drop `frame`. A drop is only an absence, so a SYN of another tuple sent behind
    /// it orders the check: once the daens has that marker, TC has run on `frame` too.
    async fn assert_refused(&mut self, frame: &[u8]) -> anyhow::Result<()> {
        let port = self.source.port();
        let isn = syn_isn(frame, self.ipv6())?;
        self.collect_syns()?;
        let before = self.syn_count(port, isn);
        self.inject.replay(frame)?;
        self.markers += 1;
        let marker = port.wrapping_add(self.markers);
        self.inject
            .replay(&with_source_port(&self.syn, self.ipv6(), marker)?)?;
        let deadline = tokio::time::Instant::now() + NETNS_TEST_TIMEOUT;
        loop {
            self.collect_syns()?;
            if self.syn_count(marker, self.isn) > 0 {
                break;
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "the marker SYN sent behind the refused one never reached the daens"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.collect_syns()?;
        let after = self.syn_count(port, isn);
        ensure!(
            after == before,
            "TC passed SYN {isn:#x} it must refuse ({before} -> {after})"
        );
        Ok(())
    }

    /// The conn-state once TC judged a SYN fresh: another incarnation carrying `isn`, whose
    /// handoff and redirect are committed under it.
    async fn await_fresh(&self, isn: u32, replaced: u64) -> anyhow::Result<ConnState> {
        let fresh = await_conn(
            &self.lab.handle,
            &self.key,
            "a fresh incarnation with committed interception",
            |conn| {
                conn.incarnation != replaced
                    && conn.tcp_syn_isn == isn
                    && conn.tcp_syn_flags & TCP_SYN_ORIGINAL_INTERCEPT != 0
            },
        )
        .await?;
        let lineage = Lineage::read(&self.lab.handle, &self.key).await?;
        ensure!(
            lineage.handoff.incarnation == fresh.incarnation
                && lineage.redirect.incarnation == fresh.incarnation,
            "fresh SYN left auxiliaries of another incarnation: {lineage:?}"
        );
        Ok(fresh)
    }

    /// The client closes and answers the captured SYNACK with a real RST: the daens request
    /// dies and TC marks the tuple Closing, leaving the publication behind.
    async fn reset_request(&mut self) -> anyhow::Result<()> {
        self.client = None;
        self.wire.replay(&self.synack)?;
        await_conn(
            &self.lab.handle,
            &self.key,
            "Closing after the real RST",
            |conn| conn.state == TcpState::TcpStateClosing as u8,
        )
        .await?;
        let (source, target) = (self.source, self.lab.target);
        tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
            while request_alive(source, target)? {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("the real RST did not destroy the daens request")?
    }
}

/// Whether the daens still holds a SYN_RECV request for this connection.
fn request_alive(source: SocketAddr, target: SocketAddr) -> anyhow::Result<bool> {
    daens::with_daens_netns("read daens TCP table", || {
        let table = std::fs::read_to_string(if target.is_ipv6() {
            "/proc/thread-self/net/tcp6"
        } else {
            "/proc/thread-self/net/tcp"
        })?;
        let local = format!(":{:04X}", target.port());
        let remote = format!(":{:04X}", source.port());
        Ok(table.lines().skip(1).any(|line| {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            fields.len() > 3
                && fields[1].ends_with(&local)
                && fields[2].ends_with(&remote)
                && fields[3] == "03"
        }))
    })
}

/// Same ISN, no kernel object, unpinned, Active and a complete fresh publication: TC keeps
/// the publication.
pub(super) fn absent_after_history(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        let published = Lineage::read(&lab.handle, &hs.key).await?;
        hs.reset_request().await?;
        mutate_conn(&lab.handle, &hs.key, |conn| {
            conn.state = TcpState::TcpStateActive as u8;
        })
        .await?;
        let isn = hs.isn;
        hs.inject.replay(&hs.syn)?;
        hs.await_syns(isn, 2).await?;
        let retry = Lineage::read(&lab.handle, &hs.key).await?;
        ensure!(
            routing_view(&published) == routing_view(&retry),
            "an absent owner's same-ISN SYN replaced the publication:\n{published:#?}\n->\n{retry:#?}"
        );
        Ok(())
    })
}

/// The kernel keeps request A when SYN B (another ISN) arrives, yet TC cannot see it: B is
/// Fresh, a second B is Cached, and the ACK for A then finds the tuple bound to B.
pub(super) fn request_a_then_b(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        let b = hs.isn.wrapping_add(OTHER_ISN_DISTANCE);
        let syn_b = with_syn_isn(&hs.syn, hs.ipv6(), b)?;
        hs.inject.replay(&syn_b)?;
        let fresh = hs.await_fresh(b, hs.original.incarnation).await?;
        hs.await_syns(b, 1).await?;
        let first = Lineage::read(&lab.handle, &hs.key).await?;
        hs.inject.replay(&syn_b)?;
        hs.await_syns(b, 2).await?;
        let second = Lineage::read(&lab.handle, &hs.key).await?;
        ensure!(
            second.conn.incarnation == fresh.incarnation
                && routing_view(&first) == routing_view(&second),
            "the second SYN B was not Cached:\n{first:#?}\n->\n{second:#?}"
        );
        let client = hs.client.as_mut().context("client already closed")?;
        ensure!(
            client.retry_count().await? == 0,
            "the client retried SYN A before ACK A was released, so ISN A may own the tuple again"
        );
        let child = hs.release().await?;
        hs.unproven(child, Authority::all(fresh.incarnation)).await
    })
}

/// A present but aged handoff makes the same-ISN SYN Fresh instead of reusing the
/// publication or refusing it.
pub(super) fn stale(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        await_established_age().await?;
        let mut hs = Handshake::open(lab, false).await?;
        let aged = monotonic_ns()?
            .checked_sub(ROUTING_HANDOFF_TIMEOUT_NS + 1)
            .context("kernel uptime too short to age the handoff")?;
        mutate_handoff(&lab.handle, &hs.key, |handoff| handoff.last_seen_ns = aged).await?;
        let isn = hs.isn;
        hs.inject.replay(&hs.syn)?;
        hs.await_fresh(isn, hs.original.incarnation).await?;
        hs.await_syns(isn, 2).await
    })
}

/// After a real RST the tuple is Closing: the same ISN gets a fresh incarnation. Restoring
/// Active (see `absent_after_history`) is the only difference between the two cases.
pub(super) fn closing(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        hs.reset_request().await?;
        let isn = hs.isn;
        hs.inject.replay(&hs.syn)?;
        hs.await_fresh(isn, hs.original.incarnation).await?;
        hs.await_syns(isn, 2).await
    })
}

#[derive(Clone, Copy)]
enum Missing {
    Handoff,
    Redirect,
}

enum Removed {
    Handoff(FlowMapValue<RoutingHandoffEntry>),
    Redirect(FlowMapValue<RedirectEntry>),
}

pub(super) fn missing_handoff(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        refuses_without(lab, Missing::Handoff).await
    })
}

pub(super) fn missing_redirect(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        refuses_without(lab, Missing::Redirect).await
    })
}

/// A tuple whose committed auxiliary is gone cannot be proven again: the same-ISN SYN is
/// dropped, never delivered, and nothing is rebuilt.
async fn refuses_without(lab: &Lab, missing: Missing) -> anyhow::Result<()> {
    let mut hs = Handshake::open(lab, false).await?;
    let (key, incarnation) = (hs.key, hs.original.incarnation);
    let removed = {
        let _backend = lab.handle.ebpf.write().await;
        match missing {
            Missing::Handoff => {
                let mut handoffs = handoff_map()?;
                let saved = handoffs.get(&key, MAP_LOCK)?;
                handoffs.remove(&key)?;
                Removed::Handoff(saved)
            }
            Missing::Redirect => {
                let mut redirects = redirect_map()?;
                let redirect_key = RedirectTuple::from_tuples(&key);
                let saved = redirects.get(&redirect_key, MAP_LOCK)?;
                redirects.remove(&redirect_key)?;
                Removed::Redirect(saved)
            }
        }
    };
    let syn = hs.syn.clone();
    hs.assert_refused(&syn).await?;
    {
        let backend = lab.handle.ebpf.read().await;
        ensure!(
            backend
                .conn_state_lookup(&key)?
                .map(|conn| (conn.incarnation, conn.tcp_syn_isn))
                == Some((incarnation, hs.isn)),
            "the refused SYN rebound conn-state"
        );
        let handoff = backend
            .routing_handoff_lookup(&key)?
            .map(|entry| entry.incarnation);
        let redirect = backend
            .redirect_track_lookup(&RedirectTuple::from_tuples(&key))?
            .map(|entry| entry.incarnation);
        let expected = match missing {
            Missing::Handoff => (None, Some(incarnation)),
            Missing::Redirect => (Some(incarnation), None),
        };
        ensure!(
            (handoff, redirect) == expected,
            "the refused SYN rebuilt or deleted a publication: handoff {handoff:?}, redirect {redirect:?}"
        );
    }
    let _backend = lab.handle.ebpf.write().await;
    match removed {
        Removed::Handoff(saved) => handoff_map()?.insert(&key, &saved, 1)?,
        Removed::Redirect(saved) => {
            redirect_map()?.insert(&RedirectTuple::from_tuples(&key), &saved, 1)?
        }
    }
    Ok(())
}

/// A full child answers by its own storage: the stored ISN selects Cached or Fresh.
pub(super) fn full_child(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        let child = hs.release().await?;
        hs.assert_proven(&child).await?;
        let published = Lineage::read(&lab.handle, &hs.key).await?;
        let isn = hs.isn;
        hs.inject.replay(&hs.syn)?;
        hs.await_syns(isn, 2).await?;
        let same = Lineage::read(&lab.handle, &hs.key).await?;
        ensure!(
            routing_view(&published) == routing_view(&same),
            "a same-ISN SYN against the proven child replaced its publication:\n{published:#?}\n->\n{same:#?}"
        );
        let other = isn.wrapping_add(OTHER_ISN_DISTANCE);
        hs.inject
            .replay(&with_syn_isn(&hs.syn, hs.ipv6(), other)?)?;
        hs.await_fresh(other, hs.original.incarnation).await?;
        hs.await_syns(other, 1).await?;
        drop(child);
        Ok(())
    })
}

/// A full child without proof storage is refused whatever the SYN's ISN: only the storage
/// can authorize reuse, and the ISN comparison needs it.
pub(super) fn full_child_unproven(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        let child = release_without_storage(&mut hs).await?;
        ensure!(
            lab.ownership(&child.stream).await.is_err(),
            "the fixture failed to deny child storage"
        );
        let same = hs.syn.clone();
        hs.assert_refused(&same).await?;
        let other = with_syn_isn(&hs.syn, hs.ipv6(), hs.isn.wrapping_add(OTHER_ISN_DISTANCE))?;
        hs.assert_refused(&other).await?;
        let conn = lab
            .handle
            .ebpf
            .read()
            .await
            .conn_state_lookup(&hs.key)?
            .context("refused SYNs deleted conn-state")?;
        ensure!(
            conn.incarnation == hs.original.incarnation && conn.tcp_syn_isn == hs.isn,
            "refused SYNs rebound conn-state"
        );
        drop(child);
        Ok(())
    })
}
