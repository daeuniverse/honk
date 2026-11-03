//! The sock_ops callback's verdict, observed through the final ACK of a real handshake.
//! A final ACK for a missing conn-state, a missing or foreign redirect, or a retiring tuple
//! is dropped, passed natively or repaired by TC before the child exists, so a real
//! handshake never reaches those predicates; only a driver for the callback itself could.

use super::super::support::netns::add_address;
use super::*;
use honk_ebpf_common::conn::{TCP_SYN_ORIGINAL_INTERCEPT, TcpState};

#[derive(Clone, Copy, Debug)]
enum Fault {
    WrongIsn,
    NoOriginalIntercept,
    NoHandoff,
    HandoffIncarnation,
}

pub(super) fn predicates(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        for fault in [
            Fault::WrongIsn,
            Fault::NoOriginalIntercept,
            Fault::NoHandoff,
            Fault::HandoffIncarnation,
        ] {
            reject(lab, fault)
                .await
                .with_context(|| format!("callback predicate {fault:?}"))?;
        }
        Ok(())
    })
}

/// The publication is damaged after the SYN and before the final ACK, in the one way the
/// ACK itself tolerates; the callback must leave the child without proof, adoption must
/// refuse it, and the tuple's competing authority must survive.
async fn reject(lab: &Lab, fault: Fault) -> anyhow::Result<()> {
    let mut hs = Handshake::open(lab, false).await?;
    let (key, incarnation) = (hs.key, hs.original.incarnation);
    let mut authority = Authority::all(incarnation);
    match fault {
        Fault::WrongIsn => mutate_conn(&lab.handle, &key, |conn| conn.tcp_syn_isn ^= 1).await?,
        Fault::NoOriginalIntercept => {
            mutate_conn(&lab.handle, &key, |conn| {
                conn.tcp_syn_flags &= !TCP_SYN_ORIGINAL_INTERCEPT;
            })
            .await?
        }
        Fault::NoHandoff => {
            let _backend = lab.handle.ebpf.write().await;
            handoff_map()?.remove(&key)?;
            authority.handoff = None;
        }
        Fault::HandoffIncarnation => {
            mutate_handoff(&lab.handle, &key, |handoff| handoff.incarnation += 1).await?;
            authority.handoff = Some(incarnation + 1);
        }
    }
    let child = hs.release().await?;
    hs.unproven(child, authority).await
}

/// TC marks Closing on a FIN or RST it sees before, or on, the segment that completes the
/// handshake, so a Closing publication must still prove its child.
pub(super) fn closing(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let mut hs = Handshake::open(lab, false).await?;
        mutate_conn(&lab.handle, &hs.key, |conn| {
            conn.state = TcpState::TcpStateClosing as u8;
        })
        .await?;
        let child = hs.release().await?;
        hs.assert_proven(&child).await?;
        admit(lab, child).await
    })
}

/// A child of a foreign namespace whose tuple and ISN equal a valid publication stays
/// unproven: only the owned daens may bind. The twin handshake runs on loopback in a fresh
/// namespace with its SYNACK held, so its ISN is known before the publication is seeded.
pub(super) fn foreign_twin(family: &str) -> anyhow::Result<()> {
    run_child(family, Kind::Proxy, async |lab: &Lab| {
        let template = Handshake::open(lab, false).await?;
        let published = Lineage::read(&lab.handle, &template.key).await?;
        let (client_ip, target) = (lab.client, lab.target);
        let foreign = fresh_test_netns();
        in_test_netns(&foreign, || -> anyhow::Result<()> {
            let mut netlink = crate::netlink::NlSock::new()?;
            let (loopback, _) = netlink.get_link("lo")?;
            netlink.set_link_up(loopback, true)?;
            for ip in [client_ip, target.ip()] {
                add_address(&mut netlink, loopback, "lo", ip)?;
            }
            // The replayed SYNACK has a local source address, which the stack drops
            // as a martian unless the namespace accepts it.
            for name in ["all", "lo"] {
                for (setting, value) in [("accept_local", "1"), ("rp_filter", "0")] {
                    std::fs::write(format!("/proc/sys/net/ipv4/conf/{name}/{setting}"), value)?;
                }
            }
            Ok(())
        })?;
        let listener = TcpListener::from_std(retransmit::listen(&foreign, target)?)?;
        let wire = in_test_netns(&foreign, || Wire::on("lo"))?;
        let (mut client, source) = Client::lan(&foreign, client_ip, target, false)?;
        let synack = gated_synack(&mut client, &wire, source, target).await?;
        let syn = tokio::time::timeout(NETNS_TEST_TIMEOUT, wire.syn(source, target))
            .await
            .context("foreign SYN capture deadline")??;
        let twin = conn_key(source, target);
        {
            let _backend = lab.handle.ebpf.write().await;
            let mut conn = published.conn;
            conn.tcp_syn_isn = syn_isn(&syn, target.is_ipv6())?;
            conn_map()?.insert(&twin, &FlowMapValue::new(conn), 1)?;
            handoff_map()?.insert(&twin, &FlowMapValue::new(published.handoff), 1)?;
            redirect_map()?.insert(
                &RedirectTuple::from_tuples(&twin),
                &FlowMapValue::new(published.redirect),
                1,
            )?;
        }
        client.release()?;
        wire.replay(&synack)?;
        let _client = client.handshake().await?;
        let (child, peer) = tokio::time::timeout(NETNS_TEST_TIMEOUT, listener.accept())
            .await
            .context("foreign accept deadline")??;
        ensure!(
            peer == source && child.local_addr()? == target,
            "the foreign twin has the wrong endpoints"
        );
        ensure!(
            lab.ownership(&child).await.is_err(),
            "a foreign-namespace child was proven by a same-tuple, same-ISN publication"
        );
        Ok(())
    })
}
