//! Protocol-neutral core shared by the authenticated inbound proxies
//! (SOCKS5 and HTTP(S)): resolve, route, score, race, and dial one proxied
//! TCP target, then relay bytes between the client and the chosen upstream.
//!
//! Protocol framing stays in the inbound modules — RFC 1928 replies versus
//! HTTP status lines phrase the same outcomes; everything between
//! authentication and the byte relay lives here once. Like `socks5`, this
//! lives inside the TCP connection module tree so the `pub(super)` score,
//! dial, and relay helpers stay private to it.

use super::*;
use crate::relay::{RelayProgress, relay_proxy};
use honk_config::inbound::ProxyUser;
use subtle::ConstantTimeEq as _;

/// The entry in `users` that `username`/`password` proves, if any. Both
/// comparisons run in constant time — the same `subtle` technique the native
/// API applies to its credentials — so response timing leaks neither which
/// user names exist nor how much of a password matched. The scan keeps
/// running past a hit, bounding the time by the table's length rather than
/// its contents; the first matching entry wins.
pub(super) fn lookup_user<'a>(
    users: &'a [ProxyUser],
    username: &[u8],
    password: &[u8],
) -> Option<&'a ProxyUser> {
    let mut matched: Option<&ProxyUser> = None;
    let mut taken = subtle::Choice::from(0u8);
    for user in users {
        let hit =
            user.username.as_bytes().ct_eq(username) & user.password.as_bytes().ct_eq(password);
        let take = hit & !taken;
        taken |= hit;
        if bool::from(take) {
            matched = Some(user);
        }
    }
    matched
}

/// Where the client pointed the session, before local name resolution.
pub(super) enum ProxyTargetRequest {
    Address(SocketAddr),
    Domain { domain: String, port: u16 },
}

/// A resolution or policy refusal the inbound must phrase in its own
/// protocol (SOCKS5 reply code, HTTP status). The accounting side effects
/// — error stats, health nudges, connection balance — are already applied
/// at the point of refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProxyRefusal {
    /// The client named a domain honk could not resolve.
    ResolveFailed,
    /// Routing policy sent the flow to `block` (or only block nodes).
    Blocked,
    /// The selected outbound has no available candidate nodes.
    NoCandidates,
    /// Every candidate dial failed.
    DialFailed,
}

/// One established proxied session: a live upstream stream plus the
/// accounting handles the relay balances once bytes stop flowing.
pub(super) struct ProxySession {
    pub(super) stream: crate::proxy::ProxyStream,
    pub(super) node: Node,
    pub(super) outbound_name: String,
    pub(super) outbound_kind: crate::stats::OutboundKind,
    pub(super) target_addr: SocketAddr,
    /// The domain the client named, when it named one (kept for logging and
    /// for invariants the caller may phrase in its protocol).
    pub(super) domain: Option<String>,
    score_reporter: Option<crate::group::ScoreReporter>,
    outbound_guard: crate::stats::ActiveConnectionGuard,
}

impl ControlPlaneHandle {
    /// Resolve, route, and dial `request` on behalf of an authenticated
    /// inbound `user`. `Ok(Ok(..))` hands back the live upstream session;
    /// `Ok(Err(..))` is a refusal for the inbound to phrase in its
    /// protocol; `Err` is a transport or runtime fault for the supervisor
    /// to log.
    pub(super) async fn proxy_dial(
        &self,
        user: &str,
        client_addr: SocketAddr,
        request: ProxyTargetRequest,
        kind: &'static str,
    ) -> anyhow::Result<Result<ProxySession, ProxyRefusal>> {
        let (target_addr, domain) = match request {
            ProxyTargetRequest::Address(address) => (address, None),
            ProxyTargetRequest::Domain { domain, port } => {
                // The client handed us a name instead of the IP its own
                // resolver saw (intercepted flows dial an already-resolved
                // IP), so resolve it through honk's DNS to keep dip/geoip
                // routing and direct dials honest. Proxies still resolve
                // remotely through `target_domain` below.
                let resolved = match self
                    .dns_resolver
                    .resolve_for_source(&domain, client_addr)
                    .await
                {
                    Ok(resolved) => resolved,
                    Err(error) => {
                        debug!(%error, %domain, kind, "inbound target resolution failed");
                        return Ok(Err(ProxyRefusal::ResolveFailed));
                    }
                };
                let Some(address) = resolved
                    .ipv4
                    .first()
                    .or_else(|| resolved.ipv6.first())
                    .copied()
                else {
                    return Ok(Err(ProxyRefusal::ResolveFailed));
                };
                (SocketAddr::new(address, port), Some(domain))
            }
        };

        let (dial_mode, connect_timeout, overall_dial_timeout) = {
            let config = self.config.read().await;
            let connect_timeout = Duration::from_millis(config.global.connect_timeout_ms);
            (
                config
                    .global
                    .dial_mode
                    .parse::<DialMode>()
                    .map_err(|_| anyhow::anyhow!("invalid global.dial_mode"))?,
                connect_timeout,
                overall_dial_timeout(connect_timeout),
            )
        };
        let conn_info = crate::routing::ConnectionInfo {
            domain: domain.clone(),
            dst_ip: target_addr.ip(),
            dst_port: target_addr.port(),
            src_ip: client_addr.ip(),
            src_port: client_addr.port(),
            protocol: "tcp",
            process_name: None,
            mac: None,
            dscp: None,
            user: Some(user.to_owned()),
        };
        let mut observation = ConnectionObservation::begin(
            self.native.as_deref(),
            crate::observe::vocab::Network::Tcp,
            client_addr,
            target_addr,
        );
        // The client named the destination itself, so the domain is verified.
        let mut route = self
            .prepare_routing(
                dial_mode,
                &conn_info,
                true,
                None,
                #[cfg(feature = "native-api")]
                observation.is_recording(),
            )
            .await;
        let mode_decision = self.apply_mode_override(&mut route).await;
        let outbound_name = mode_decision.name;
        let mode_constraint = mode_decision.constraint;

        // Config's publication guard pins the group and runtime handles.
        let (generation_config, generation_group_manager, runtime_generation) = {
            let config = self.config.read().await;
            (
                Arc::clone(&config),
                self.group_manager.read().clone(),
                self.runtime_registry.read().clone(),
            )
        };
        let outbound_kind =
            crate::stats::OutboundKind::routed(&generation_group_manager, &outbound_name);
        let outbound_guard = self.stats.track_connection(&outbound_name, outbound_kind);

        let ipver = if target_addr.is_ipv6() {
            IpVersion::V6
        } else {
            IpVersion::V4
        };
        // `selection_chains` only feeds the native-api racing hooks.
        #[cfg_attr(not(feature = "native-api"), allow(unused_variables))]
        let (
            mut candidates,
            selection_mode,
            mut score_feedback,
            selection_chains,
            _final_owners,
            health_ipver,
        ) = {
            let context = tcp_score_context(target_addr, domain.as_deref(), ipver);
            let plan = observation.observe_tcp_plan(None, || {
                crate::control::reload::resolve_outbound_plan_for_target(
                    &generation_config,
                    &generation_group_manager,
                    &outbound_name,
                    &context,
                    mode_constraint,
                )
            });
            unpack_tcp_score_plan(plan)
        };
        // Same speculation bound as intercepted TCP: only a cold URLTest
        // group may race more than one candidate.
        if selection_mode == SelectionPlanMode::ColdUrlTest {
            candidates.truncate(3);
        } else {
            candidates.truncate(1);
        }
        score_feedback.retain(|id, _| candidates.iter().any(|node| node.id == *id));

        if candidates.is_empty() {
            debug!(
                user,
                outbound = %outbound_name,
                kind,
                "inbound has no available candidate nodes"
            );
            let group_manager = self.group_manager.read().clone();
            for node in group_manager.leaf_nodes_in_group(&outbound_name) {
                self.alive_set.notify_check_tcp(node.id);
            }
            self.stats.record_error(&outbound_name, outbound_kind);
            drop(outbound_guard);
            let refusal = if outbound_name == "block" {
                ProxyRefusal::Blocked
            } else {
                ProxyRefusal::NoCandidates
            };
            return Ok(Err(refusal));
        }
        // Reserved outbounds always dial by address; named proxies take the
        // domain for remote resolution when we have one.
        let target_domain = if matches!(
            outbound_name.as_str(),
            "direct" | "block" | "must_rules" | "control_plane_routing"
        ) {
            None
        } else {
            domain.clone()
        };

        let cold_urltest = selection_mode == SelectionPlanMode::ColdUrlTest;
        let candidate_refs: Vec<&Node> = candidates.iter().collect();
        let dial_deadline = tokio::time::Instant::now() + overall_dial_timeout;
        let raced = self
            .race_candidates(
                &candidate_refs,
                target_addr,
                target_domain,
                &outbound_name,
                outbound_kind,
                route.mark,
                connect_timeout,
                dial_deadline,
                Arc::clone(&runtime_generation),
                health_ipver,
                &score_feedback,
                cold_urltest,
                #[cfg(feature = "native-api")]
                &selection_chains,
                #[cfg(feature = "native-api")]
                &observation,
            )
            .await;
        let winner = match raced {
            Ok(Some(winner)) => winner,
            Ok(None) => {
                self.stats.record_error(&outbound_name, outbound_kind);
                drop(outbound_guard);
                let refusal = if outbound_name == "block" || only_block_nodes(&candidates) {
                    ProxyRefusal::Blocked
                } else {
                    ProxyRefusal::DialFailed
                };
                return Ok(Err(refusal));
            }
            Err(error) => {
                drop(outbound_guard);
                return Err(error);
            }
        };
        drop(score_feedback);

        Ok(Ok(ProxySession {
            stream: winner.stream,
            node: winner.node,
            outbound_name,
            outbound_kind,
            target_addr,
            domain,
            score_reporter: winner.reporter,
            outbound_guard,
        }))
    }

    /// Relay bytes between the client and the session's upstream until
    /// either side closes, then balance accounting and node scoring. The
    /// caller has already signaled success in its protocol (SOCKS5 reply,
    /// `200 Connection Established`, or a rewritten absolute-form request).
    pub(super) async fn proxy_relay(
        &self,
        client: &mut TcpStream,
        session: ProxySession,
        client_addr: SocketAddr,
        kind: &'static str,
    ) -> anyhow::Result<()> {
        let ProxySession {
            stream,
            node: _,
            outbound_name,
            outbound_kind,
            target_addr,
            domain: _,
            score_reporter,
            outbound_guard,
        } = session;

        let conn_upload = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let conn_download = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (outbound_upload, outbound_download) =
            self.stats.byte_counters(&outbound_name, outbound_kind);
        let first_response = score_reporter.as_ref().map(|reporter| {
            let reporter = reporter.clone();
            std::sync::Arc::new(move || reporter.first_response())
                as std::sync::Arc<dyn Fn() + Send + Sync>
        });
        let on_transfer = score_reporter.as_ref().map(|reporter| {
            let reporter = reporter.clone();
            std::sync::Arc::new(move |upload, download| {
                if upload != 0 {
                    reporter.tx(upload);
                }
                if download != 0 {
                    reporter.rx(download);
                }
            }) as std::sync::Arc<dyn Fn(u64, u64) + Send + Sync>
        });
        let relay_result = relay_proxy(
            client,
            stream,
            client_addr,
            target_addr,
            RelayProgress {
                upload: conn_upload,
                download: conn_download,
                outbound_upload: Some(outbound_upload),
                outbound_download: Some(outbound_download),
                first_response,
                on_transfer,
            },
        )
        .await;
        match &relay_result {
            Ok(_) => {
                if let Some(reporter) = &score_reporter {
                    reporter.finish(crate::group::ScoreOutcome::Success);
                }
            }
            Err(error) => {
                let io_err = error.downcast_ref::<std::io::Error>();
                if io_err.is_some_and(crate::relay::is_ignorable_connection_error) {
                    debug!(%client_addr, %target_addr, kind, "inbound relay closed");
                } else {
                    debug!(%error, %target_addr, %outbound_name, kind, "inbound relay ended");
                }
                self.stats.record_error(&outbound_name, outbound_kind);
                if let Some(reporter) = &score_reporter {
                    reporter.finish(tcp_relay_score_outcome(error));
                }
            }
        }
        drop(outbound_guard);
        relay_result.map(|_| ())
    }
}
