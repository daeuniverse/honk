//! Process-scoped inbound proxy listeners for `inbound.socks5` and
//! `inbound.http`.
//!
//! Like the standalone DNS listener these are ordinary host-netns sockets:
//! they carry no proxy marks and never enter `daens`. Accepted connections
//! authenticate through `ControlPlaneHandle::serve_socks5` or
//! `ControlPlaneHandle::serve_http` before a single proxied byte flows, then
//! reuse the intercepted flows' scoring, dial racing, and relay machinery
//! with the username attached as a routing fact. One generic supervisor loop
//! serves both protocols; only the session handler and the log label differ.

use super::ConnectionGuard;
use super::connection::ControlPlaneHandle;
use crate::control::drain::DrainTracker;
use honk_config::inbound::ProxyUser;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::{debug, info};

/// Same per-listener reserve as the standalone DNS listener: at most a
/// quarter of the shared flow budget per listener, never zero capacity.
const fn per_listener_capacity(total_connection_capacity: usize) -> usize {
    if total_connection_capacity == 0 {
        0
    } else {
        let quarter = total_connection_capacity / 4;
        if quarter == 0 { 1 } else { quarter }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerPhase {
    Running,
    StopAccepting,
    Abort,
}

/// Which protocol a listener serves; selects the session handler and the
/// log label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InboundKind {
    Socks5,
    Http,
}

impl InboundKind {
    fn label(self) -> &'static str {
        match self {
            Self::Socks5 => "SOCKS5",
            Self::Http => "HTTP",
        }
    }
}

/// Sockets bound synchronously so an unreachable listener address fails
/// startup atomically instead of half-spawning supervisors.
pub(super) struct BoundInboundListener {
    kind: InboundKind,
    listener: std::net::TcpListener,
    users: Arc<Vec<ProxyUser>>,
}

impl BoundInboundListener {
    pub(super) fn bind(kind: InboundKind, bind: &str, users: &[ProxyUser]) -> io::Result<Self> {
        let mut candidates: Vec<SocketAddr> = bind.to_socket_addrs()?.collect();
        candidates.dedup();
        let mut last_error = None;
        for candidate in candidates {
            match bind_listener(candidate) {
                Ok(listener) => {
                    return Ok(Self {
                        kind,
                        listener,
                        users: Arc::new(users.to_vec()),
                    });
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("inbound listener bind {bind} resolved to no address"),
            )
        }))
    }

    pub(super) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub(super) fn spawn(
        self,
        plane: ControlPlaneHandle,
        connection_limit: Arc<Semaphore>,
        drain: Arc<DrainTracker>,
    ) -> io::Result<InboundListener> {
        let Self {
            kind,
            listener,
            users,
        } = self;
        let address = listener.local_addr()?;
        let listener = TcpListener::from_std(listener)?;
        info!(%address, kind = kind.label(), "inbound listener started");
        let (phase, phase_rx) = watch::channel(ListenerPhase::Running);
        let listener_limit = Arc::new(Semaphore::new(per_listener_capacity(
            connection_limit.available_permits(),
        )));
        let mut supervisors = JoinSet::new();
        supervisors.spawn(run_inbound_supervisor(
            listener,
            plane,
            connection_limit,
            listener_limit,
            users,
            drain,
            phase_rx,
            kind,
        ));
        Ok(InboundListener { phase, supervisors })
    }
}

fn bind_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    // SO_REUSEADDR permits an immediate process restart across accepted
    // connections in TIME_WAIT; without SO_REUSEPORT it cannot share a live
    // listener tuple.
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// Supervisor ownership retained by the runtime epoch for one listener.
pub(super) struct InboundListener {
    phase: watch::Sender<ListenerPhase>,
    supervisors: JoinSet<anyhow::Result<()>>,
}

impl InboundListener {
    /// Close accept admission while already authenticated sessions finish as
    /// part of the control plane's ordinary bounded drain.
    pub(super) fn stop_accepting(&self) {
        let _ = self.phase.send(ListenerPhase::StopAccepting);
    }

    /// Force-cancel any session that outlived the bounded drain and join the
    /// supervisor, leaving no detached connection task behind.
    pub(super) async fn abort_and_join(&mut self) -> anyhow::Result<()> {
        let _ = self.phase.send(ListenerPhase::Abort);
        let mut failure = None;
        while let Some(result) = self.supervisors.join_next().await {
            if let Err(error) = result
                .map_err(anyhow::Error::from)
                .and_then(|result| result)
            {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for InboundListener {
    fn drop(&mut self) {
        let _ = self.phase.send(ListenerPhase::Abort);
        self.supervisors.abort_all();
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_inbound_supervisor(
    listener: TcpListener,
    plane: ControlPlaneHandle,
    connection_limit: Arc<Semaphore>,
    listener_limit: Arc<Semaphore>,
    users: Arc<Vec<ProxyUser>>,
    drain: Arc<DrainTracker>,
    mut phase: watch::Receiver<ListenerPhase>,
    kind: InboundKind,
) -> anyhow::Result<()> {
    let label = kind.label();
    let mut children = JoinSet::new();
    let mut failure = None;
    // A persistent accept error repeats every iteration; warn once per episode.
    let mut accept_failing = false;

    loop {
        tokio::select! {
            biased;
            changed = phase.changed() => {
                if changed.is_err() || *phase.borrow() != ListenerPhase::Running {
                    break;
                }
            }
            completed = children.join_next(), if !children.is_empty() => {
                retain_child_result(&mut failure, completed, false, label);
            }
            accepted = listener.accept() => {
                let (stream, client_addr) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        crate::logging::warn_on_entry!(
                            !std::mem::replace(&mut accept_failing, true),
                            error_kind = ?error.kind(),
                            kind = label,
                            "inbound accept failed"
                        );
                        continue;
                    }
                };
                if std::mem::replace(&mut accept_failing, false) {
                    info!(kind = label, "inbound accept recovered");
                }
                if *phase.borrow() != ListenerPhase::Running || drain.should_reject() {
                    continue;
                }
                let listener_permit = match Arc::clone(&listener_limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(%client_addr, kind = label, "dropping inbound connection at listener capacity");
                        continue;
                    }
                };
                let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        debug!(%client_addr, kind = label, "dropping inbound connection at capacity");
                        continue;
                    }
                };
                let guard = ConnectionGuard::new(Arc::clone(&drain));
                let plane = plane.clone();
                let users = Arc::clone(&users);
                children.spawn(async move {
                    let _permit = permit;
                    let _listener_permit = listener_permit;
                    let _guard = guard;
                    let served = match kind {
                        InboundKind::Socks5 => {
                            plane.serve_socks5(stream, client_addr, &users).await
                        }
                        InboundKind::Http => plane.serve_http(stream, client_addr, &users).await,
                    };
                    if let Err(error) = served {
                        debug!(%error, %client_addr, kind = label, "inbound connection failed");
                    }
                });
            }
        }
    }

    drop(listener);
    finish_children(&mut children, &mut phase, &mut failure, label).await;
    failure.map_or(Ok(()), Err)
}

async fn finish_children(
    children: &mut JoinSet<()>,
    phase: &mut watch::Receiver<ListenerPhase>,
    failure: &mut Option<anyhow::Error>,
    label: &'static str,
) {
    let mut aborted = *phase.borrow() == ListenerPhase::Abort;
    if aborted {
        children.abort_all();
    }

    while !children.is_empty() {
        tokio::select! {
            changed = phase.changed(), if !aborted => {
                if changed.is_err() || *phase.borrow() == ListenerPhase::Abort {
                    aborted = true;
                    children.abort_all();
                }
            }
            completed = children.join_next() => retain_child_result(failure, completed, aborted, label),
        }
    }
}

fn retain_child_result(
    failure: &mut Option<anyhow::Error>,
    completed: Option<Result<(), tokio::task::JoinError>>,
    aborted: bool,
    label: &'static str,
) {
    if let Some(Err(error)) = completed
        && (!aborted || !error.is_cancelled())
    {
        debug!(label, "inbound child join failed");
        failure.get_or_insert_with(|| anyhow::Error::new(error).context(label));
    }
}
