//! Administrator credentials and sessions for password mode.
//!
//! One record in the state db's `admin` row names the administrator and holds a
//! PBKDF2-HMAC-SHA256 hash of the password. Sessions are opaque random tokens kept in memory as
//! SHA-256 digests; a restart forgets them all.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use base64::Engine as _;
use hmac::Mac as _;
use hmac::digest::KeyInit as _;
use parking_lot::Mutex;
use rand::Rng as _;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use tokio::sync::{oneshot, watch};
use tokio::task::JoinSet;

use super::{ApiError, ErrorCode, Peer, types::RequestId};
use crate::state::StateDb;
use axum::http::StatusCode;
use axum::response::Response;

mod request;
mod storage;
pub(super) use request::{login, logout, setup};
use storage::{CredentialStore, StoreError};

#[cfg(test)]
mod tests;

const RECORD_LIMIT: usize = 4096;
pub(crate) const PBKDF2_ITERATIONS: u32 = 100_000;
pub(crate) const SESSION_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
pub(crate) const SESSION_LIMIT: usize = 32;
const TOKEN_PREFIX: &str = "hnk1_";

const BASE64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// RFC 8018 §5.2 with HMAC-SHA256 and a single 32-byte block.
pub(crate) fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let keyed =
        <hmac::Hmac<Sha256>>::new_from_slice(password).expect("HMAC accepts any key length");
    let mut mac = keyed.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut block: [u8; 32] = mac.finalize().into_bytes().into();
    let mut output = block;
    for _ in 1..iterations {
        let mut mac = keyed.clone();
        mac.update(&block);
        block = mac.finalize().into_bytes().into();
        for (out, byte) in output.iter_mut().zip(block) {
            *out ^= byte;
        }
    }
    output
}

pub(crate) fn valid_username(username: &str) -> bool {
    (1..=64).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

pub(crate) fn valid_password(password: &str) -> bool {
    let scalars = password.chars().count();
    (8..=128).contains(&scalars) && password.len() <= 512
}

/// Sessions issued by login: at most `SESSION_LIMIT`, each `SESSION_LIFETIME` long, known only by digest.
#[derive(Default)]
pub(crate) struct Sessions {
    inner: Mutex<Vec<Session>>,
}

struct Session {
    digest: [u8; 32],
    issued: Instant,
    expires: Instant,
    /// Dropped with the session, which tells every lease it has ended.
    ended: watch::Sender<()>,
}

/// Held by a response that outlives its request, such as an event stream.
pub(crate) struct SessionLease {
    ended: watch::Receiver<()>,
    expires: Instant,
}

impl SessionLease {
    /// Completes when the session is revoked, replaced by a newer login, or expires.
    pub(crate) async fn ended(mut self) {
        let expiry = tokio::time::sleep_until(self.expires.into());
        tokio::select! {
            () = expiry => {}
            _ = self.ended.changed() => {}
        }
    }
}

pub(crate) struct Issued {
    pub(crate) token: String,
    pub(crate) expires_at: SystemTime,
}

impl Sessions {
    pub(crate) fn issue(&self) -> Issued {
        self.issue_at(Instant::now(), SystemTime::now())
    }

    fn issue_at(&self, now: Instant, wall: SystemTime) -> Issued {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let token = format!("{TOKEN_PREFIX}{}", BASE64.encode(bytes));
        let mut sessions = self.inner.lock();
        sessions.retain(|session| session.expires > now);
        while sessions.len() >= SESSION_LIMIT {
            let oldest = sessions
                .iter()
                .enumerate()
                .min_by_key(|(_, session)| session.issued)
                .map(|(index, _)| index)
                .expect("non-empty");
            sessions.swap_remove(oldest);
        }
        sessions.push(Session {
            digest: Sha256::digest(token.as_bytes()).into(),
            issued: now,
            expires: now + SESSION_LIFETIME,
            ended: watch::Sender::new(()),
        });
        Issued {
            token,
            expires_at: wall + SESSION_LIFETIME,
        }
    }

    /// The live session `token` names; every stored digest is compared so timing does not say which matched.
    pub(crate) fn authenticate(&self, token: &str) -> Option<SessionLease> {
        self.authenticate_at(token, Instant::now())
    }

    fn authenticate_at(&self, token: &str, now: Instant) -> Option<SessionLease> {
        if !token.starts_with(TOKEN_PREFIX) {
            return None;
        }
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let sessions = self.inner.lock();
        let mut found = subtle::Choice::from(0);
        for session in sessions.iter().filter(|session| session.expires > now) {
            found |= session.digest.ct_eq(&digest);
        }
        if !bool::from(found) {
            return None;
        }
        // Only a holder of the valid token reaches this ordinary lookup.
        sessions
            .iter()
            .find(|session| session.digest == digest)
            .map(|session| SessionLease {
                ended: session.ended.subscribe(),
                expires: session.expires,
            })
    }

    /// Ends the session; returns whether one was ended.
    pub(crate) fn revoke(&self, token: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut sessions = self.inner.lock();
        let before = sessions.len();
        sessions.retain(|session| !bool::from(session.digest.ct_eq(&digest)));
        sessions.len() != before
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

/// Accepted attempts and consecutive failures, serialized by the credential worker.
pub(crate) struct AuthRate {
    inner: Mutex<RateState>,
}

struct RateState {
    attempts: Vec<(std::net::IpAddr, Instant)>,
    failures: u32,
    locked_until: Option<Instant>,
}

/// Attempts allowed per peer and overall in one minute, and the lock after consecutive failures.
pub(crate) const PEER_ATTEMPTS: usize = 5;
pub(crate) const GLOBAL_ATTEMPTS: usize = 10;
pub(crate) const FAILURES_BEFORE_LOCK: u32 = 5;
pub(crate) const LOCK: Duration = Duration::from_secs(60);
const WINDOW: Duration = Duration::from_secs(60);

impl Default for AuthRate {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RateState {
                attempts: Vec::with_capacity(GLOBAL_ATTEMPTS),
                failures: 0,
                locked_until: None,
            }),
        }
    }
}

impl AuthRate {
    /// Seconds the caller must wait, or `None` when the attempt may proceed.
    pub(crate) fn admit(&self, peer: std::net::IpAddr) -> Option<u32> {
        self.admit_at(peer, Instant::now())
    }

    fn admit_at(&self, peer: std::net::IpAddr, now: Instant) -> Option<u32> {
        let mut state = self.inner.lock();
        if let Some(until) = state.locked_until {
            if until > now {
                return Some(seconds_until(until, now));
            }
            state.locked_until = None;
            state.failures = 0;
        }
        state
            .attempts
            .retain(|(_, at)| now.duration_since(*at) < WINDOW);
        if state.attempts.len() >= GLOBAL_ATTEMPTS {
            return Some(seconds_until(state.attempts[0].1 + WINDOW, now));
        }
        let mut peers = state
            .attempts
            .iter()
            .filter(|(address, _)| *address == peer);
        if let Some((_, oldest)) = peers.next()
            && peers.count() + 1 >= PEER_ATTEMPTS
        {
            return Some(seconds_until(*oldest + WINDOW, now));
        }
        state.attempts.push((peer, now));
        None
    }

    /// A wrong credential; the global lock closes after `FAILURES_BEFORE_LOCK` in a row.
    pub(crate) fn failed(&self) {
        self.failed_at(Instant::now());
    }

    fn failed_at(&self, now: Instant) {
        let mut state = self.inner.lock();
        state.failures += 1;
        if state.failures >= FAILURES_BEFORE_LOCK {
            state.locked_until = Some(now + LOCK);
        }
    }

    pub(crate) fn succeeded(&self) {
        let mut state = self.inner.lock();
        state.failures = 0;
        state.locked_until = None;
    }
}

fn seconds_until(deadline: Instant, now: Instant) -> u32 {
    deadline.saturating_duration_since(now).as_secs().max(1) as u32
}

/// Everything password mode owns: the record, the live sessions and the login admission.
pub(crate) struct Auth {
    pub(crate) store: CredentialStore,
    pub(crate) sessions: Sessions,
    rate: AuthRate,
    work: Mutex<Work>,
}

#[derive(Default)]
struct Work {
    closed: bool,
    /// Cleared before the reply is sent: a finished job can still be unreaped.
    busy: bool,
    jobs: JoinSet<()>,
}

impl Auth {
    pub(crate) fn open(db: Arc<StateDb>) -> Result<Self, StoreError> {
        Ok(Self {
            store: CredentialStore::open(db)?,
            sessions: Sessions::default(),
            rate: AuthRate::default(),
            work: Mutex::new(Work::default()),
        })
    }

    async fn run(
        self: &Arc<Self>,
        peer: Peer,
        id: &RequestId,
        work: impl FnOnce(&Self, &RequestId) -> Result<Response, ApiError> + Send + 'static,
    ) -> Result<Response, ApiError> {
        let receive = {
            let mut worker = self.work.lock();
            while let Some(result) = worker.jobs.try_join_next() {
                if result.is_err() {
                    worker.closed = true;
                }
            }
            if worker.closed {
                return Err(unavailable(id));
            }
            // ponytail: one administrator needs one worker; no credential queue to outlive requests.
            if worker.busy {
                return Err(rate_limited(id, 1));
            }
            if let Some(after) = self.rate.admit(peer.0) {
                return Err(rate_limited(id, after));
            }
            let (send, receive) = oneshot::channel();
            let auth = Arc::clone(self);
            let id = id.clone();
            worker.busy = true;
            worker.jobs.spawn_blocking(move || {
                let response = work(&auth, &id);
                auth.work.lock().busy = false;
                let _ = send.send(response);
            });
            receive
        };
        receive.await.map_err(|_| unavailable(id))?
    }

    pub(crate) fn close(&self) {
        self.work.lock().closed = true;
    }

    /// Joins real KDF/SQL work even when its HTTP request was dropped.
    pub(crate) async fn shutdown(&self) {
        let mut jobs = {
            let mut worker = self.work.lock();
            worker.closed = true;
            std::mem::take(&mut worker.jobs)
        };
        while let Some(result) = jobs.join_next().await {
            if result.is_err() {
                tracing::error!("native credential worker failed");
            }
        }
    }
}

fn unavailable(id: &RequestId) -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::TemporarilyUnavailable,
        "Password login is temporarily unavailable",
        Some(id.0.clone()),
    )
}

fn rate_limited(id: &RequestId, after: u32) -> ApiError {
    ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        ErrorCode::RateLimited,
        "Too many login attempts",
        Some(id.0.clone()),
    )
    .with_retry_after(after)
}
