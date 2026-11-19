//! Inbound proxy listeners (`inbound { ... }`).
//!
//! These are process-scoped server sockets that accept proxied traffic from
//! the LAN, authenticate it, and feed it into the same routing and outbound
//! machinery as transparently intercepted flows.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Top-level `inbound { ... }` section. Empty by default: no listener is
/// served unless the operator declares one.
///
/// Field order is serde-visible: `socks5` stays first so the legacy
/// positional (sequence) config form keeps mapping to the right fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InboundConfig {
    /// SOCKS5 listeners, one per `socks5 { ... }` block, in file order.
    #[serde(default)]
    pub socks5: Vec<Socks5Inbound>,
    /// HTTP proxy listeners, one per `http { ... }` block, in file order.
    #[serde(default)]
    pub http: Vec<HttpInbound>,
    /// Shared `username: password` table inherited by every listener block
    /// that declares no users of its own, so one set of credentials serves
    /// the SOCKS5 and the HTTP(S) inbound at once.
    #[serde(default)]
    pub users: Vec<ProxyUser>,
}

impl InboundConfig {
    /// The table a listener authenticates against: its own users, or the
    /// shared table when its block declares none.
    pub fn effective_users<'a>(&'a self, own: &'a [ProxyUser]) -> &'a [ProxyUser] {
        if own.is_empty() { &self.users } else { own }
    }

    /// Structural validation shared by every config entry path (dae text,
    /// serde/native assembly). The parser adds spans where it has them.
    pub fn validate(&self) -> Result<(), InboundValidationFailure> {
        let listeners = self
            .socks5
            .iter()
            .map(|listener| (InboundKind::Socks5, &listener.bind, &listener.users))
            .chain(
                self.http
                    .iter()
                    .map(|listener| (InboundKind::Http, &listener.bind, &listener.users)),
            );
        let mut indexes = [0usize; 2];
        for (kind, bind, own) in listeners {
            let index = indexes[kind as usize];
            indexes[kind as usize] += 1;
            let reason = match validate_listener(bind, own, &self.users, kind) {
                Ok(()) => continue,
                Err(reason) => reason,
            };
            return Err(InboundValidationFailure {
                kind,
                index,
                reason,
            });
        }
        Ok(())
    }
}

/// Which kind of listener block failed, mirroring the dae grammar words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    Socks5,
    Http,
}

impl InboundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Socks5 => "socks5",
            Self::Http => "http",
        }
    }
}

/// One listener failed validation: its kind, its index among listeners of
/// that kind, and the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundValidationFailure {
    pub kind: InboundKind,
    pub index: usize,
    pub reason: &'static str,
}

fn validate_listener(
    bind: &str,
    own: &[ProxyUser],
    shared: &[ProxyUser],
    kind: InboundKind,
) -> Result<(), &'static str> {
    if !bind_is_well_formed(bind) {
        return Err("bind must be a host:port address with a non-zero port");
    }
    let users = if own.is_empty() { shared } else { own };
    if users.is_empty() {
        return Err(match kind {
            InboundKind::Socks5 => "a socks5 inbound requires at least one user",
            InboundKind::Http => "an http inbound requires at least one user",
        });
    }
    let mut seen = HashSet::new();
    for user in users {
        // RFC 1929 encodes both fields as a single length byte; the Basic
        // inbound keeps the same bound so one table is portable everywhere.
        if user.username.is_empty() {
            return Err("user name must not be empty");
        }
        if user.username.len() > 255 || user.password.len() > 255 {
            return Err("user name and password must be at most 255 bytes (RFC 1929)");
        }
        if !seen.insert(user.username.as_str()) {
            return Err("duplicate user name in one listener");
        }
    }
    Ok(())
}

/// One SOCKS5 server socket with RFC 1929 username/password authentication.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Socks5Inbound {
    /// `host:port` to listen on. A hostname is resolved at bind time, exactly
    /// like `dns.bind`.
    pub bind: String,
    /// Authentication users, or empty to inherit the shared `users` table. A
    /// listener that ends up with no user is rejected: an unauthenticated
    /// SOCKS5 open relay is never the intended default.
    #[serde(default)]
    pub users: Vec<ProxyUser>,
}

/// One HTTP proxy server socket with `Proxy-Authorization` Basic
/// authentication (CONNECT tunnels and absolute-URI forwarding).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpInbound {
    /// `host:port` to listen on, same rules as `Socks5Inbound::bind`.
    pub bind: String,
    /// Authentication users, or empty to inherit the shared `users` table.
    #[serde(default)]
    pub users: Vec<ProxyUser>,
}

/// Deliberately manual: `Debug` must never print the password.
impl std::fmt::Debug for Socks5Inbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Inbound")
            .field("bind", &self.bind)
            .field("users", &self.users)
            .finish()
    }
}

impl std::fmt::Debug for HttpInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpInbound")
            .field("bind", &self.bind)
            .field("users", &self.users)
            .finish()
    }
}

/// One `username: password` entry of a `users { ... }` block, authenticated
/// by the SOCKS5 (RFC 1929) and HTTP (Basic) inbounds alike.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyUser {
    pub username: String,
    pub password: String,
}

/// Historical name kept for the SOCKS5 code paths.
pub type Socks5User = ProxyUser;

impl std::fmt::Debug for ProxyUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyUser")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .finish()
    }
}

/// Syntax-only check; resolution happens at bind time like `dns.bind`.
fn bind_is_well_formed(bind: &str) -> bool {
    if let Ok(addr) = bind.trim().parse::<std::net::SocketAddr>() {
        return addr.port() != 0;
    }
    bind.trim()
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users(pairs: &[(&str, &str)]) -> Vec<ProxyUser> {
        pairs
            .iter()
            .map(|(username, password)| ProxyUser {
                username: (*username).to_string(),
                password: (*password).to_string(),
            })
            .collect()
    }

    fn socks5(bind: &str, pairs: &[(&str, &str)]) -> Socks5Inbound {
        Socks5Inbound {
            bind: bind.to_string(),
            users: users(pairs),
        }
    }

    fn http(bind: &str, pairs: &[(&str, &str)]) -> HttpInbound {
        HttpInbound {
            bind: bind.to_string(),
            users: users(pairs),
        }
    }

    #[test]
    fn accepts_well_formed_listeners() {
        assert!(
            InboundConfig {
                socks5: vec![socks5("0.0.0.0:7894", &[("alice", "pw")])],
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
        assert!(
            InboundConfig {
                socks5: vec![socks5("[::1]:7894", &[("alice", "pw")])],
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
        assert!(
            InboundConfig {
                http: vec![http("example.invalid:7895", &[("alice", "pw")])],
                ..Default::default()
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn rejects_unauthenticated_or_malformed_listeners() {
        assert_eq!(
            InboundConfig {
                socks5: vec![socks5("0.0.0.0:7894", &[])],
                ..Default::default()
            }
            .validate(),
            Err(InboundValidationFailure {
                kind: InboundKind::Socks5,
                index: 0,
                reason: "a socks5 inbound requires at least one user",
            })
        );
        assert_eq!(
            InboundConfig {
                http: vec![http("0.0.0.0:7895", &[])],
                ..Default::default()
            }
            .validate(),
            Err(InboundValidationFailure {
                kind: InboundKind::Http,
                index: 0,
                reason: "an http inbound requires at least one user",
            })
        );
        for bind in ["", "0.0.0.0:0", "0.0.0.0:70000"] {
            assert!(
                InboundConfig {
                    socks5: vec![socks5(bind, &[("alice", "pw")])],
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
            assert!(
                InboundConfig {
                    http: vec![http(bind, &[("alice", "pw")])],
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
        for bad in [
            vec![("", "pw")],
            vec![("alice", "pw"), ("alice", "other")],
            vec![(&"x".repeat(256), "pw")],
        ] {
            assert!(
                InboundConfig {
                    socks5: vec![socks5("0.0.0.0:7894", &bad)],
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
            assert!(
                InboundConfig {
                    http: vec![http("0.0.0.0:7895", &bad)],
                    ..Default::default()
                }
                .validate()
                .is_err()
            );
        }
    }

    #[test]
    fn failure_indexes_are_per_kind() {
        // The second http listener is broken; the socks5 count does not
        // shift the index reported for the http kind.
        assert_eq!(
            InboundConfig {
                socks5: vec![
                    socks5("0.0.0.0:7894", &[("alice", "pw")]),
                    socks5("0.0.0.0:7896", &[("carol", "pw")]),
                ],
                http: vec![
                    http("0.0.0.0:7895", &[("bob", "pw")]),
                    http("0.0.0.0:7897", &[]),
                ],
                ..Default::default()
            }
            .validate(),
            Err(InboundValidationFailure {
                kind: InboundKind::Http,
                index: 1,
                reason: "an http inbound requires at least one user",
            })
        );
    }

    #[test]
    fn shared_users_inherit_into_both_kinds() {
        let config = InboundConfig {
            socks5: vec![socks5("0.0.0.0:7894", &[])],
            http: vec![http("0.0.0.0:7895", &[])],
            users: users(&[("alice", "pw")]),
        };
        assert!(config.validate().is_ok());
        assert_eq!(config.effective_users(&config.socks5[0].users).len(), 1);
        assert_eq!(config.effective_users(&config.http[0].users).len(), 1);
        // A listener's own table shadows the shared one.
        let own = users(&[("dave", "pw")]);
        assert_eq!(config.effective_users(&own).len(), 1);
        assert_eq!(config.effective_users(&own)[0].username, "dave");
    }

    #[test]
    fn debug_redacts_passwords() {
        let text = format!("{:?}", socks5("0.0.0.0:7894", &[("alice", "hunter2")]));
        assert!(!text.contains("hunter2"));
        assert!(text.contains("alice"));
        let text = format!("{:?}", http("0.0.0.0:7895", &[("bob", "hunter3")]));
        assert!(!text.contains("hunter3"));
        assert!(text.contains("bob"));
    }
}
