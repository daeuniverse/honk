use super::ParserDiagnostics;
use super::cursor::Segment;
use super::read;
use super::read::Text;
use crate::diagnostic::Severity;
use crate::inbound::{HttpInbound, InboundConfig, ProxyUser, Socks5Inbound};

pub(super) fn parse_section(
    section: &[Segment<'_, '_>],
    diagnostics: &mut ParserDiagnostics<'_>,
) -> Result<InboundConfig, super::ParseFailure> {
    let mut socks5 = Vec::new();
    let mut http = Vec::new();
    let mut users: Vec<ProxyUser> = Vec::new();
    for root in section {
        let Some(body) = root.body() else {
            continue;
        };
        for child in body {
            match read::block_header(&child) {
                Some(header) if header.raw() == "socks5" => {
                    let (bind, own) = parse_listener(&child, diagnostics);
                    socks5.push(Socks5Inbound { bind, users: own });
                }
                Some(header) if header.raw() == "http" => {
                    let (bind, own) = parse_listener(&child, diagnostics);
                    http.push(HttpInbound { bind, users: own });
                }
                Some(header) if header.raw() == "users" => {
                    // Shared table at the section level, inherited by every
                    // listener block that declares no users of its own.
                    parse_users(&child, diagnostics, &mut users);
                }
                Some(header) => header.notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-block",
                    "unknown inbound block ignored; expected socks5, http, or users",
                ),
                None => Text::segment(&child).notice(
                    diagnostics,
                    Severity::Warning,
                    "unknown-statement",
                    "unknown inbound statement ignored; expected a socks5 or http block",
                ),
            }
        }
    }
    Ok(InboundConfig {
        socks5,
        http,
        users,
    })
}

fn parse_listener(
    block: &Segment<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
) -> (String, Vec<ProxyUser>) {
    let mut bind = String::new();
    let mut users: Vec<ProxyUser> = Vec::new();
    let Some(body) = block.body() else {
        return (bind, users);
    };
    for child in body {
        if let Some(header) = read::block_header(&child) {
            if header.raw() == "users" {
                parse_users(&child, diagnostics, &mut users);
                continue;
            }
            header.notice(
                diagnostics,
                Severity::Warning,
                "unknown-block",
                "unknown listener block ignored; expected users",
            );
            continue;
        }
        let line = Text::segment(&child);
        let Some((key, value)) = line.kv() else {
            line.notice(
                diagnostics,
                Severity::Warning,
                "unknown-statement",
                "unknown listener statement ignored; expected bind or a users block",
            );
            continue;
        };
        if key.raw() != "bind" {
            key.notice(
                diagnostics,
                Severity::Warning,
                "unknown-key",
                "unknown listener key ignored; expected bind",
            );
            continue;
        }
        diagnostics.register_field("bind", value);
        bind = value.unquote().raw().to_owned();
    }
    (bind, users)
}

fn parse_users(
    block: &Segment<'_, '_>,
    diagnostics: &mut ParserDiagnostics<'_>,
    users: &mut Vec<ProxyUser>,
) {
    let Some(body) = block.body() else {
        return;
    };
    for line in body {
        let line = Text::segment(&line);
        let Some((key, value)) = line.kv() else {
            line.notice(
                diagnostics,
                Severity::Warning,
                "unknown-statement",
                "unknown users entry ignored; expected username: password",
            );
            continue;
        };
        users.push(ProxyUser {
            username: key.unquote().raw().to_owned(),
            password: value.unquote().raw().to_owned(),
        });
    }
}
