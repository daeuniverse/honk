//! SIP008 and sing-box node imports normalized through the common Clash builder.

#[cfg(test)]
use honk_config::node::Node;
use serde_yaml::{Mapping, Value};

use super::IndexedOutcome;
#[cfg(test)]
use super::IndexedOutcomeKind;

mod sing_box;

enum NormalizedEntry {
    Node(Mapping),
    Profile(&'static str),
    Unsupported(&'static str),
}

type NodeResult = Result<NormalizedEntry, &'static str>;

#[cfg(test)]
pub(super) fn parse_json_subscription(
    value: Value,
    subscription_id: Option<uuid::Uuid>,
) -> anyhow::Result<Vec<Node>> {
    let mut nodes = Vec::new();
    emit_json_subscription(value, subscription_id, |outcome| {
        if let IndexedOutcomeKind::Node(node) = outcome.kind {
            nodes.push(node);
        }
    })?;
    if nodes.is_empty() {
        anyhow::bail!("no supported nodes found in JSON subscription");
    }
    Ok(nodes)
}

pub(super) fn emit_json_subscription(
    value: Value,
    subscription_id: Option<uuid::Uuid>,
    mut emit: impl FnMut(IndexedOutcome),
) -> anyhow::Result<()> {
    match value {
        Value::Sequence(servers) => parse_entries(
            servers,
            subscription_id,
            normalize_sip008,
            "servers",
            &mut emit,
        ),
        Value::Mapping(mut root) => {
            let outbounds = root.remove("outbounds");
            let servers = root.remove("servers");
            match (outbounds, servers) {
                (Some(_), Some(_)) => anyhow::bail!("ambiguous JSON subscription wrapper"),
                (Some(Value::Sequence(outbounds)), None) => parse_entries(
                    outbounds,
                    subscription_id,
                    sing_box::normalize,
                    "outbounds",
                    &mut emit,
                ),
                (Some(_), None) => anyhow::bail!("sing-box 'outbounds' must be an array"),
                (None, Some(Value::Sequence(servers))) => {
                    if let Some(version) = root.remove("version")
                        && !matches!(version.as_u64(), Some(1 | 2))
                    {
                        anyhow::bail!("unsupported SIP008 version");
                    }
                    parse_entries(
                        servers,
                        subscription_id,
                        normalize_sip008,
                        "servers",
                        &mut emit,
                    )
                }
                (None, Some(_)) => anyhow::bail!("SIP008 'servers' must be an array"),
                (None, None) => anyhow::bail!("unsupported JSON subscription wrapper"),
            }
        }
        _ => anyhow::bail!("JSON subscription root must be an object or array"),
    }
}

fn parse_entries(
    entries: Vec<Value>,
    subscription_id: Option<uuid::Uuid>,
    normalize: fn(Value) -> NodeResult,
    path: &'static str,
    emit: &mut impl FnMut(IndexedOutcome),
) -> anyhow::Result<()> {
    for (index, entry) in entries.into_iter().enumerate() {
        let ordinal = index + 1;
        let outcome = match normalize(entry) {
            Ok(NormalizedEntry::Node(proxy)) => {
                match super::clash::parse_clash_proxy(&proxy, subscription_id) {
                    Ok(node) => IndexedOutcome::node(ordinal, path, node),
                    Err(reason) if reason.contains("unsupported") => {
                        IndexedOutcome::unsupported(ordinal, path, reason)
                    }
                    Err(reason) => IndexedOutcome::malformed(ordinal, path, reason),
                }
            }
            Ok(NormalizedEntry::Profile(reason)) => IndexedOutcome::profile(ordinal, path, reason),
            Ok(NormalizedEntry::Unsupported(reason)) => {
                IndexedOutcome::unsupported(ordinal, path, reason)
            }
            Err(reason) => IndexedOutcome::malformed(ordinal, path, reason),
        };
        emit(outcome);
    }
    Ok(())
}

fn normalize_sip008(value: Value) -> NodeResult {
    let Value::Mapping(mut source) = value else {
        return Err("SIP008 server must be an object");
    };
    let mut proxy = Mapping::new();
    put(&mut proxy, "type", Value::String("ss".into()));
    move_strings(
        &mut source,
        &mut proxy,
        &[
            ("server", "server"),
            ("method", "cipher"),
            ("remarks", "name"),
            ("plugin", "plugin"),
            ("plugin_opts", "plugin-opts"),
        ],
    )?;
    move_credential_strings(&mut source, &mut proxy, &[("password", "password")])?;
    match source.remove("server_port") {
        None | Some(Value::Null) => {}
        Some(port) if matches!(port.as_u64(), Some(1..=65535)) => {
            put(&mut proxy, "port", port);
        }
        Some(_) => return Err("SIP008 server port must be an integer"),
    }
    Ok(NormalizedEntry::Node(proxy))
}

fn put(mapping: &mut Mapping, key: &str, value: Value) {
    mapping.insert(Value::String(key.into()), value);
}

fn take_optional_string(mapping: &mut Mapping, key: &str) -> Result<Option<String>, &'static str> {
    match mapping.remove(key) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err("JSON string setting has an invalid type"),
    }
}

fn take_optional_credential(
    mapping: &mut Mapping,
    key: &str,
) -> Result<Option<String>, &'static str> {
    match mapping.remove(key) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Number(value)) if value.as_f64().is_some_and(|value| value.is_finite()) => {
            Ok(Some(value.to_string()))
        }
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err("JSON credential setting has an invalid type"),
    }
}

fn move_strings(
    source: &mut Mapping,
    target: &mut Mapping,
    fields: &[(&str, &str)],
) -> Result<(), &'static str> {
    for &(source_key, target_key) in fields {
        if let Some(value) =
            take_optional_string(source, source_key)?.filter(|value| !value.trim().is_empty())
        {
            put(target, target_key, Value::String(value));
        }
    }
    Ok(())
}

fn move_credential_strings(
    source: &mut Mapping,
    target: &mut Mapping,
    fields: &[(&str, &str)],
) -> Result<(), &'static str> {
    for &(source_key, target_key) in fields {
        if let Some(value) = take_optional_credential(source, source_key)? {
            put(target, target_key, Value::String(value));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use honk_config::node::{VlessMultiplex, VlessUdpEncoding};
    use honk_config::types::NodeProtocol;

    use super::*;

    fn json(input: &str) -> Value {
        serde_yaml::from_str(input).unwrap()
    }

    #[test]
    fn sip008_wrappers_and_server_lists_normalize_to_shadowsocks() {
        for input in [
            r#"{"version":1,"servers":[{"id":"00000000-0000-4000-8000-000000000001","remarks":"sip-node","server":"sip.example","server_port":8388,"method":"aes-256-gcm","password":"password","plugin":"","plugin_opts":""}]}"#,
            r#"[{"remarks":"sip-node","server":"sip.example","server_port":8388,"method":"aes-256-gcm","password":"password"}]"#,
            r#"{"version":2,"servers":[{"remarks":"sip-node","server":"sip.example","server_port":8388,"method":"aes-256-gcm","password":"password"}]}"#,
        ] {
            let subscription_id = uuid::Uuid::new_v4();
            let nodes = parse_json_subscription(json(input), Some(subscription_id)).unwrap();
            assert_eq!(nodes.len(), 1);
            let node = &nodes[0];
            assert_eq!(node.protocol(), NodeProtocol::SS);
            assert_eq!(node.name, "sip-node");
            assert_eq!(node.host(), "sip.example");
            assert_eq!(node.port, 8388);
            assert_eq!(node.subscription_id, Some(subscription_id));
            let shadowsocks = node.shadowsocks().unwrap();
            assert_eq!(shadowsocks.encryption.as_deref(), Some("aes-256-gcm"));
            assert_eq!(shadowsocks.password.as_deref(), Some("password"));
        }
    }

    #[test]
    fn sing_box_outbounds_preserve_supported_protocol_configuration() {
        let nodes = parse_json_subscription(
            json(
                r#"{
                  "outbounds": [
                    {"type":"selector","tag":"select","outbounds":["ss"]},
                    {"type":"urltest","tag":"auto","outbounds":["ss"]},
                    {"type":"direct","tag":"direct"},
                    {"type":"block","tag":"block"},
                    {"type":"dns","tag":"dns"},
                    {"type":"shadowsocks","tag":"ss","server":"ss.example","server_port":8388,"method":"aes-256-gcm","password":"ss-password"},
                    {"type":"socks","tag":"socks","server":"socks.example","server_port":1080,"version":"5","username":"user","password":"socks-password"},
                    {"type":"vmess","tag":"vmess","server":"vmess.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000002","security":"auto","alter_id":0,"network":"tcp","tls":{"enabled":true,"server_name":"vmess-sni.example","insecure":true},"transport":{"type":"ws","path":"/socket","headers":{"Host":"ws-host.example"}}},
                    {"type":"vless","tag":"vless","server":"vless.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000003","tls":{"enabled":true,"server_name":"vless-sni.example","reality":{"enabled":true,"public_key":"jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc","short_id":"abcd"},"utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"grpc","service_name":"TunService"}},
                    {"type":"trojan","tag":"trojan","server":"trojan.example","server_port":443,"password":"trojan-password","tls":{"enabled":true,"server_name":"trojan-sni.example"}},
                    {"type":"hysteria2","tag":"hy2","server":"hy2.example","server_ports":["20000:20002","8443"],"hop_interval":"15s","up_mbps":100,"down_mbps":200,"password":"hy2-password","obfs":{"type":"salamander","password":"obfs-password"},"initial_stream_receive_window":1048576,"initial_connection_receive_window":2097152,"disable_path_mtu_discovery":true,"tls":{"enabled":true,"server_name":"hy2-sni.example","insecure":true,"alpn":["h3"]}},
                    {"type":"tuic","tag":"tuic","server":"tuic.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000004","password":"tuic-password","congestion_control":"bbr","udp_relay_mode":"native","initial_packet_size":1252,"tls":{"enabled":true,"server_name":"tuic-sni.example","alpn":["h3","tuic"]}},
                    {"type":"anytls","tag":"anytls","server":"anytls.example","server_port":443,"password":"anytls-password","network":"tcp","min_idle_session":4,"idle_session_check_interval":"30s","idle_session_timeout":"1m","tls":{"enabled":true,"server_name":"anytls-sni.example","alpn":["h2"]}},
                    {"type":"juicity","tag":"juicity","server":"juicity.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000005","password":"juicity-password","initial_stream_receive_window":8388608,"initial_connection_receive_window":8388608,"tls":{"enabled":true,"server_name":"juicity-sni.example","alpn":["h3"]}}
                  ]
                }"#,
            ),
            None,
        )
        .unwrap();

        assert_eq!(nodes.len(), 9);
        assert_eq!(
            nodes.iter().map(Node::protocol).collect::<Vec<_>>(),
            vec![
                NodeProtocol::SS,
                NodeProtocol::Socks5,
                NodeProtocol::VMess,
                NodeProtocol::VLess,
                NodeProtocol::Trojan,
                NodeProtocol::Hysteria2,
                NodeProtocol::Tuic,
                NodeProtocol::AnyTLS,
                NodeProtocol::Juicity,
            ]
        );

        let vmess = &nodes[2];
        assert_eq!(vmess.network(), Some("tcp"));
        assert_eq!(vmess.transport().unwrap().transport, "ws");
        assert_eq!(
            vmess.transport().unwrap().ws_path.as_deref(),
            Some("/socket")
        );
        assert_eq!(
            vmess.transport().unwrap().ws_host.as_deref(),
            Some("ws-host.example")
        );
        assert_eq!(
            vmess.tls().unwrap().sni.as_deref(),
            Some("vmess-sni.example")
        );
        assert!(vmess.tls().unwrap().skip_cert_verify);

        let vless = nodes[3].vless().unwrap();
        assert_eq!(vless.udp_encoding, VlessUdpEncoding::Xudp);
        assert_eq!(vless.transport.transport, "grpc");
        assert_eq!(vless.transport.grpc_service.as_deref(), Some("TunService"));
        assert_eq!(
            vless.tls.reality_public_key.as_deref(),
            Some("jHkr1EmJCyQxjU0HXJlNblVdXB4Z7yODHJhgJ5lqmzc")
        );
        assert_eq!(vless.tls.reality_short_id.as_deref(), Some("abcd"));

        let hy2 = nodes[5].hysteria2().unwrap();
        assert_eq!(nodes[5].port, 20_000);
        assert_eq!(hy2.auth.as_deref(), Some("hy2-password"));
        assert_eq!(hy2.obfs.as_deref(), Some("obfs-password"));
        assert_eq!(hy2.up_mbps, Some(100));
        assert_eq!(hy2.down_mbps, Some(200));
        assert_eq!(hy2.port_hopping.as_deref(), Some("20000-20002,8443"));
        assert_eq!(hy2.hop_interval, Some(15));
        assert_eq!(hy2.init_stream_recv_window, Some(1_048_576));
        assert_eq!(hy2.init_conn_recv_window, Some(2_097_152));
        assert_eq!(hy2.disable_mtu_discovery, Some(true));

        let tuic = nodes[6].tuic().unwrap();
        assert_eq!(tuic.congestion.as_deref(), Some("bbr"));
        assert_eq!(tuic.alpn.as_deref(), Some("h3,tuic"));
        assert_eq!(tuic.quic.mtu, Some(1252));

        let anytls = nodes[7].anytls().unwrap();
        assert_eq!(anytls.tls.alpn, ["h2"]);
        assert_eq!(anytls.network.as_deref(), Some("tcp"));
        assert_eq!(anytls.min_idle_session, Some(4));
        assert_eq!(anytls.idle_session_check_interval, Some(30));
        assert_eq!(anytls.idle_session_timeout, Some(60));
    }

    #[test]
    fn sing_box_vless_packet_settings_preserve_source_defaults_and_network_gate() {
        let nodes = parse_json_subscription(
            json(
                r#"{"outbounds":[
                  {"type":"vless","tag":"default-xudp","server":"one.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000011"},
                  {"type":"vless","tag":"default-xudp-disabled","server":"disabled-default.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000010","network":"tcp"},
                  {"type":"vless","tag":"native-enabled","server":"two.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000012","packet_encoding":"","multiplex":{"enabled":false}},
                  {"type":"vless","tag":"native-disabled","server":"three.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000013","network":"tcp","packet_encoding":""},
                  {"type":"vless","tag":"xudp-disabled","server":"four.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000014","network":"tcp","packet_encoding":"xudp"},
                  {"type":"vless","tag":"native-vision-tcp","server":"five.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000015","network":"tcp","packet_encoding":"","flow":"xtls-rprx-vision","tls":{"enabled":true}},
                  {"type":"vless","tag":"h2mux-disabled","server":"six.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000016","network":"tcp","multiplex":{"enabled":true,"protocol":"h2mux","padding":true}},
                  {"type":"vless","tag":"uot","server":"seven.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000017","udp_over_tcp":{"enabled":true,"version":2}},
                  {"type":"vless","tag":"wrapper-precedence","server":"eight.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000018","packet_encoding":"","multiplex":{"enabled":true,"protocol":"h2mux"}},
                  {"type":"vless","tag":"disabled-wrapper-default","server":"nine.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000019","multiplex":{"enabled":false}},
                  {"type":"vless","tag":"xudp-wrapper-precedence","server":"ten.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000020","packet_encoding":"xudp","multiplex":{"enabled":true,"protocol":"h2mux"}}
                ]}"#,
            ),
            None,
        )
        .unwrap();

        assert_eq!(
            nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            [
                "default-xudp",
                "default-xudp-disabled",
                "native-enabled",
                "native-disabled",
                "xudp-disabled",
                "native-vision-tcp",
                "h2mux-disabled",
                "uot",
                "wrapper-precedence",
                "disabled-wrapper-default",
                "xudp-wrapper-precedence",
            ]
        );
        assert_eq!(
            nodes
                .iter()
                .map(|node| {
                    let config = node.vless().unwrap();
                    (config.udp_encoding, config.multiplex, config.udp_enabled())
                })
                .collect::<Vec<_>>(),
            [
                (VlessUdpEncoding::Xudp, VlessMultiplex::Off, true),
                (VlessUdpEncoding::Auto, VlessMultiplex::Off, false),
                (VlessUdpEncoding::Native, VlessMultiplex::Off, true),
                (VlessUdpEncoding::Auto, VlessMultiplex::Off, false),
                (VlessUdpEncoding::Auto, VlessMultiplex::Off, false),
                (VlessUdpEncoding::Auto, VlessMultiplex::Off, false),
                (
                    VlessUdpEncoding::Auto,
                    VlessMultiplex::H2 { padding: true },
                    false,
                ),
                (VlessUdpEncoding::UotV2, VlessMultiplex::Off, true,),
                (
                    VlessUdpEncoding::Auto,
                    VlessMultiplex::H2 { padding: false },
                    true,
                ),
                (VlessUdpEncoding::Xudp, VlessMultiplex::Off, true),
                (
                    VlessUdpEncoding::Auto,
                    VlessMultiplex::H2 { padding: false },
                    true,
                ),
            ]
        );
        assert!(nodes.iter().all(|node| node.id == node.derive_id()));
    }

    #[test]
    fn sing_box_rejects_removed_vless_mode_before_projection() {
        assert!(matches!(
            sing_box::normalize(json(r#"{"type":"vless","vless_mode":null}"#)),
            Err("VLESS vless_mode was removed")
        ));
        let nodes = parse_json_subscription(
            json(
                r#"{"outbounds":[
                  {"type":"vless","tag":"null","server":"null.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000071","vless_mode":null},
                  {"type":"vless","tag":"empty","server":"empty.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000072","vless_mode":""},
                  {"type":"vless","tag":"false","server":"false.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000073","vless_mode":false},
                  {"type":"vless","tag":"old-value","server":"old.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000074","vless_mode":"legacy"},
                  {"type":"vmess","tag":"vmess-unchanged","server":"vmess.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000075","vless_mode":"xudp"}
                ]}"#,
            ),
            None,
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "vmess-unchanged");
    }

    const C10_SING_BOX_TRANSPORTS: &str = r#"{"outbounds":[
      {"type":"vless","tag":"packet-tcp-stream-tcp","server":"raw.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000025","network":"tcp","transport":{"type":"tcp"}},
      {"type":"vless","tag":"packet-tcp-stream-ws","server":"ws.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000027","network":"tcp","transport":{"type":"ws"}},
      {"type":"vless","tag":"packet-tcp-stream-grpc","server":"grpc.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000028","network":"tcp","transport":{"type":"grpc"}},
      {"type":"vless","tag":"raw-tcp-active-settings","server":"active.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000029","network":"tcp","transport":{"type":"tcp","path":"/must-not-ignore"}},
      {"type":"vless","tag":"unsupported-h2-stream","server":"h2.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000026","network":"tcp","transport":{"type":"h2"}}
    ]}"#;

    #[test]
    fn c10_sing_box_packet_network_and_stream_transport_are_separate() {
        let nodes = parse_json_subscription(json(C10_SING_BOX_TRANSPORTS), None).unwrap();
        assert_eq!(nodes.len(), 3);
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            [
                "packet-tcp-stream-tcp",
                "packet-tcp-stream-ws",
                "packet-tcp-stream-grpc"
            ]
        );
        assert_eq!(nodes[0].network(), Some("tcp"));
        assert_eq!(nodes[0].transport().unwrap().transport, "tcp");
        assert_eq!(nodes[1].network(), Some("tcp"));
        assert_eq!(nodes[1].transport().unwrap().transport, "ws");
        assert_eq!(nodes[2].network(), Some("tcp"));
        assert_eq!(nodes[2].transport().unwrap().transport, "grpc");
    }

    const C11_SING_BOX_PACKET_NETWORKS: &str = r#"{"outbounds":[
      {"type":"vless","tag":"packet-udp-stream-ws","server":"udp.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000029","network":"udp","transport":{"type":"ws"}},
      {"type":"vless","tag":"packet-list-stream-grpc","server":"list.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000030","network":"tcp,udp","transport":{"type":"grpc"}},
      {"type":"vless","tag":"packet-empty","server":"empty.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","network":"","transport":{"type":"tcp"}},
      {"type":"vless","tag":"packet-null","server":"null.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000032","network":null,"transport":{"type":"ws"}},
      {"type":"anytls","tag":"native-anytls-udp","server":"native-anytls.example","server_port":443,"password":"password","network":"udp","tls":{"enabled":true}},
      {"type":"vless","tag":"packet-unknown","server":"unknown.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000033","network":"quic","transport":{"type":"tcp"}}
    ]}"#;

    #[test]
    fn c11_sing_box_packet_networks_do_not_rewrite_stream_transport() {
        let nodes = parse_json_subscription(json(C11_SING_BOX_PACKET_NETWORKS), None).unwrap();
        assert_eq!(nodes.len(), 5);
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            [
                "packet-udp-stream-ws",
                "packet-list-stream-grpc",
                "packet-empty",
                "packet-null",
                "native-anytls-udp"
            ]
        );
        assert!(nodes[0].vless().unwrap().udp_enabled());
        assert_eq!(nodes[0].transport().unwrap().transport, "ws");
        assert!(nodes[1].vless().unwrap().udp_enabled());
        assert_eq!(nodes[1].transport().unwrap().transport, "grpc");
        assert_eq!(nodes[2].network(), None);
        assert_eq!(nodes[2].transport().unwrap().transport, "tcp");
        assert_eq!(nodes[3].network(), None);
        assert_eq!(nodes[3].transport().unwrap().transport, "ws");
        assert_eq!(nodes[4].anytls().unwrap().network.as_deref(), Some("udp"));
    }

    #[test]
    fn sing_box_empty_grpc_and_tuic_defaults_are_preserved() {
        let nodes = parse_json_subscription(
            json(
                r#"{"outbounds":[
                  {"type":"vless","tag":"grpc-default","server":"one.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000015","transport":{"type":"grpc"}},
                  {"type":"vless","tag":"grpc-empty","server":"two.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000016","transport":{"type":"grpc","service_name":""}},
                  {"type":"tuic","tag":"tuic-missing-password","server":"three.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000017","tls":{"enabled":true}},
                  {"type":"tuic","tag":"tuic-empty-password","server":"four.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000018","password":"","tls":{"enabled":true}}
                ]}"#,
            ),
            None,
        )
        .unwrap();

        assert_eq!(nodes.len(), 4);
        assert_eq!(
            nodes[0].transport().unwrap().grpc_service.as_deref(),
            Some("")
        );
        assert_eq!(
            nodes[1].transport().unwrap().grpc_service.as_deref(),
            Some("")
        );
        assert!(nodes[2].tuic().unwrap().password.is_none());
        assert_eq!(nodes[3].tuic().unwrap().password.as_deref(), Some(""));
    }

    #[test]
    fn malformed_nodes_do_not_poison_valid_siblings() {
        let nodes = parse_json_subscription(
            json(
                r#"{"outbounds":[
                  {"type":"selector","tag":"select","outbounds":["good"]},
                  {"type":"vless","tag":"bad-packet-mode","server":"bad.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000021","packet_encoding":"packetaddr"},
                  {"type":"hysteria2","tag":"bad-hop-range","server":"bad-hop.example","server_ports":["9000:8000"],"password":"password","tls":{"enabled":true}},
                  {"type":"hysteria2","tag":"bad-hy2-alpn","server":"bad-hy2.example","server_port":443,"password":"password","tls":{"enabled":true,"alpn":["hq-29"]}},
                  {"type":"juicity","tag":"bad-juicity-alpn","server":"bad-juicity.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000022","password":"password","tls":{"enabled":true,"alpn":["hq-29"]}},
                  {"type":"anytls","tag":"bad-anytls-alpn","server":"bad-anytls.example","server_port":443,"password":"password","tls":{"enabled":true,"alpn":["h2",42]}},
                  {"type":"juicity","tag":"bad-window","server":"bad-window.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000023","password":"password","initial_stream_receive_window":1048576,"tls":{"enabled":true,"alpn":["h3"]}},
                  {"type":"tuic","tag":"missing-tuic-uuid","server":"missing-tuic.example","server_port":443,"password":"password","tls":{"enabled":true}},
                  {"type":"shadowsocks","tag":"plugin","server":"plugin.example","server_port":8388,"method":"aes-256-gcm","password":"password","plugin":"v2ray-plugin"},
                  {"type":"shadowsocks","tag":"good","server":"good.example","server_port":8388,"method":"aes-256-gcm","password":"password"}
                ]}"#,
            ),
            None,
        )
        .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "good");
        assert_eq!(nodes[0].protocol(), NodeProtocol::SS);
    }

    #[test]
    fn malformed_or_unrepresentable_json_inputs_fail_without_echoing_values() {
        for input in [
            r#"{"outbounds":[{"type":"vless","server":"secret.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","packet_encoding":"packetaddr"}]}"#,
            r#"{"outbounds":[{"type":"vmess","server":"secret.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","security":"chacha20-poly1305"}]}"#,
            r#"{"outbounds":[{"type":"vless","server":"secret.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","packet_encoding":"","multiplex":{"enabled":true,"protocol":"yamux"}}]}"#,
            r#"{"outbounds":[{"type":"trojan","server":"secret.example","server_port":443,"password":"secret-password","tls":{"enabled":true},"transport":{"type":"http","path":"/secret"}}]}"#,
            r#"{"outbounds":[{"type":"trojan","server":"secret.example","server_port":443,"password":"secret-password"}]}"#,
            r#"{"outbounds":[{"type":"vless","server":"secret.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000031","detour":"secret-hop"}]}"#,
            r#"{"version":3,"servers":[{"server":"secret.example","server_port":8388,"method":"aes-256-gcm","password":"secret-password"}]}"#,
        ] {
            let error = parse_json_subscription(json(input), None)
                .unwrap_err()
                .to_string();
            assert!(!error.contains("secret"));
            assert!(!error.contains("00000000-0000-4000-8000-000000000031"));
        }
    }

    #[test]
    fn structural_or_unknown_only_sing_box_body_is_rejected() {
        for input in [
            r#"{"outbounds":[]}"#,
            r#"{"outbounds":[{"type":"selector","tag":"select","outbounds":[]},{"type":"direct","tag":"direct"},{"type":"http","tag":"unsupported","server":"proxy.example","server_port":8080}]}"#,
        ] {
            assert!(parse_json_subscription(json(input), None).is_err());
        }
    }

    #[test]
    fn configured_sip008_plugin_is_not_imported_as_plain_shadowsocks() {
        assert!(
            parse_json_subscription(
                json(
                    r#"{"version":1,"servers":[{"remarks":"plugin-node","server":"ss.example","server_port":8388,"method":"aes-256-gcm","password":"password","plugin":"v2ray-plugin","plugin_opts":"mode=websocket"}]}"#,
                ),
                None,
            )
            .is_err()
        );
    }
    const C09_SIP008_CREDENTIALS: &str = r#"{"servers":[
      {"remarks":"numeric","server":"sip.example","server_port":8388,"method":"aes-256-gcm","password":12345},
      {"remarks":"fractional","server":"fractional.example","server_port":8388,"method":"aes-256-gcm","password":1.25},
      {"remarks":"string-bytes","server":"string.example","server_port":8388,"method":"aes-256-gcm","password":" password-bytes "},
      {"remarks":"bool","server":"bool.example","server_port":8388,"method":"aes-256-gcm","password":true},
      {"remarks":"list","server":"list.example","server_port":8388,"method":"aes-256-gcm","password":[]},
      {"remarks":"map","server":"map.example","server_port":8388,"method":"aes-256-gcm","password":{}}
    ]}"#;
    const C09_SING_BOX_CREDENTIALS: &str = r#"{"outbounds":[
      {"type":"shadowsocks","tag":"numeric-password","server":"ss.example","server_port":8388,"method":"aes-256-gcm","password":54321},
      {"type":"hysteria2","tag":"numeric-auth","server":"hy.example","server_port":443,"password":67890,"tls":{"enabled":true}},
      {"type":"socks","tag":"null-password","server":"socks.example","server_port":1080,"password":null},
      {"type":"shadowsocks","tag":"bool-password","server":"bool.example","server_port":8388,"method":"aes-256-gcm","password":true},
      {"type":"shadowsocks","tag":"list-password","server":"list.example","server_port":8388,"method":"aes-256-gcm","password":[]},
      {"type":"shadowsocks","tag":"map-password","server":"map.example","server_port":8388,"method":"aes-256-gcm","password":{}},
      {"type":"vless","tag":"numeric-uuid","server":"uuid.example","server_port":443,"uuid":12345,"tls":{"enabled":true}}
    ]}"#;

    #[test]
    fn c09_structured_credentials_coerce_native_numbers_and_reject_invalid_types() {
        let sip = parse_json_subscription(json(C09_SIP008_CREDENTIALS), None).unwrap();
        assert_eq!(sip.len(), 3);
        assert_eq!(
            sip[0].shadowsocks().unwrap().password.as_deref(),
            Some("12345")
        );
        assert_eq!(
            sip[1].shadowsocks().unwrap().password.as_deref(),
            Some("1.25")
        );
        assert_eq!(
            sip[2].shadowsocks().unwrap().password.as_deref(),
            Some(" password-bytes ")
        );

        let nodes = parse_json_subscription(json(C09_SING_BOX_CREDENTIALS), None).unwrap();
        assert_eq!(
            nodes
                .iter()
                .map(|node| node.name.as_str())
                .collect::<Vec<_>>(),
            ["numeric-password", "numeric-auth", "null-password"]
        );
        assert_eq!(
            nodes[0].shadowsocks().unwrap().password.as_deref(),
            Some("54321")
        );
        assert_eq!(nodes[1].hysteria2().unwrap().auth.as_deref(), Some("67890"));
        assert_eq!(nodes[2].socks5().unwrap().password, None);
    }
    const C14_SING_BOX_DURATIONS: &str = r#"{"outbounds":[
      {"type":"hysteria2","tag":"hy2-native-zero","server":"hy2-native.example","server_port":443,"password":"password","hop_interval":0,"tls":{"enabled":true}},
      {"type":"hysteria2","tag":"hy2-text-zero","server":"hy2-text.example","server_port":443,"password":"password","hop_interval":"0","tls":{"enabled":true}},
      {"type":"hysteria2","tag":"hy2-subsecond","server":"hy2-subsecond.example","server_port":443,"password":"password","hop_interval":"500ms","tls":{"enabled":true}},
      {"type":"anytls","tag":"anytls-native-zero","server":"anytls-native.example","server_port":443,"password":"password","idle_session_check_interval":0,"idle_session_timeout":0,"tls":{"enabled":true}},
      {"type":"anytls","tag":"anytls-text-zero-subsecond","server":"anytls-text.example","server_port":443,"password":"password","idle_session_check_interval":"0","idle_session_timeout":"500ms","tls":{"enabled":true}},
      {"type":"anytls","tag":"anytls-missing","server":"anytls-missing.example","server_port":443,"password":"password","tls":{"enabled":true}},
      {"type":"anytls","tag":"anytls-null","server":"anytls-null.example","server_port":443,"password":"password","idle_session_check_interval":null,"idle_session_timeout":null,"tls":{"enabled":true}},
      {"type":"hysteria2","tag":"invalid-hop-type","server":"invalid-hop.example","server_port":443,"password":"password","hop_interval":[],"tls":{"enabled":true}},
      {"type":"anytls","tag":"invalid-anytls-timeout","server":"invalid-anytls.example","server_port":443,"password":"password","idle_session_timeout":{},"tls":{"enabled":true}}
    ]}"#;

    #[test]
    fn c14_sing_box_durations_preserve_zero_round_subsecond_and_absence() {
        let nodes = parse_json_subscription(json(C14_SING_BOX_DURATIONS), None).unwrap();
        assert_eq!(nodes[0].hysteria2().unwrap().hop_interval, Some(0));
        assert_eq!(nodes[1].hysteria2().unwrap().hop_interval, Some(0));
        assert_eq!(nodes[2].hysteria2().unwrap().hop_interval, Some(1));
        assert_eq!(
            nodes[3].anytls().unwrap().idle_session_check_interval,
            Some(0)
        );
        assert_eq!(nodes[3].anytls().unwrap().idle_session_timeout, Some(0));
        assert_eq!(
            nodes[4].anytls().unwrap().idle_session_check_interval,
            Some(0)
        );
        assert_eq!(nodes[4].anytls().unwrap().idle_session_timeout, Some(1));
        assert!(
            nodes[5]
                .anytls()
                .unwrap()
                .idle_session_check_interval
                .is_none()
        );
        assert!(nodes[5].anytls().unwrap().idle_session_timeout.is_none());
        assert!(
            nodes[6]
                .anytls()
                .unwrap()
                .idle_session_check_interval
                .is_none()
        );
        assert!(nodes[6].anytls().unwrap().idle_session_timeout.is_none());
    }

    #[test]
    fn c14_sing_box_invalid_duration_types_are_rejected_by_entry_policy() {
        let mut fixture = json(C14_SING_BOX_DURATIONS);
        let entries = fixture["outbounds"].as_sequence_mut().unwrap();
        for invalid in entries.drain(7..) {
            let mut body = Mapping::new();
            body.insert("outbounds".into(), Value::Sequence(vec![invalid]));
            assert!(parse_json_subscription(Value::Mapping(body), None).is_err());
        }
    }
}
