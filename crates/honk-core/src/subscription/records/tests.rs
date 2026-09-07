use super::*;

#[test]
fn public_parser_preserves_quoted_names_and_protocol_word_names() {
    let nodes = parse_records_subscription(
        r#""edge=west"=trojan,example.com,443," pass,word = "
trojan=trojan,example.com,443,password
trojan=example.com:443,password=qx,tag=qx
base64=ss,example.com,8388,aes-128-gcm,aGVsbG8="#,
        None,
    )
    .unwrap();
    assert_eq!(nodes.len(), 4);
    assert_eq!(nodes[0].name, "edge=west");
    assert_eq!(
        nodes[0].trojan().unwrap().password.as_deref(),
        Some(" pass,word = ")
    );
    assert_eq!(nodes[1].name, "trojan");
    assert_eq!(nodes[1].protocol().as_str(), "trojan");
    assert_eq!(nodes[2].name, "qx");
    assert_eq!(
        nodes[3].shadowsocks().unwrap().password.as_deref(),
        Some("aGVsbG8=")
    );
}

#[test]
fn public_parser_keeps_quoted_password_edge_spaces() {
    let nodes = parse_records_subscription(
        r#"node=trojan,example.com,443,password = " pass,word = ""#,
        None,
    )
    .unwrap();
    assert_eq!(
        nodes[0].trojan().unwrap().password.as_deref(),
        Some(" pass,word = ")
    );
}

#[test]
fn dialect_credentials_keep_alias_order_and_empty_shadowing() {
    let first = "11111111-1111-4111-8111-111111111111";
    let second = "22222222-2222-4222-8222-222222222222";
    let third = "33333333-3333-4333-8333-333333333333";
    let nodes = parse_records_subscription(
            &format!(
                "named-vmess=vmess,example.com,443,username={first},uuid={second},password={third}\n\
                 vmess=example.com:443,password={third},uuid={second},username={first},tag=qx-vmess\n\
                 named-vless=vless,example.com,443,uuid={second},password={third}\n\
                 vless=example.com:443,password={third},uuid={second},tag=qx-vless\n\
                 vmess=example.com:443,password=,uuid={second},tag=empty-shadow"
            ),
            None,
        )
        .unwrap();
    assert_eq!(nodes.len(), 4);
    assert_eq!(nodes[0].vmess().unwrap().uuid.as_deref(), Some(first));
    assert_eq!(nodes[1].vmess().unwrap().uuid.as_deref(), Some(third));
    assert_eq!(nodes[2].vless().unwrap().uuid.as_deref(), Some(second));
    assert_eq!(nodes[3].vless().unwrap().uuid.as_deref(), Some(third));
}

#[test]
fn unsupported_wire_extensions_are_dropped_with_sibling_survival() {
    let nodes = parse_records_subscription(
        "ss=example.com:443,method=aes-128-gcm,password=pwd,udp-relay=true,udp-over-tcp=sp.v2\n\
             ss=example.com:443,method=aes-128-gcm,password=pwd,ssr-protocol=auth_chain_b\n\
             trojan=example.com:443,password=chained,proxy=upstream\n\
             trojan=example.com:443,password=survivor,tag=survivor",
        None,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "survivor");
    assert_eq!(
        nodes[0].trojan().unwrap().password.as_deref(),
        Some("survivor")
    );
}

#[test]
fn disabled_wire_defaults_remain_accepted() {
    let nodes = parse_records_subscription(
            "trojan=example.com:443,password=pwd,udp-relay=false,udp-over-tcp=false,ssr-protocol=,ssr-protocol-param=,fast-open=false,tls13=true,server_check_url=http://127.0.0.1:1",
            None,
        )
        .unwrap();
    assert_eq!(nodes.len(), 1);
    assert!(nodes[0].trojan().is_some());
}

#[test]
fn conflicting_udp_aliases_are_rejected_without_dropping_siblings() {
    let nodes = parse_records_subscription(
        "trojan=example.com:443,password=conflict,udp=true,udp-relay=false\n\
             trojan=example.com:443,password=survivor,udp-relay=true,tag=survivor",
        None,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "survivor");
}

#[test]
fn qx_effective_pins_are_rejected_and_disabled_pins_stay_disabled() {
    let cert_pin = "ab".repeat(32);
    let public_pin = "cd".repeat(32);
    let nodes = parse_records_subscription(
            &format!(
                "trojan=192.0.2.1:443,password=pwd,over-tls=true,tls-verification=true,tls-cert-sha256={cert_pin},server-name=certificate.example,tag=cert\n\
                 trojan=192.0.2.1:443,password=pwd,tls-verification=true,tls-pubkey-sha256={public_pin},tag=unsupported\n\
                 trojan=192.0.2.1:443,password=pwd,tls-verification=false,tls-pubkey-sha256={public_pin},tls-cert-sha256={cert_pin},server-name=certificate.example,tag=insecure"
            ),
            None,
        )
        .unwrap();
    assert_eq!(nodes.len(), 1);
    let insecure = &nodes[0];
    assert_eq!(insecure.name, "insecure");
    assert_eq!(
        insecure.tls().unwrap().sni.as_deref(),
        Some("certificate.example")
    );
    assert!(insecure.tls().unwrap().skip_cert_verify);
    assert!(insecure.tls().unwrap().pin_sha256.is_none());
}

#[test]
fn named_tls_controls_are_mapped_or_rejected_without_losing_siblings() {
    let pin = "ab".repeat(32);
    let nodes = parse_records_subscription(
            &format!(
                "pinned=trojan,192.0.2.1,443,pwd,server-cert-fingerprint-sha256={pin}\n\
                 client-cert=trojan,example.com,443,pwd,client-cert=identity\n\
                 verify-name=trojan,example.com,443,pwd,server-cert-verify-name=certificate.example\n\
                 no-sni=trojan,example.com,443,pwd,sni=off\n\
                 shadow=trojan,example.com,443,pwd,shadow-tls-password=secret\n\
                 custom-alpn=trojan,example.com,443,pwd,alpn=h2\n\
                 future-wire=trojan,example.com,443,pwd,future-tls-mode=ech\n\
                 metadata=trojan,example.com,443,pwd,client-note=kept"
            ),
            None,
        )
        .unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0].name, "pinned");
    assert_eq!(
        nodes[0].tls().unwrap().pin_sha256.as_deref(),
        Some(pin.as_str())
    );
    assert_eq!(nodes[1].name, "metadata");
}

#[test]
fn qx_reality_ignores_only_alpn_and_session_ticket_customization() {
    let uuid = "44444444-4444-4444-8444-444444444444";
    let key = "k4Uxez0sjl8bKaZH2Vgi8-WDFshML51QkxKFLWFIONk";
    let nodes = parse_records_subscription(
            &format!(
                "vless=example.com:443,password={uuid},obfs=over-tls,reality-base64-pubkey={key},reality-hex-shortid=0123456789abcdef,tls-alpn=026832,tls-no-session-ticket=true,tag=reality\n\
                 vless=example.com:443,password={uuid},obfs=over-tls,reality-base64-pubkey={key},tls-no-session-reuse=true,tag=reuse\n\
                 vless=example.com:443,password={uuid},obfs=over-tls,reality-hex-shortid=0123456789abcdef,tls-alpn=026832,tag=malformed\n\
                 vless=example.com:443,password={uuid},obfs=ws,reality-base64-pubkey={key},tls-no-session-ticket=true,tag=disabled\n\
                 trojan=example.com:443,password=survivor,tag=survivor"
            ),
            None,
        )
        .unwrap();
    assert_eq!(nodes.len(), 2);
    let reality = nodes.iter().find(|node| node.name == "reality").unwrap();
    assert_eq!(
        reality.tls().unwrap().reality_public_key.as_deref(),
        Some(key)
    );
    assert!(nodes.iter().any(|node| node.name == "survivor"));
}

#[test]
fn qx_legacy_vmess_and_active_session_controls_are_rejected() {
    let uuid = "11111111-1111-4111-8111-111111111111";
    let nodes = parse_records_subscription(
        &format!(
            "vmess=example.com:80,password={uuid},aead=false,tag=legacy\n\
                 vmess=example.com:80,password={uuid},aead=true,tag=aead\n\
                 trojan=example.com:443,password=pwd,tls-no-session-reuse=true,tag=session\n\
                 trojan=example.com:443,password=pwd,tls-no-session-reuse=false,tag=default"
        ),
        None,
    )
    .unwrap();
    assert_eq!(nodes.len(), 2);
    assert!(nodes.iter().any(|node| node.name == "aead"));
    assert!(nodes.iter().any(|node| node.name == "default"));
}

#[test]
fn tuic_empty_password_and_h3_alpn_are_returned() {
    let uuid = "22222222-2222-4222-8222-222222222222";
    let nodes = parse_records_subscription(
        &format!(
            "tuic=example.com:443,uuid={uuid},password=,alpn=h3,tag=tuic\n\
                 juicity=example.com:443,uuid={uuid},password=pwd,alpn=h3,tag=juicity"
        ),
        None,
    )
    .unwrap();
    assert_eq!(nodes.len(), 2);
    assert!(
        nodes
            .iter()
            .find(|node| node.name == "tuic")
            .unwrap()
            .tuic()
            .is_some()
    );
    assert_eq!(
        nodes
            .iter()
            .find(|node| node.name == "juicity")
            .unwrap()
            .juicity()
            .unwrap()
            .password
            .as_deref(),
        Some("pwd")
    );
}

#[test]
fn reality_does_not_override_explicit_tls_disable() {
    let nodes = parse_records_subscription(
            "vless=example.com:443,password=33333333-3333-4333-8333-333333333333,obfs=over-tls,tls=false,reality-base64-pubkey=key,reality-hex-shortid=sid,tag=contradiction\n\
             trojan=example.com:443,password=survivor,tag=survivor",
            None,
        )
        .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "survivor");
}
