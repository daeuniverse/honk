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
    assert_eq!(nodes.len(), 3);
    assert_eq!(nodes[0].name, "pinned");
    assert_eq!(
        nodes[0].tls().unwrap().pin_sha256.as_deref(),
        Some(pin.as_str())
    );
    assert_eq!(nodes[1].name, "custom-alpn");
    assert_eq!(nodes[1].tls().unwrap().alpn, ["h2"]);
    assert_eq!(nodes[2].name, "metadata");
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

const C07_RECORD_TLS_ALIASES: &str = r#"named-all=trojan,example.com,443,fixture-password,servername=tls.example,server-name=tls.example,sni=tls.example,tls-name=tls.example,tls-host=tls.example,tag=named-all
named-baseline=trojan,example.com,443,fixture-password,sni=tls.example,tag=named-baseline
named-empty=trojan,empty.example,443,fixture-password,servername=,server-name=,sni=,tls-name=,tls-host=,tag=named-empty
named-conflict=trojan,conflict.example,443,fixture-password,servername=first.example,server-name=second.example,tag=named-conflict
named-off=trojan,off.example,443,fixture-password,sni=off,tag=named-off
vless=ws.example:443,password=11111111-1111-4111-8111-111111111111,obfs=wss,obfs-host=ws.example,tag=qx-wss-fallback
vless=explicit.example:443,password=22222222-2222-4222-8222-222222222222,obfs=wss,obfs-host=ws.example,sni=explicit.example,tag=qx-wss-explicit"#;

#[test]
fn c07_record_tls_aliases_coalesce_and_preserve_qx_wss_fallback() {
    let nodes = parse_records_subscription(C07_RECORD_TLS_ALIASES, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        [
            "named-all",
            "named-baseline",
            "named-empty",
            "qx-wss-fallback",
            "qx-wss-explicit"
        ]
    );

    let all = &nodes[0];
    let baseline = &nodes[1];
    let empty = &nodes[2];
    let fallback = &nodes[3];
    let explicit = &nodes[4];
    assert_eq!(all.tls().unwrap().sni.as_deref(), Some("tls.example"));
    assert_eq!(
        all.trojan().unwrap().password.as_deref(),
        Some("fixture-password")
    );
    assert_eq!(all.id, baseline.id);
    assert_eq!(empty.tls().unwrap().sni, None);
    assert_eq!(fallback.tls().unwrap().sni.as_deref(), Some("ws.example"));
    assert_eq!(fallback.transport().unwrap().transport, "ws");
    assert_eq!(
        fallback.transport().unwrap().ws_host.as_deref(),
        Some("ws.example")
    );
    assert_eq!(
        explicit.tls().unwrap().sni.as_deref(),
        Some("explicit.example")
    );
    assert_eq!(
        explicit.transport().unwrap().ws_host.as_deref(),
        Some("ws.example")
    );
}

const C07_RECORD_FLOW_ALIASES: &str = r#"named-both=vless,flow.example,443,33333333-3333-4333-8333-333333333333,flow=xtls-rprx-vision,vless-flow=xtls-rprx-vision,tls=true
named-flow-only=vless,flow.example,443,33333333-3333-4333-8333-333333333333,flow=xtls-rprx-vision,tls=true
named-vless-flow-only=vless,flow.example,443,33333333-3333-4333-8333-333333333333,vless-flow=xtls-rprx-vision,tls=true
vless=flow-qx.example:443,password=44444444-4444-4444-8444-444444444444,flow=xtls-rprx-vision,vless-flow=xtls-rprx-vision,tls=true,tag=qx-both
vless=flow-qx.example:443,password=44444444-4444-4444-8444-444444444444,flow=xtls-rprx-vision,tls=true,tag=qx-flow-only
vless=flow-qx.example:443,password=44444444-4444-4444-8444-444444444444,vless-flow=xtls-rprx-vision,tls=true,tag=qx-vless-flow-only
named-empty=vless,empty-flow.example,443,55555555-5555-4555-8555-555555555555,flow=,vless-flow=,tls=true,tag=named-empty
named-empty-baseline=vless,empty-flow.example,443,55555555-5555-4555-8555-555555555555,tls=true,tag=named-empty-baseline
vless=empty-qx.example:443,password=66666666-6666-4666-8666-666666666666,flow=,vless-flow=,tls=true,tag=qx-empty
vless=empty-qx.example:443,password=66666666-6666-4666-8666-666666666666,tls=true,tag=qx-empty-baseline
named-positional=vless,positional.example,443,77777777-7777-4777-8777-777777777777,xtls-rprx-vision,tls=true
named-conflict=vless,conflict-flow.example,443,88888888-8888-4888-8888-888888888888,flow=xtls-rprx-vision,vless-flow=other-flow,tls=true
vless=conflict-qx.example:443,password=99999999-9999-4999-8999-999999999999,flow=xtls-rprx-vision,vless-flow=other-flow,tls=true,tag=qx-conflict"#;
#[test]
fn c07_record_flow_aliases_resolve_by_dialect_without_positional_fallback() {
    let nodes = parse_records_subscription(C07_RECORD_FLOW_ALIASES, None).unwrap();
    assert_eq!(nodes.len(), 11);
    assert!(nodes.iter().all(|node| node.vless().is_some()));

    let named_both = nodes.iter().find(|node| node.name == "named-both").unwrap();
    let named_flow_only = nodes
        .iter()
        .find(|node| node.name == "named-flow-only")
        .unwrap();
    let named_vless_flow_only = nodes
        .iter()
        .find(|node| node.name == "named-vless-flow-only")
        .unwrap();
    let qx_both = nodes.iter().find(|node| node.name == "qx-both").unwrap();
    let qx_flow_only = nodes
        .iter()
        .find(|node| node.name == "qx-flow-only")
        .unwrap();
    let qx_vless_flow_only = nodes
        .iter()
        .find(|node| node.name == "qx-vless-flow-only")
        .unwrap();
    let named_empty = nodes
        .iter()
        .find(|node| node.name == "named-empty")
        .unwrap();
    let named_empty_baseline = nodes
        .iter()
        .find(|node| node.name == "named-empty-baseline")
        .unwrap();
    let qx_empty = nodes.iter().find(|node| node.name == "qx-empty").unwrap();
    let qx_empty_baseline = nodes
        .iter()
        .find(|node| node.name == "qx-empty-baseline")
        .unwrap();
    let named_positional = nodes
        .iter()
        .find(|node| node.name == "named-positional")
        .unwrap();

    for node in [
        named_both,
        named_flow_only,
        named_vless_flow_only,
        qx_both,
        qx_flow_only,
        qx_vless_flow_only,
    ] {
        assert_eq!(
            node.vless().unwrap().flow.as_deref(),
            Some("xtls-rprx-vision")
        );
    }
    for node in [
        named_empty,
        named_empty_baseline,
        qx_empty,
        qx_empty_baseline,
        named_positional,
    ] {
        assert_eq!(node.vless().unwrap().flow.as_deref(), None);
    }

    for (left, right) in [
        (named_both, named_flow_only),
        (named_both, named_vless_flow_only),
        (qx_both, qx_flow_only),
        (qx_both, qx_vless_flow_only),
        (named_empty, named_empty_baseline),
        (qx_empty, qx_empty_baseline),
    ] {
        assert_eq!(left.id, right.id);
    }
}

fn c08_record_verification_fixture(pin: &str) -> String {
    format!(
        r#"named-equal=trojan,plain.example,443,password,skip-cert-verify=true,allow-insecure=true,insecure=true
inverse-agree=trojan,inverse.example,443,password,tls-verification=false,insecure=true
inverse-conflict=trojan,inverse-conflict.example,443,password,tls-verification=true,insecure=true
plain-conflict=trojan,plain-conflict.example,443,password,skip-cert-verify=true,insecure=false
invalid-t=trojan,invalid-t.example,443,password,skip-cert-verify=true,allow-insecure=t
invalid-y=trojan,invalid-y.example,443,password,skip-cert-verify=true,allow-insecure=y
invalid-f=trojan,invalid-f.example,443,password,skip-cert-verify=true,allow-insecure=f
invalid-n=trojan,invalid-n.example,443,password,skip-cert-verify=true,allow-insecure=n
invalid-empty=trojan,invalid-empty.example,443,password,skip-cert-verify=true,allow-insecure=
trojan=qx-agree.example:443,password=password,tls-verification=false,insecure=true,tls-cert-sha256={pin},tag=qx-pins-agree
trojan=qx-reject.example:443,password=password,tls-verification=true,insecure=false,tls-cert-sha256={pin},tag=qx-pins-reject"#
    )
}

#[test]
fn c08_record_verification_aliases_resolve_before_qx_pin_controls() {
    let pin = "ab".repeat(32);
    let nodes = parse_records_subscription(&c08_record_verification_fixture(&pin), None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["named-equal", "inverse-agree", "qx-pins-agree"]
    );

    for node in &nodes {
        assert!(node.tls().unwrap().skip_cert_verify);
    }
    assert_eq!(nodes[0].tls().unwrap().pin_sha256, None);
    assert_eq!(nodes[2].tls().unwrap().pin_sha256, None);
}

const C09_RECORD_CREDENTIALS: &str = r#"ss-named-explicit=ss,ss-explicit.example,8388,positional-cipher,positional-password,encrypt-method=aes-128-gcm,method=aes-128-gcm,cipher=aes-128-gcm,password=explicit-password
ss-named-positional=ss,ss-positional.example,8388,aes-128-gcm,positional-password
ss=ss-qx.example:8388,method=aes-128-gcm,cipher=aes-128-gcm,encrypt-method=aes-128-gcm,password=qx-password,tag=ss-qx-equal
socks-named-positional=socks5,socks-positional.example,1080,named-user,named-password
socks5=socks-qx.example:1080,username=qx-user,password=qx-password,tag=socks-qx-explicit
vmess-named-equal=vmess,vmess.example,443,positional-cipher,11111111-1111-4111-8111-111111111111,username=11111111-1111-4111-8111-111111111111,uuid=11111111-1111-4111-8111-111111111111,password=11111111-1111-4111-8111-111111111111,method=auto,encryption=auto,cipher=auto,tls=true
vmess-named-positional=vmess,vmess-positional.example,443,auto,22222222-2222-4222-8222-222222222222,tls=true
vmess=vmess-qx.example:443,password=33333333-3333-4333-8333-333333333333,uuid=33333333-3333-4333-8333-333333333333,username=33333333-3333-4333-8333-333333333333,method=auto,cipher=auto,tls=true,tag=vmess-qx-equal
vless-named-equal=vless,vless.example,443,44444444-4444-4444-8444-444444444444,uuid=44444444-4444-4444-8444-444444444444,password=44444444-4444-4444-8444-444444444444,tls=true
vless-named-positional=vless,vless-positional.example,443,55555555-5555-4555-8555-555555555555,tls=true
vless=vless-qx.example:443,password=66666666-6666-4666-8666-666666666666,uuid=66666666-6666-4666-8666-666666666666,tls=true,tag=vless-qx-equal
hysteria2-named-equal=hysteria2,hy2.example,443,password=hy2-password,auth=hy2-password,tls=true
hysteria2-named-positional=hysteria2,hy2-positional.example,443,hy2-positional-auth,tls=true
hysteria2=hy2-qx.example:443,password=qx-hy2-password,auth=qx-hy2-password,tls=true,tag=hy2-qx-equal
tuic-named-equal=tuic,tuic.example,443,uuid=77777777-7777-4777-8777-777777777777,username=77777777-7777-4777-8777-777777777777,password=tuic-password,tls=true
tuic-named-positional=tuic,tuic-positional.example,443,88888888-8888-4888-8888-888888888888,tuic-positional-password,tls=true
tuic=tuic-qx.example:443,uuid=99999999-9999-4999-8999-999999999999,username=99999999-9999-4999-8999-999999999999,password=qx-tuic-password,tls=true,tag=tuic-qx-equal
trojan-named-explicit=trojan,trojan-explicit.example,443,positional-password,password=explicit-password,tls=true
trojan-named-positional=trojan,trojan-positional.example,443,positional-password,tls=true
anytls-named-explicit=anytls,anytls-explicit.example,443,positional-password,password=explicit-password,tls=true
anytls-named-positional=anytls,anytls-positional.example,443,positional-password,tls=true
ss-named-repeated-equal=ss,ss-repeat.example,8388,aes-128-gcm,repeat,password=repeat,password=repeat
ss-named-conflict=ss,ss-conflict.example,8388,method=aes-128-gcm,cipher=chacha20,password=secret
ss-named-repeated-conflict=ss,ss-repeat-conflict.example,8388,aes-128-gcm,password=first,password=second
vmess-named-conflict=vmess,vmess-conflict.example,443,username=11111111-1111-4111-8111-111111111111,uuid=22222222-2222-4222-8222-222222222222,tls=true
vmess=vmess-qx-conflict.example:443,password=11111111-1111-4111-8111-111111111111,uuid=22222222-2222-4222-8222-222222222222,tls=true,tag=vmess-qx-conflict
vless=vless-qx-conflict.example:443,password=11111111-1111-4111-8111-111111111111,uuid=22222222-2222-4222-8222-222222222222,tls=true,tag=vless-qx-conflict
hysteria2=hy2-qx-conflict.example:443,password=first,auth=second,tls=true,tag=hy2-qx-conflict
tuic=tuic-qx-conflict.example:443,uuid=11111111-1111-4111-8111-111111111111,username=22222222-2222-4222-8222-222222222222,password=password,tls=true,tag=tuic-qx-conflict
hysteria2=hy2-qx-empty.example:443,password=,auth=usable,tls=true,tag=hy2-qx-empty"#;

#[test]
fn c09_record_credentials_resolve_aliases_before_positional_fallback() {
    let nodes = parse_records_subscription(C09_RECORD_CREDENTIALS, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        [
            "ss-named-explicit",
            "ss-named-positional",
            "ss-qx-equal",
            "socks-named-positional",
            "socks-qx-explicit",
            "vmess-named-equal",
            "vmess-named-positional",
            "vmess-qx-equal",
            "vless-named-equal",
            "vless-named-positional",
            "vless-qx-equal",
            "hysteria2-named-equal",
            "hysteria2-named-positional",
            "hy2-qx-equal",
            "tuic-named-equal",
            "tuic-named-positional",
            "tuic-qx-equal",
            "trojan-named-explicit",
            "trojan-named-positional",
            "anytls-named-explicit",
            "anytls-named-positional",
            "ss-named-repeated-equal"
        ]
    );

    let explicit_ss = &nodes[0];
    assert_eq!(
        explicit_ss.shadowsocks().unwrap().encryption.as_deref(),
        Some("aes-128-gcm")
    );
    assert_eq!(
        explicit_ss.shadowsocks().unwrap().password.as_deref(),
        Some("explicit-password")
    );
    assert_eq!(
        nodes[1].shadowsocks().unwrap().password.as_deref(),
        Some("positional-password")
    );
    assert_eq!(
        nodes[3].socks5().unwrap().username.as_deref(),
        Some("named-user")
    );
    assert_eq!(
        nodes[5].vmess().unwrap().uuid.as_deref(),
        Some("11111111-1111-4111-8111-111111111111")
    );
    assert_eq!(
        nodes[6].vmess().unwrap().uuid.as_deref(),
        Some("22222222-2222-4222-8222-222222222222")
    );
    assert_eq!(
        nodes[8].vless().unwrap().uuid.as_deref(),
        Some("44444444-4444-4444-8444-444444444444")
    );
    assert_eq!(
        nodes[12].hysteria2().unwrap().auth.as_deref(),
        Some("hy2-positional-auth")
    );
    assert_eq!(
        nodes[15].tuic().unwrap().uuid.as_deref(),
        Some("88888888-8888-4888-8888-888888888888")
    );
    assert_eq!(
        nodes[17].trojan().unwrap().password.as_deref(),
        Some("explicit-password")
    );
    assert_eq!(
        nodes[19].anytls().unwrap().password.as_deref(),
        Some("explicit-password")
    );
    assert_eq!(
        nodes[21].shadowsocks().unwrap().password.as_deref(),
        Some("repeat")
    );
}

const B2_EMPTY_CREDENTIALS: &str = r#"socks5=example.com:1080,username=user,password="",tag=socks
hysteria2=example.com:443,auth="",tag=hy2
tuic=example.com:443,uuid=11111111-1111-4111-8111-111111111111,password="",tag=tuic"#;
const B2_SPACE_CREDENTIALS: &str =
    r#"socks5=example.com:1080,username=" ",password="  ",tag=spaces"#;
const B2_EMPTY_OVERRIDE: &str =
    r#"empty=socks5,example.com,1080,fallback-user,fallback-password,username="",password="""#;

#[test]
fn b2_record_permitted_empty_credentials_survive() {
    let nodes = parse_records_subscription(B2_EMPTY_CREDENTIALS, None).unwrap();
    assert_eq!(nodes[0].socks5().unwrap().password.as_deref(), Some(""));
    assert_eq!(nodes[1].hysteria2().unwrap().auth.as_deref(), Some(""));
    assert_eq!(nodes[2].tuic().unwrap().password.as_deref(), Some(""));
}

#[test]
fn b2_record_quoted_credential_whitespace_survives() {
    let nodes = parse_records_subscription(B2_SPACE_CREDENTIALS, None).unwrap();
    let credentials = nodes[0].socks5().unwrap();
    assert_eq!(credentials.username.as_deref(), Some(" "));
    assert_eq!(credentials.password.as_deref(), Some("  "));
}

#[test]
fn b2_record_explicit_empty_overrides_positional_credentials() {
    let nodes = parse_records_subscription(B2_EMPTY_OVERRIDE, None).unwrap();
    let credentials = nodes[0].socks5().unwrap();
    assert_eq!(credentials.username.as_deref(), Some(""));
    assert_eq!(credentials.password.as_deref(), Some(""));
}

const C10_RECORD_TRANSPORTS: &str = r#"raw-tcp=trojan,raw.example,443,password=secret,transport=tcp,network=tcp
ws-equal=trojan,ws.example,443,password=secret,transport=WS,transport=ws,network=ws
grpc-equal=trojan,grpc.example,443,password=secret,transport=grpc,network=grpc
transport-conflict=trojan,conflict.example,443,password=secret,transport=ws,network=grpc
unsupported-h2=trojan,h2.example,443,password=secret,transport=h2"#;

#[test]
fn c10_record_transport_aliases_resolve_before_loss() {
    let nodes = parse_records_subscription(C10_RECORD_TRANSPORTS, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        ["raw-tcp", "ws-equal", "grpc-equal"]
    );
    assert_eq!(nodes[0].transport().unwrap().transport, "tcp");
    assert_eq!(nodes[1].transport().unwrap().transport, "ws");
    assert_eq!(nodes[2].transport().unwrap().transport, "grpc");
}

const B4_RECORD_PACKET_REJECTIONS: &[&str] = &[
    "anytls=example.com:443,password=fixture,network=quic,network=tcp,udp=false,tag=invalid",
    "anytls=example.com:443,password=fixture,network=udp,network=tcp,tag=conflict",
    "anytls=example.com:443,password=fixture,udp=true,udp=false,tag=conflict",
    "anytls=example.com:443,password=fixture,udp-relay=true,udp-relay=false,tag=conflict",
];
const B4_RECORD_PACKET_AGREEMENT: &str = r#"anytls=example.com:443,password=fixture,network=udp,network="tcp,udp",udp=true,udp-relay=on,tag=agreement"#;

#[test]
fn b4_record_packet_occurrences_cannot_hide_invalid_claims() {
    for record in B4_RECORD_PACKET_REJECTIONS {
        assert!(parse_records_subscription(record, None).is_err());
    }
}

#[test]
fn b4_record_equivalent_packet_claims_keep_first_spelling() {
    let nodes = parse_records_subscription(B4_RECORD_PACKET_AGREEMENT, None).unwrap();
    assert_eq!(nodes[0].network(), Some("udp"));
}

const B4_RECORD_VLESS_PACKET_ENCODINGS: &str = r#"none=vless,none.example,443,00000000-0000-4000-8000-000000000051,packet-encoding=none
empty=vless,empty.example,443,00000000-0000-4000-8000-000000000052,packet_encoding=
aliases=vless,aliases.example,443,00000000-0000-4000-8000-000000000053,packet-encoding=none,packet_encoding=
xudp-disabled=vless,xudp.example,443,00000000-0000-4000-8000-000000000054,packetencoding=xudp,udp=false
vision-native-tcp=vless,vision.example,443,00000000-0000-4000-8000-000000000055,packet-encoding=none,udp=false,flow=xtls-rprx-vision,tls=true
omitted=vless,omitted.example,443,00000000-0000-4000-8000-000000000059
udp-alias=vless,udp.example,443,00000000-0000-4000-8000-000000000060,udp-relay=true
conflict=vless,conflict.example,443,00000000-0000-4000-8000-000000000056,packet-encoding=none,packet_encoding=xudp
hidden-invalid=vless,invalid.example,443,00000000-0000-4000-8000-000000000057,packet-encoding=invalid,packet-encoding=none
conflict-empty=vless,empty-conflict.example,443,00000000-0000-4000-8000-000000000058,packetencoding=xudp,packet_encoding="#;

#[test]
fn b4_record_vless_packet_aliases_preserve_native_and_reject_conflicts() {
    let nodes = parse_records_subscription(B4_RECORD_VLESS_PACKET_ENCODINGS, None).unwrap();
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>(),
        [
            "none",
            "empty",
            "aliases",
            "xudp-disabled",
            "vision-native-tcp",
            "omitted",
            "udp-alias",
        ]
    );
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.vless().unwrap().udp_encoding)
            .collect::<Vec<_>>(),
        [
            honk_config::node::VlessUdpEncoding::Native,
            honk_config::node::VlessUdpEncoding::Native,
            honk_config::node::VlessUdpEncoding::Native,
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessUdpEncoding::Auto,
            honk_config::node::VlessUdpEncoding::Xudp,
        ]
    );
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.vless().unwrap().udp_enabled())
            .collect::<Vec<_>>(),
        [true, true, true, false, false, false, true]
    );
    assert!(nodes.iter().all(|node| node.id == node.derive_id()));
}

#[test]
fn record_vless_mode_is_rejected_before_disabled_value_cleanup() {
    let fields = split_fields(
        "removed=vless,removed.example,443,00000000-0000-4000-8000-000000000060,vless_mode=",
    )
    .unwrap();
    assert_eq!(
        parse_record(&fields).unwrap_err(),
        "VLESS vless_mode was removed"
    );
    let nodes = parse_records_subscription(
        r#"null=vless,null.example,443,00000000-0000-4000-8000-000000000061,vless_mode=
empty=vless,empty.example,443,00000000-0000-4000-8000-000000000062,vless_mode=off
false=vless,false.example,443,00000000-0000-4000-8000-000000000063,vless_mode=false
old-value=vless,old.example,443,00000000-0000-4000-8000-000000000064,vless_mode=legacy
vmess-unchanged=vmess,vmess.example,443,auto,00000000-0000-4000-8000-000000000065,vless_mode=off"#,
        None,
    )
    .unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].name, "vmess-unchanged");
}

const B4_RECORD_DURATION_CONFLICT: &str =
    "hysteria2=example.com:443,password=fixture,mhop=1s,hop_interval=2s,tag=conflict";
const B4_RECORD_DURATION_EQUIVALENT: &str = "hysteria2=example.com:443,password=fixture,mhop=500ms,hop-interval=1s,hop_interval=1000ms,tag=equal";

#[test]
fn b4_record_duration_aliases_compare_converted_seconds() {
    let nodes = parse_records_subscription(B4_RECORD_DURATION_EQUIVALENT, None).unwrap();
    assert_eq!(nodes[0].hysteria2().unwrap().hop_interval, Some(1));
    assert!(parse_records_subscription(B4_RECORD_DURATION_CONFLICT, None).is_err());
}

#[test]
fn b4_record_repeated_duration_cannot_hide_invalid_claim() {
    let invalid =
        B4_RECORD_DURATION_CONFLICT.replace("mhop=1s,hop_interval=2s", "mhop=bad,mhop=1s");
    assert!(parse_records_subscription(&invalid, None).is_err());
}
