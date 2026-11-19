//! End-to-end dae-text checks for the `inbound` section: the shared user
//! table, listener blocks, and their merge into `InboundConfig`. A previous
//! regression dropped everything but `socks5` at the section dispatcher, so
//! these cover the full document → config → validate path.

mod inbound_syntax {
    use honk_config::parser::parse_dae_config_with_detailed_diagnostics;

    #[test]
    fn shared_users_and_http_block_parse_into_inbound() {
        let input = "inbound {\n\
                     users {\n\
                     alice: pw-a\n\
                     bob: pw-b\n\
                     }\n\
                     socks5 {\n\
                     bind: '0.0.0.0:7891'\n\
                     }\n\
                     http {\n\
                     bind: '0.0.0.0:7890'\n\
                     }\n\
                     }\n";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(config.inbound.users.len(), 2);
        assert_eq!(config.inbound.users[0].username, "alice");
        assert_eq!(config.inbound.socks5.len(), 1);
        assert_eq!(config.inbound.socks5[0].bind, "0.0.0.0:7891");
        assert!(config.inbound.socks5[0].users.is_empty());
        assert_eq!(config.inbound.http.len(), 1);
        assert_eq!(config.inbound.http[0].bind, "0.0.0.0:7890");
        config.inbound.validate().unwrap();
        assert_eq!(
            config
                .inbound
                .effective_users(&config.inbound.socks5[0].users)
                .len(),
            2
        );
        assert_eq!(
            config
                .inbound
                .effective_users(&config.inbound.http[0].users)
                .len(),
            2
        );
    }

    #[test]
    fn listener_local_users_still_parse() {
        let input = "inbound {\n\
                     socks5 {\n\
                     bind: '0.0.0.0:7891'\n\
                     users {\n\
                     carol: pw-c\n\
                     }\n\
                     }\n\
                     }\n";
        let mut diagnostics = Vec::new();
        let config = parse_dae_config_with_detailed_diagnostics(input, &mut diagnostics).unwrap();
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert!(config.inbound.users.is_empty());
        assert_eq!(config.inbound.socks5[0].users.len(), 1);
        config.inbound.validate().unwrap();
    }
}
