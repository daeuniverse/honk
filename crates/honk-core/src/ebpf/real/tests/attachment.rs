use super::*;

#[test]
#[ignore = "requires root; run via just test-netns"]
fn missing_dae0_attach_failure_is_propagated() {
    private_netns(|| {
        let mut netlink = crate::netlink::NlSock::new().unwrap();
        let missing = netlink
            .get_link("dae0")
            .expect_err("test namespace must not contain dae0");
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);

        let mut backend = RealEbpfBackend::load_routing_test_fixture(
            crate::DEFAULT_BPF_OBJECT,
            DaeParam::default(),
        )
        .expect("load embedded production object");
        let program: &mut aya::programs::SchedClassifier = backend
            .bpf_mut()
            .unwrap()
            .program_mut("dae0_ingress")
            .unwrap()
            .try_into()
            .unwrap();
        program
            .load()
            .expect("load valid reply program before attach");
        let caller_netns = std::fs::read_link("/proc/thread-self/ns/net").unwrap();
        let links_before = held_bpf_link_count();
        let error = backend
            .attach_dae0_programs()
            .expect_err("missing dae0 attach must fail");
        assert!(error.to_string().contains("attach dae0_ingress"));
        assert!(backend.dae0_ingress_link.is_none());
        assert_eq!(
            held_bpf_link_count(),
            links_before,
            "failed attach leaked a BPF link"
        );
        assert_eq!(
            std::fs::read_link("/proc/thread-self/ns/net").unwrap(),
            caller_netns,
            "failed attach changed the caller's network namespace"
        );
        assert!(
            netlink.get_link("dae0").is_err(),
            "failed attach created dae0"
        );
    });
}
