use super::*;

pub(super) static RESOLVER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub(super) struct ResolverReset(Option<UrltestResolver>);

impl ResolverReset {
    pub(super) fn install(hook: UrltestResolver) -> Self {
        Self(URLTEST_RESOLVER.write().replace(hook))
    }
}

impl Drop for ResolverReset {
    fn drop(&mut self) {
        *URLTEST_RESOLVER.write() = self.0.take();
    }
}

#[tokio::test]
async fn hook_supplies_addresses_and_preserves_rejection() {
    let _lock = RESOLVER_LOCK.lock().await;
    let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let called2 = called.clone();
    let hook: UrltestResolver = Arc::new(move |host, port| {
        let called2 = called2.clone();
        Box::pin(async move {
            // Other urltest tests run concurrently against this global
            // hook — answer only our hosts and pass foreigners through.
            if host == "rejected.invalid" {
                return Err(anyhow::Error::new(crate::proxy::PacketRejection::Policy));
            }
            if host == "empty.invalid" {
                return Ok(Vec::new());
            }
            if host == "example.invalid" && port == 443 {
                called2.store(true, std::sync::atomic::Ordering::Relaxed);
                return Ok(vec!["127.0.0.1:443".parse().unwrap()]);
            }
            tokio::net::lookup_host(format!("{host}:{port}"))
                .await
                .map(|addrs| addrs.collect())
                .map_err(anyhow::Error::from)
        })
    });
    let _reset = ResolverReset::install(hook);
    let node = honk_config::Config::builtin_direct_node();
    // The dial itself fails (nothing on 127.0.0.1:443) but the hook
    // must have been consulted first.
    let handler = crate::proxy::direct::DirectHandler::new();
    let _ = urltest_node(
        &crate::runtime::NodeRuntime::try_ephemeral(&node).unwrap(),
        &handler,
        "https://example.invalid/",
        Duration::from_millis(50),
    )
    .await;
    assert!(called.load(std::sync::atomic::Ordering::Relaxed));

    let error = resolve_urltest_address("rejected.invalid", 443)
        .await
        .expect_err("typed hook rejection");
    assert!(crate::proxy::is_packet_rejection(&error));

    resolve_urltest_address("empty.invalid", 443)
        .await
        .expect_err("empty hook result");
}
