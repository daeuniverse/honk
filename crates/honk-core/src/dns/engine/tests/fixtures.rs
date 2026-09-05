struct SequenceExchange {
    replies: StdMutex<HashMap<String, VecDeque<anyhow::Result<Vec<u8>>>>>,
    cache_probe: Option<Arc<Mutex<DnsCache>>>,
    calls: AtomicUsize,
}
#[async_trait]
impl DnsUpstreamPool for SequenceExchange {
    async fn query(&self, upstream: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(cache) = &self.cache_probe {
            assert!(
                cache.try_lock().is_ok(),
                "cache guard held at exchange await"
            );
        }
        self.replies
            .lock()
            .expect("reply lock")
            .get_mut(upstream)
            .and_then(VecDeque::pop_front)
            .map(|reply| {
                reply.map(|mut response| {
                    response[0..2].copy_from_slice(&query[0..2]);
                    response
                })
            })
            .unwrap_or_else(|| anyhow::bail!("missing reply for {upstream}"))
    }
}

fn response(query: &[u8], ip: [u8; 4], ttl: u32) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[0..2].copy_from_slice(&[0, 0]);
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[6..8].copy_from_slice(&1_u16.to_be_bytes());
    wire.extend_from_slice(&[
        0xc0,
        0x0c,
        0,
        1,
        0,
        1,
        ttl.to_be_bytes()[0],
        ttl.to_be_bytes()[1],
        ttl.to_be_bytes()[2],
        ttl.to_be_bytes()[3],
        0,
        4,
        ip[0],
        ip[1],
        ip[2],
        ip[3],
    ]);
    wire
}

fn router(
    initial: &str,
    response_rules: Vec<DnsResponseRule>,
    fixed_ttl: Option<u32>,
) -> Arc<DnsRouter> {
    let routing = DnsRouting {
        request: DnsRequestRouting {
            rules: Vec::new(),
            fallback: DnsRequestAction::Upstream(initial.to_owned()),
        },
        response: DnsResponseRouting {
            rules: response_rules,
            fallback: DnsResponseAction::Accept,
        },
        ..Default::default()
    };
    let fixed = fixed_ttl
        .map(|ttl| HashMap::from([("example.com".to_owned(), ttl)]))
        .unwrap_or_default();
    Arc::new(DnsRouter::new_with_fixed_ttl(&routing, &fixed).expect("router"))
}

fn exchange(
    replies: impl IntoIterator<Item = (&'static str, anyhow::Result<Vec<u8>>)>,
    cache_probe: Option<Arc<Mutex<DnsCache>>>,
) -> Arc<SequenceExchange> {
    let mut by_upstream: HashMap<String, VecDeque<anyhow::Result<Vec<u8>>>> = HashMap::new();
    for (upstream, reply) in replies {
        by_upstream
            .entry(upstream.to_owned())
            .or_default()
            .push_back(reply);
    }
    Arc::new(SequenceExchange {
        replies: StdMutex::new(by_upstream),
        cache_probe,
        calls: AtomicUsize::new(0),
    })
}


fn edns_query(version: u8, option: Option<(u16, &[u8])>) -> Vec<u8> {
    let mut query = build_dns_query("example.com", 1);
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 41, 4, 208, 0, version, 0, 0]);
    let option_len = option
        .map(|(_, data)| 4_usize.saturating_add(data.len()))
        .unwrap_or_default();
    query.extend_from_slice(&(option_len as u16).to_be_bytes());
    if let Some((code, data)) = option {
        query.extend_from_slice(&code.to_be_bytes());
        query.extend_from_slice(&(data.len() as u16).to_be_bytes());
        query.extend_from_slice(data);
    }
    query
}

fn ineligible_queries() -> Vec<(&'static str, Vec<u8>)> {
    let mut non_query = build_dns_query("example.com", 1);
    non_query[2] = 0x09;
    let mut unsupported_flags = build_dns_query("example.com", 1);
    unsupported_flags[2..4].copy_from_slice(&0x0140_u16.to_be_bytes());
    vec![
        ("non-QUERY", non_query),
        ("unsupported-flags", unsupported_flags),
        ("EDNSv1", edns_query(1, None)),
        ("ECS", edns_query(0, Some((8, &[0, 1, 2, 3])))),
        ("COOKIE", edns_query(0, Some((10, &[1, 2, 3, 4])))),
        ("unknown-EDNS", edns_query(0, Some((65, &[])))),
    ]
}

fn nodata_response(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[0..2].copy_from_slice(&[0, 0]);
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire
}

fn ineligible_response(query: &[u8]) -> Vec<u8> {
    let mut wire = query.to_vec();
    wire[0..2].copy_from_slice(&[0, 0]);
    wire[2] |= 0x80;
    wire[3] |= 0x80;
    wire
}

struct OverlapExchange {
    entered: mpsc::UnboundedSender<()>,
    release: Arc<Barrier>,
}

#[async_trait]
impl DnsUpstreamPool for OverlapExchange {
    async fn query(&self, _: &str, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.entered.send(()).expect("test receiver remains open");
        self.release.wait().await;
        let mut response = query.to_vec();
        response[0..2].copy_from_slice(&[0, 0]);
        response[2] |= 0x80;
        response[3] |= 0x80;
        Ok(response)
    }
}
