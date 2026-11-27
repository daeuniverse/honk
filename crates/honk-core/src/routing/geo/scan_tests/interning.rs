use super::*;
use crate::dns::routing::DnsRouter;
use honk_config::routing::RoutingCondition;

fn sites(codes: &[&str]) -> RoutingCondition {
    RoutingCondition {
        geosite: codes.iter().map(|code| (*code).into()).collect(),
        ..Default::default()
    }
}

fn id(
    condition: &RoutingCondition,
    assets: &GeoAssets,
    shared: &mut SharedMatchers,
    registry: &mut DomainRegistry,
) -> anyhow::Result<u32> {
    let mut result = Vec::new();
    append_conditions(&mut result, false, condition, assets, registry, shared)?;
    let [
        CompiledCondition {
            predicate: CompiledPredicate::Domain(id),
            ..
        },
    ] = result.as_slice()
    else {
        panic!("expected exactly one domain predicate");
    };
    Ok(*id)
}

fn overlapping(second: &str) -> Vec<u8> {
    let common = domain_msg(2, "Ä.example", &[("Hot", None)]);
    let extra = domain_msg(3, second, &[]);
    geosite_dat(&[
        ("A", vec![common.clone(), common.clone()]),
        ("B", vec![common.clone(), extra.clone()]),
        ("UNION", vec![extra, common]),
    ])
}

#[test]
fn unions_intern_by_content_and_keep_display_order_separate() {
    let bytes = overlapping("b.example");
    let assets = assets_for(&bytes, &["a", "b", "union", "b@hot"]);
    let mut registry = DomainRegistry::default();
    let mut shared = SharedMatchers::default();
    let mut compile =
        |codes: &[&str]| id(&sites(codes), &assets, &mut shared, &mut registry).unwrap();
    assert_eq!(compile(&["a", "b"]), 0);
    assert_eq!(compile(&["b", "a", "B"]), 0);
    assert_eq!(compile(&["union"]), 0);
    assert_eq!(compile(&["a"]), 1);
    assert_eq!(compile(&["B@HOT"]), 1);
    assert_ne!(registry.keys[0], registry.keys[1]);
    let replacement = overlapping("replacement.example");
    let assets = assets_for(&replacement, &["union"]);
    assert_eq!(
        id(
            &sites(&["union"]),
            &assets,
            &mut SharedMatchers::default(),
            &mut registry
        )
        .unwrap(),
        2
    );

    let fingerprint = |codes: &str, bytes: &[u8]| {
        let config = honk_config::parser::parse_dae_config(&format!(
            "routing {{\n domain({codes}) -> direct\n fallback: block\n }}",
        ))
        .unwrap();
        Router::from_config_with_geo_sources(
            &config.routing,
            &GeoSourceSet::from_bytes(bytes.to_vec(), vec![]),
        )
        .unwrap()
        .policy_fingerprint()
    };
    assert_ne!(
        fingerprint("geosite:a, geosite:b", &bytes),
        fingerprint("geosite:b, geosite:a", &bytes)
    );
    assert_ne!(
        fingerprint("geosite:union", &bytes),
        fingerprint("geosite:union", &replacement)
    );
}

#[test]
fn class_tags_unicode_folding_and_glob_text_determine_identity() {
    let mut categories = Vec::new();
    for (i, kind) in [3, 2, 0, 1].into_iter().enumerate() {
        for (j, text) in ["Ä", "ä"].into_iter().enumerate() {
            categories.push((format!("k{i}-{j}"), vec![domain_msg(kind, text, &[])]));
        }
    }
    let codes: Vec<_> = categories.iter().map(|(code, _)| code.as_str()).collect();
    let bytes = geosite_dat(
        &categories
            .iter()
            .map(|(code, entries)| (code.as_str(), entries.clone()))
            .collect::<Vec<_>>(),
    );
    let assets = assets_for(&bytes, &codes);
    let mut registry = DomainRegistry::default();
    let mut shared = SharedMatchers::default();
    let mut compile = |condition| id(&condition, &assets, &mut shared, &mut registry).unwrap();
    let geo_ids: Vec<_> = codes.iter().map(|code| compile(sites(&[code]))).collect();
    assert_eq!(geo_ids, [0, 0, 1, 1, 2, 3, 4, 5]);
    for (expected, fields) in [
        RoutingCondition {
            domain_suffix: vec!["Ä".into()],
            ..Default::default()
        },
        RoutingCondition {
            domain_keyword: vec!["Ä".into()],
            ..Default::default()
        },
        RoutingCondition {
            domain_regex: vec!["Ä".into()],
            ..Default::default()
        },
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(compile(fields), 6 + expected as u32);
    }
    let glob = compile(RoutingCondition {
        domain: vec!["*.example".into()],
        ..Default::default()
    });
    let mut regex = RoutingCondition {
        domain_regex: vec![r"^.*\.example$".into()],
        ..Default::default()
    };
    assert_eq!(glob, compile(regex.clone()));
    regex.domain_regex[0] = r"^.*[.]example$".into();
    assert_ne!(glob, compile(regex));
}

#[test]
fn capacity_counts_distinct_sets_and_allows_hits_at_the_limit() {
    let assets = assets_for(&[], &[]);
    let mut registry = DomainRegistry::default();
    let mut shared = SharedMatchers::default();
    let mut compile = |n| {
        id(
            &RoutingCondition {
                domain_suffix: vec![format!("host{n}")],
                ..Default::default()
            },
            &assets,
            &mut shared,
            &mut registry,
        )
    };
    for n in 0..ROUTING_FACT_CAPACITY {
        assert_eq!(compile(n).unwrap(), n as u32);
    }
    assert_eq!(compile(0).unwrap(), 0);
    let error = compile(ROUTING_FACT_CAPACITY).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("more than 256 domain predicates"),
        "{error}"
    );
    assert_eq!(compile(255).unwrap(), 255);
}

#[test]
fn repeated_empty_selectors_share_across_routers_and_each_use_warns() {
    if crate::test_support::run_exact_in_child(
        "HONK_DOMAIN_INTERN_WARN_CHILD",
        "routing::geo::scan_tests::interning::repeated_empty_selectors_share_across_routers_and_each_use_warns",
    ) {
        return;
    }
    let config = honk_config::parser::parse_dae_config("dns {\n routing { request {\n qname(geosite:b@absent) -> reject\n qname(geosite:b@absent) -> asis\n fallback: asis\n } } }\n routing {\n domain(geosite:b@absent) -> block\n domain(geosite:b@absent, keyword:extra) -> direct\n fallback: block\n }").unwrap();
    let sources = GeoSourceSet::from_bytes(overlapping("b.example"), vec![]);
    let output = tempfile::NamedTempFile::new().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .with_ansi(false)
        .with_writer(Arc::new(output.reopen().unwrap()))
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut shared = SharedMatchers::default();
        let router = Router::from_config_sharing(&config.routing, &sources, &mut shared).unwrap();
        let dns = DnsRouter::new_sharing(&config.dns, &sources, &mut shared).unwrap();
        let traffic = router.geosite_matchers();
        let queries = dns.geosite_matchers();
        assert_eq!((traffic.len(), queries.len()), (2, 2));
        assert!(
            traffic
                .iter()
                .chain(&queries)
                .all(|m| Arc::ptr_eq(traffic[0], m))
        );
        assert!(!traffic[0].matches("b.example"));
    });
    let logged = std::fs::read_to_string(output.path()).unwrap();
    assert_eq!(
        logged
            .lines()
            .filter(
                |s| s.contains("geosite code expanded to zero matchers; rule will never match")
                    && s.contains("b@absent")
            )
            .count(),
        4,
        "{logged}"
    );
}

#[test]
fn cached_and_mixed_digests_match_an_independent_owned_encoding() {
    use std::collections::BTreeSet;
    fn reference(entries: &[(u8, &str)]) -> [u8; 32] {
        let entries: BTreeSet<(u8, String)> = entries
            .iter()
            .map(|&(tag, text)| (tag, text.to_owned()))
            .collect();
        let mut bytes = b"honk.domain-matcher-key.v1\0".to_vec();
        bytes.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (tag, text) in entries {
            bytes.push(tag);
            bytes.extend_from_slice(&(text.len() as u64).to_le_bytes());
            bytes.extend_from_slice(text.as_bytes());
        }
        Sha256::digest(bytes).into()
    }
    let full = domain_msg(3, "Ä.example", &[("HOT", None)]);
    let suffix = domain_msg(2, "É.example", &[]);
    let keyword = domain_msg(0, "Key", &[]);
    let regex = domain_msg(1, "x.+", &[]);
    let dat = geosite_dat(&[
        ("A", vec![keyword.clone(), full.clone(), full.clone()]),
        ("B", vec![full, suffix, regex, keyword]),
    ]);
    let assets = assets_for(&dat, &["a", "b", "a@hot", "a@cold"]);
    let mut registry = DomainRegistry::default();
    let mut shared = SharedMatchers::default();
    let a = &[(3, "ä.example"), (5, "Key")][..];
    let both = &[(3, "ä.example"), (4, "é.example"), (5, "Key"), (6, "x.+")][..];
    for (codes, expected) in [
        (&["a"][..], a),
        (&["A", " a "], a),
        (&["a", "b"], both),
        (&["b", "a"], both),
        (&["a@hot"], &[(3, "ä.example")]),
        (&["a@cold"], &[][..]),
    ] {
        let index = id(&sites(codes), &assets, &mut shared, &mut registry).unwrap() as usize;
        assert_eq!(
            registry.keys[index].as_bytes(),
            &reference(expected),
            "{codes:?}"
        );
    }
    let mixed = RoutingCondition {
        domain: vec!["*.test".into()],
        domain_regex: vec![r"^.*\.test$".into(), "x.+".into()],
        domain_suffix: vec!["é.example".into()],
        domain_keyword: vec!["Key".into()],
        ..sites(&["a", "b", " A "])
    };
    let index = id(&mixed, &assets, &mut shared, &mut registry).unwrap() as usize;
    let mut expected = both.to_vec();
    expected.extend([(0, r"^.*\.test$"), (0, "x.+"), (1, "é.example"), (2, "Key")]);
    assert_eq!(registry.keys[index].as_bytes(), &reference(&expected));
    assert_eq!(registry.matchers[index].geosite.len(), 2);
}
