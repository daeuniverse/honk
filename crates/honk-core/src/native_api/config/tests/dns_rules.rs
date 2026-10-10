use super::*;

const MAIN_DNS: &str = "dns {
 upstream {
  alidns: 'udp://223.5.5.5:53'
  googledns: 'tcp+udp://8.8.8.8:53'
 }
 routing {
  request {
   qname(suffix: example.com) -> AliDNS # domestic
   qname(omitted.example) ->
   qtype(aaaa) -> reject
  }
 }
}
";

const LOCKED_DNS: &str = "dns {
 routing {
  request {
   qname(keyword: internal) -> asis
   fallback: googledns
  }
  response {
   upstream(googledns) && ip(10.0.0.0/8) -> alidns
  }
 }
}
";

/// The source row whose id the rule names, and the text at its line and column.
fn at<'c>(config: &'c Value, rule: &Value) -> (&'c Value, &'c str) {
    let source = &rule["source"];
    let row = config["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == source["source_id"])
        .unwrap();
    let line = row["content"]
        .as_str()
        .unwrap()
        .lines()
        .nth(source["line"].as_u64().unwrap() as usize - 1)
        .unwrap();
    (
        row,
        &line[source["column"].as_u64().unwrap() as usize - 1..],
    )
}

#[tokio::test]
async fn dns_rules_list_both_lists_across_sources_with_spliceable_locations() {
    let fixture = Fixture::new_custom(Access::Metadata, false, |_, files| {
        files.get_mut("main.dae").unwrap().push_str(MAIN_DNS);
        files.insert("locked.dae", LOCKED_DNS.into());
    })
    .await;
    let capabilities = fixture.get("/api/v1/capabilities").await;
    assert_eq!(
        capabilities["resources"]["dns_rules"],
        json!({"available":true,"max_rules":4096})
    );
    let config = fixture.get(CONFIG).await;
    let rules = fixture.get("/api/v1/dns/rules").await;
    let generation = rules["generation_id"].as_str().unwrap();
    assert_eq!(
        rules["request"]
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| (
                rule["rule_id"].as_str().unwrap().strip_prefix(generation),
                rule["index"].as_u64().unwrap(),
                rule["expression"].as_str().unwrap(),
                rule["action"].as_str().unwrap(),
                rule["upstream"].as_str(),
                rule["kind"].as_str().unwrap(),
            ))
            .collect::<Vec<_>>(),
        [
            (
                Some(":dns_request:rule:0"),
                0,
                "qname(suffix: example.com) -> AliDNS",
                "upstream",
                Some("alidns"),
                "rule"
            ),
            (
                Some(":dns_request:rule:1"),
                1,
                "qtype(aaaa) -> reject",
                "reject",
                None,
                "rule"
            ),
            (
                Some(":dns_request:rule:2"),
                2,
                "qname(keyword: internal) -> asis",
                "asis",
                None,
                "rule"
            ),
            (
                Some(":dns_request:fallback"),
                3,
                "fallback: googledns",
                "upstream",
                Some("googledns"),
                "fallback"
            ),
        ]
    );
    for (rule, file, line, column) in [
        (&rules["request"][0], "main.dae", 23, 4),
        (&rules["request"][1], "main.dae", 25, 4),
        (&rules["request"][2], "locked.dae", 4, 4),
        (&rules["request"][3], "locked.dae", 5, 4),
        (&rules["response"][0], "locked.dae", 8, 4),
    ] {
        assert_eq!(rule["source"]["file"], file, "{rule}");
        assert_eq!(rule["source"]["line"], line, "{rule}");
        assert_eq!(rule["source"]["column"], column, "{rule}");
        let (row, text) = at(&config, rule);
        assert_eq!(row["path"], file);
        assert!(
            text.starts_with(rule["expression"].as_str().unwrap()),
            "{text:?} does not start with {rule}"
        );
    }
    assert_eq!(
        rules["response"],
        json!([
            {
                "rule_id": format!("{generation}:dns_response:rule:0"),
                "index": 0,
                "expression": "upstream(googledns) && ip(10.0.0.0/8) -> alidns",
                "action": "requery",
                "upstream": "alidns",
                "source": rules["response"][0]["source"],
                "kind": "rule",
            },
            {
                "rule_id": format!("{generation}:dns_response:fallback"),
                "index": 1,
                "expression": "fallback: accept",
                "action": "accept",
                "upstream": null,
                "source": null,
                "kind": "fallback",
            },
        ])
    );
    let encoded = rules.to_string();
    for withheld in [
        SECRET,
        "domestic",
        "omitted",
        fixture.directory.path().to_str().unwrap(),
    ] {
        assert!(!encoded.contains(withheld), "{withheld}");
    }
    fixture.shutdown().await;
}

#[tokio::test]
async fn dns_rules_without_dns_routing_list_only_default_fallbacks() {
    let fixture = Fixture::new(Access::Metadata, false).await;
    let rules = fixture.get("/api/v1/dns/rules").await;
    let generation = rules["generation_id"].as_str().unwrap();
    assert_eq!(
        rules,
        json!({
            "generation_id": generation,
            "request": [{
                "rule_id": format!("{generation}:dns_request:fallback"),
                "index": 0,
                "expression": "fallback: default",
                "action": "upstream",
                "upstream": "default",
                "source": null,
                "kind": "fallback",
            }],
            "response": [{
                "rule_id": format!("{generation}:dns_response:fallback"),
                "index": 0,
                "expression": "fallback: accept",
                "action": "accept",
                "upstream": null,
                "source": null,
                "kind": "fallback",
            }],
        })
    );
    fixture.shutdown().await;
}
