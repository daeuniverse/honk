use super::*;
use serde_json::json;

fn render(template: &str, body: &str, event: &Value) -> io::Result<Vec<u8>> {
    let format = CompiledFormat::compile(template, body).unwrap();
    let mut output = Buffer::new(MAX_MESSAGE_BYTES);
    format.write(event, &json!("build1"), &json!("revision1"), &mut output)?;
    validate_header(&output.bytes)?;
    Ok(output.bytes)
}

fn body(bytes: &[u8]) -> Value {
    serde_json::from_slice(&bytes[header::parse(bytes).unwrap().body..]).unwrap()
}

#[test]
fn default_message_preserves_the_complete_original_json() {
    let event = sample_event();
    let bytes = render(DEFAULT_TEMPLATE, "", &event).unwrap();
    let expected = format!(
        "<134>1 2026-01-01T00:00:00.000001Z router honk - dns.query - {}",
        serde_json::to_string(&event).unwrap()
    );
    assert_eq!(bytes, expected.as_bytes());
    assert_eq!(body(&bytes), event);
}

#[test]
fn processing_metadata_tags_preserve_number_string_and_null() {
    let mut event = sample_event();
    event["duration_ms"] = json!(429.064);
    for upstream in [json!("final"), json!("cache"), Value::Null] {
        event["upstream"] = upstream.clone();
        let bytes = render(
            DEFAULT_TEMPLATE,
            r#"{"duration_ms":"${duration_ms}","upstream":"${upstream}"}"#,
            &event,
        )
        .unwrap();
        assert_eq!(
            body(&bytes),
            json!({"duration_ms":429.064,"upstream":upstream})
        );
    }
    let bytes = render(
        "<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - duration=${duration_ms} upstream=${upstream}",
        "",
        &event,
    ).unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .ends_with("duration=429.064 upstream=null")
    );
}

#[test]
fn whole_tags_preserve_types_and_nested_values_without_reparsing() {
    let mut event = sample_event();
    event["answers"] = json!([{"type":"A","data":"203.0.113.1"}]);
    event["answer_ips"] = json!(["203.0.113.1"]);
    event["rcode"] = Value::Null;
    let bytes = render(
        DEFAULT_TEMPLATE,
        r#"{
        "client":{"ip":"${client_ip}","port":"${client_port}"},
        "data":["${answers}","${answer_ips}","${response_truncated}","${rcode}"],
        "fixed":123,"enabled":true,"nothing":null,
        "text":"port=${client_port} rcode=${rcode}",
        "force_text":"${client_port|text}",
        "quoted":"${domain|json}",
        "meta":["${version}","${template_version}"],
        "dollar":"$${domain} $$"
    }"#,
        &event,
    )
    .unwrap();
    assert_eq!(
        body(&bytes),
        json!({
            "client":{"ip":"192.0.2.1","port":53000},
            "data":[event["answers"],event["answer_ips"],false,null],
            "fixed":123,"enabled":true,"nothing":null,
            "text":"port=53000 rcode=null","force_text":"53000",
            "quoted":"\"example.com.\"","meta":["build1","revision1"],
            "dollar":"${domain} $"
        })
    );
}

#[test]
fn interpolation_and_cef_filters_escape_their_own_context() {
    let mut event = sample_event();
    event["domain"] = json!("a|b=c\\d\n\r\"雪");
    let bytes = render(DEFAULT_TEMPLATE, r#"{"message":"query=${domain}"}"#, &event).unwrap();
    assert_eq!(
        body(&bytes)["message"],
        format!("query={}", event["domain"].as_str().unwrap())
    );
    let template = "<134>1 ${completed_at} ${hostname} ${app_name} - dns.query - CEF:0|vendor|honk|${version|cef_header}|dns.query|${domain|cef_header}|1|src=${client_ip|cef_ext} dhost=${domain|cef_ext}";
    let bytes = render(template, "", &event).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.ends_with("CEF:0|vendor|honk|build1|dns.query|a\\|b=c\\\\d\\n\\r\"雪|1|src=192.0.2.1 dhost=a|b\\=c\\\\d\\n\\r\"雪"));
}

#[test]
fn structured_data_requires_escaping_and_cannot_inject_new_fields() {
    let template = "<134>1 ${completed_at} ${hostname} ${app_name} - dns.query [meta domain=\"${domain|sd}\"] ${json}";
    let mut event = sample_event();
    event["domain"] = json!("a\"]\\雪");
    let bytes = render(template, "", &event).unwrap();
    assert!(
        std::str::from_utf8(&bytes)
            .unwrap()
            .contains("[meta domain=\"a\\\"\\]\\\\雪\"] ")
    );
    assert_eq!(body(&bytes), event);
    assert!(CompiledFormat::compile(&template.replace("|sd", ""), "").is_err());
    event["domain"] = json!("bad\nvalue");
    assert!(render(template, "", &event).is_err());
}

#[test]
fn dynamic_header_values_cannot_shift_other_valid_header_fields() {
    let mut event = sample_event();
    event["hostname"] = json!("host app - dns.query - payload");
    assert!(render(DEFAULT_TEMPLATE, "", &event).is_err());
    event["hostname"] = json!("h".repeat(256));
    assert!(render(DEFAULT_TEMPLATE, "", &event).is_err());
    event["hostname"] = json!("host");
    event["completed_at"] = json!("2026-01-01T00:00:00.1234567Z");
    assert!(render(DEFAULT_TEMPLATE, "", &event).is_err());
}

#[test]
fn invalid_templates_and_duplicate_keys_are_rejected() {
    for template in [
        "",
        "<192>1 - host app - id - x",
        "<134>2 - host app - id - x",
        "<00>1 - host app - id - x",
        "<013>1 - host app - id - x",
        "<134>1 - host app - id [same][same] x",
        "<134>1 - host app - id [same x=\"a\" x=\"b\"] x",
        "<134>1 ${completed_at} ${hostname} ${template_version} - dns.query - ${json}",
        "<134>1 bad host app - id - x",
        "<134>1 - host app - id [bad x=\"a]b\"] x",
        "<134>1 - host app - id - ${unknown}",
        "<134>1 - host app - id - ${domain|unknown}",
        "<134>1 - host app - id - ${domain",
        "<134>1 - ${json} app - id - x",
    ] {
        assert!(CompiledFormat::compile(template, "").is_err(), "{template}");
    }
    for json in [
        "[]",
        "null",
        "{",
        r#"{"x":"${json}"}"#,
        r#"{"x":"${missing}"}"#,
        r#"{"x":1,"x":2}"#,
        r#"{"x":{"y":1,"y":2}}"#,
    ] {
        assert!(
            CompiledFormat::compile(DEFAULT_TEMPLATE, json).is_err(),
            "{json}"
        );
    }
}

#[test]
fn template_sources_depth_and_complexity_are_bounded() {
    assert!(CompiledFormat::compile(&"x".repeat(MAX_SOURCE_BYTES + 1), "").is_err());
    let nested = format!("{{\"x\":{}0{}}}", "[".repeat(17), "]".repeat(17));
    assert!(CompiledFormat::compile(DEFAULT_TEMPLATE, &nested).is_err());
    let many = format!("{{\"x\":[{}]}}", vec!["0"; MAX_NODES + 1].join(","));
    assert!(CompiledFormat::compile(DEFAULT_TEMPLATE, &many).is_err());
    let tags = format!(
        "<134>1 - host app - id - {}",
        "${domain}".repeat(MAX_TAGS + 1)
    );
    assert!(CompiledFormat::compile(&tags, "").is_err());
    let groups = (0..1800).map(|i| format!("[id{i}]")).collect::<String>();
    assert!(CompiledFormat::compile(&format!("<134>1 - host app - id {groups} x"), "").is_err());
}

#[test]
fn repeated_large_values_stop_at_the_output_cap() {
    let mut event = sample_event();
    event["answers"] = json!(["x".repeat(MAX_MESSAGE_BYTES / 2)]);
    assert!(
        render(
            DEFAULT_TEMPLATE,
            r#"{"a":"${answers}","b":"${answers}"}"#,
            &event
        )
        .is_err()
    );
    assert!(
        render(
            DEFAULT_TEMPLATE,
            r#"{"message":"prefix ${answers} ${answers}"}"#,
            &event
        )
        .is_err()
    );
}
