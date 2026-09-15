use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use honk_config::conformance::project;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    note: String,
    upstream: Upstream,
    case: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upstream {
    commit: String,
    sources: Vec<UpstreamSource>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpstreamSource {
    file: PathBuf,
    url: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    input: Option<PathBuf>,
    source: Option<Source>,
    #[serde(default)]
    wrap: String,
    dae: String,
    honk: String,
    honk_diagnostics: Vec<String>,
    compare: Option<String>,
    #[serde(default)]
    differences: Vec<Difference>,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    unknown_sections: usize,
    layer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    file: Option<PathBuf>,
    dae: Option<PathBuf>,
    lines: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Difference {
    path: String,
    dae: Value,
    honk: Value,
    reason: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn input(case: &Case, upstream: &Upstream) -> Option<String> {
    assert_ne!(
        case.input.is_some(),
        case.source.is_some(),
        "{}: one input source required",
        case.id
    );
    let mut text = if let Some(path) = &case.input {
        std::fs::read_to_string(root().join(path))
            .unwrap_or_else(|e| panic!("{}: cannot read input {}: {e}", case.id, path.display()))
    } else {
        let source = case.source.as_ref().unwrap();
        assert_ne!(source.file.is_some(), source.dae.is_some());
        let path = if let Some(file) = &source.dae {
            assert!(
                upstream.sources.iter().any(|s| &s.file == file),
                "{}: uncited source",
                case.id
            );
            match std::env::var_os("CONFORMANCE_SRC") {
                Some(dir) => PathBuf::from(dir).join(file),
                None => {
                    assert!(
                        std::env::var_os("DAE_PARSE_BIN").is_none(),
                        "CONFORMANCE_SRC required with oracle"
                    );
                    return None;
                }
            }
        } else {
            root().join(source.file.as_ref().unwrap())
        };
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {}: {e}", case.id, path.display()));
        let (start, end) = source
            .lines
            .split_once('-')
            .unwrap_or((&source.lines, &source.lines));
        let start: usize = start
            .parse()
            .unwrap_or_else(|_| panic!("{}: bad line range {}", case.id, source.lines));
        let end: usize = end
            .parse()
            .unwrap_or_else(|_| panic!("{}: bad line range {}", case.id, source.lines));
        let lines: Vec<_> = text.lines().collect();
        assert!(
            start > 0 && end >= start && end <= lines.len(),
            "{}: line range {} is outside {} lines",
            case.id,
            source.lines,
            lines.len()
        );
        if source.file.is_some() {
            assert!(start >= 2 && end < lines.len());
            assert_eq!(
                lines[start - 2].trim(),
                "```dae",
                "{}: stale fence start",
                case.id
            );
            assert_eq!(lines[end].trim(), "```", "{}: stale fence end", case.id);
        }
        format!("{}\n", lines[start - 1..end].join("\n"))
    };
    for section in case.wrap.split('.').rev().filter(|s| !s.is_empty()) {
        text = format!("{section} {{\n{text}\n}}\n");
    }
    Some(text)
}

fn oracle(binary: &Path, case_id: &str, input: &str) -> Value {
    let mut child = Command::new(binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("{case_id}: cannot start the dae oracle: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap_or_else(|e| panic!("{case_id}: cannot feed the dae oracle: {e}"));
    let output = child
        .wait_with_output()
        .unwrap_or_else(|e| panic!("{case_id}: dae oracle did not exit: {e}"));
    assert!(
        output.status.success(),
        "{case_id}: oracle process: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{case_id}: oracle JSON: {e}"))
}

fn diff(
    path: &str,
    dae: Option<&Value>,
    honk: Option<&Value>,
    out: &mut Vec<(String, Value, Value)>,
) {
    match (dae, honk) {
        (Some(Value::Object(d)), Some(Value::Object(h))) => {
            let keys: std::collections::BTreeSet<_> = d.keys().chain(h.keys()).collect();
            for key in keys {
                let next = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                diff(&next, d.get(key), h.get(key), out);
            }
        }
        (Some(Value::Array(d)), Some(Value::Array(h))) => {
            for i in 0..d.len().max(h.len()) {
                diff(&format!("{path}[{i}]"), d.get(i), h.get(i), out);
            }
        }
        _ if dae == honk => {}
        _ => out.push((
            path.to_owned(),
            dae.cloned().unwrap_or(json!({"absent": true})),
            honk.cloned().unwrap_or(json!({"absent": true})),
        )),
    }
}

fn compare(case: &Case, dae: &Value, honk: &Value) -> Result<(), String> {
    let mut actual = Vec::new();
    diff("", Some(dae), Some(honk), &mut actual);
    for (path, d, h) in &actual {
        if !case
            .differences
            .iter()
            .any(|e| e.path == *path && e.dae == *d && e.honk == *h)
        {
            return Err(format!("{path}: dae={d}, honk={h}"));
        }
    }
    for expected in &case.differences {
        if !actual
            .iter()
            .any(|(path, d, h)| *path == expected.path && *d == expected.dae && *h == expected.honk)
        {
            return Err(format!(
                "{}: stale or incorrect bounded difference",
                expected.path
            ));
        }
    }
    Ok(())
}

#[test]
fn manifest_cases() {
    let manifest_path = std::env::var_os("CONFORMANCE_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("conformance/manifest.toml"));
    let manifest: Manifest =
        toml::from_str(&std::fs::read_to_string(manifest_path).unwrap()).unwrap();
    assert!(!manifest.note.is_empty());
    for source in &manifest.upstream.sources {
        assert_eq!(source.sha256.len(), 64);
        assert_eq!(
            source.url,
            format!(
                "https://raw.githubusercontent.com/daeuniverse/dae/{}/{}",
                manifest.upstream.commit,
                source.file.display()
            )
        );
    }
    let binary = std::env::var_os("DAE_PARSE_BIN").map(PathBuf::from);
    if let Some(binary) = &binary {
        let version = Command::new(binary).arg("-version").output().unwrap();
        assert!(version.status.success());
        assert!(
            String::from_utf8_lossy(&version.stdout).contains(&manifest.upstream.commit),
            "wrong dae revision"
        );
    } else {
        eprintln!(
            "oracle absent: checking honk acceptance and diagnostics only; unfetched dae sources skipped"
        );
    }
    let list = Command::new(env!("CARGO"))
        .args([
            "test",
            "-p",
            "honk-config",
            "--lib",
            "--tests",
            "--",
            "--list",
        ])
        .current_dir(root())
        .output()
        .expect("list typed/loading tests");
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let listed = String::from_utf8(list.stdout).unwrap();
    let names: HashSet<_> = listed
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .map(|name| name.rsplit("::").next().unwrap())
        .collect();
    let filter = std::env::var("CONFORMANCE_CASE").unwrap_or_default();
    let mut ids = HashSet::new();
    let mut total = 0;
    let mut equal = 0;
    let mut bounded = 0;
    let mut rejected = 0;
    let mut skipped = 0;
    let mut failures = Vec::new();
    for case in manifest.case {
        assert!(ids.insert(case.id.clone()), "duplicate case {}", case.id);
        if !case.id.contains(&filter) {
            continue;
        }
        assert!(["accept", "reject"].contains(&case.dae.as_str()));
        assert!(["accept", "reject"].contains(&case.honk.as_str()));
        assert!(
            (case.compare.as_deref() == Some("equal") && case.differences.is_empty())
                || (case.compare.is_none() && !case.differences.is_empty())
        );
        let mut paths = HashSet::new();
        for entry in &case.differences {
            assert!(
                !entry.reason.is_empty() && !entry.path.is_empty() && paths.insert(&entry.path)
            );
        }
        if case.dae != case.honk {
            assert!(
                !case.reason.is_empty(),
                "{}: acceptance needs a reason",
                case.id
            );
        }
        if case.layer != "structure" {
            let (layer, test) = case.layer.split_once(':').expect("layer:test");
            assert!(["typed", "loading"].contains(&layer));
            assert!(names.contains(test), "{}: missing test {test}", case.id);
        }
        let Some(input) = input(&case, &manifest.upstream) else {
            skipped += 1;
            continue;
        };
        total += 1;
        let projection = project(&input);
        let codes: Vec<_> = projection.diagnostics.iter().map(|d| d.code).collect();
        let mut error = None;
        if projection.accepted != (case.honk == "accept") {
            error = Some(format!(
                "accepted: honk={}, expected {}",
                projection.accepted, case.honk
            ));
        } else if codes != case.honk_diagnostics {
            error = Some(format!(
                "diagnostics: honk={codes:?}, expected {:?}",
                case.honk_diagnostics
            ));
        } else if projection.unknown_positions.len() != case.unknown_sections {
            error = Some("unknown_sections: incorrect root count".to_owned());
        }
        if let Some(binary) = &binary {
            let dae = oracle(binary, &case.id, &input);
            let accepted = dae.get("error").is_none();
            if accepted != (case.dae == "accept") {
                error = Some(format!(
                    "accepted: dae={accepted}, expected {}; {}",
                    case.dae,
                    dae.get("error").unwrap_or(&Value::Null)
                ));
            } else if accepted && projection.document.is_some() {
                // Structure goes first so the lexer control reports the lost param.val,
                // not the later node-decoding diagnostic caused by those same spans.
                if let Err(difference) = compare(
                    &case,
                    &dae,
                    projection.document.as_ref().expect("accepted document"),
                ) {
                    error = Some(difference);
                } else if !projection.accepted {
                    rejected += 1;
                } else if case.differences.is_empty() {
                    equal += 1;
                } else {
                    bounded += 1;
                }
            } else {
                rejected += 1;
            }
        }
        if let Some(error) = error {
            failures.push((case.id, error));
        }
    }
    assert!(total > 0, "case filter matched nothing");
    let result = json!({"total": total, "equal": equal, "bounded": bounded, "rejected_as_expected": rejected, "skipped": skipped, "oracle": binary.is_some(), "failure": failures.first().map(|(id, detail)| json!({"case": id, "path": detail.split(':').next().unwrap(), "detail": detail}))});
    if let Some(path) = std::env::var_os("CONFORMANCE_RESULT") {
        std::fs::write(path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    }
    println!("conformance: {result}; {} failures", failures.len());
    assert!(
        failures.is_empty(),
        "{}",
        failures
            .iter()
            .map(|(id, detail)| format!("{id}: {detail}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
