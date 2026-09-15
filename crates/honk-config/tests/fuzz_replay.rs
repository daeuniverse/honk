use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use honk_config::fuzz_checks;
use serde_json::json;

fn collect(directory: &Path, inputs: &mut Vec<PathBuf>) {
    if !directory.exists() {
        return;
    }
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            collect(&entry.path(), inputs);
        } else if kind.is_file() {
            inputs.push(entry.path());
        }
    }
}

#[test]
fn saved_inputs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let checks: [(&str, fn(&[u8])); 3] = [
        ("document", fuzz_checks::document),
        ("share_link", fuzz_checks::share_link),
        ("lexer", fuzz_checks::lexer),
    ];
    let mut count = 0;
    for (target, check) in checks {
        let mut inputs = Vec::new();
        collect(&root.join("corpus").join(target), &mut inputs);
        assert!(!inputs.is_empty(), "{target}: seed corpus is empty");
        collect(&root.join("artifacts").join(target), &mut inputs);
        inputs.sort();
        for path in inputs {
            eprintln!("fuzz replay: {}", path.display());
            let data = std::fs::read(&path).unwrap();
            let (send, receive) = mpsc::sync_channel(1);
            let worker = std::thread::spawn(move || {
                let result = std::panic::catch_unwind(|| check(&data));
                let _ = send.send(result.is_ok());
            });
            let failure = match receive.recv_timeout(Duration::from_secs(5)) {
                Ok(true) => None,
                Ok(false) => Some("panic"),
                Err(mpsc::RecvTimeoutError::Timeout) => Some("five-second timeout"),
                Err(mpsc::RecvTimeoutError::Disconnected) => Some("worker disconnected"),
            };
            count += 1;
            if let Some(output) = std::env::var_os("FUZZ_REPLAY_RESULT") {
                let result = json!({"inputs": count, "failure": failure.map(|detail| json!({"path": path, "detail": detail}))});
                std::fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
            }
            if let Some(failure) = failure {
                panic!("{}: {failure}", path.display());
            }
            worker.join().unwrap();
        }
    }
    println!("fuzz replay: {count} inputs passed");
}
