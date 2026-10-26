//! Replays the committed seed corpus and any saved crash artifacts through the fuzz properties on
//! stable Rust, so a regression fails ordinary CI without a nightly fuzzer.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use honk_netstack::fuzz_checks;

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

type Check = (&'static str, fn(&[u8]));

#[test]
fn saved_inputs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let checks: [Check; 3] = [
        ("netstack_packet", fuzz_checks::packet),
        ("netstack_schedule", fuzz_checks::schedule),
        ("netstack_transparent", fuzz_checks::transparent),
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
            let failure = match receive.recv_timeout(Duration::from_secs(20)) {
                Ok(true) => None,
                Ok(false) => Some("panic"),
                Err(mpsc::RecvTimeoutError::Timeout) => Some("twenty-second timeout"),
                Err(mpsc::RecvTimeoutError::Disconnected) => Some("worker disconnected"),
            };
            if let Some(failure) = failure {
                panic!("{}: {failure}", path.display());
            }
            worker.join().unwrap();
            count += 1;
        }
    }
    println!("fuzz replay: {count} inputs passed");
}
