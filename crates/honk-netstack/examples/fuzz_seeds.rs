//! Writes the seed corpus for the `fuzz/` targets: `cargo run -p honk-netstack --features
//! fuzz-checks --example fuzz_seeds -- fuzz/corpus`. Files are named by content hash, so
//! regenerating is idempotent.

use std::path::Path;

fn main() {
    let root = std::env::args_os()
        .nth(1)
        .expect("usage: fuzz_seeds <corpus directory>");
    let root = Path::new(&root);
    let mut counts = std::collections::BTreeMap::<&str, usize>::new();
    for (target, bytes) in honk_netstack::fuzz_checks::seeds() {
        let dir = root.join(target);
        std::fs::create_dir_all(&dir).unwrap();
        let name = &blake3::hash(&bytes).to_hex()[..40];
        std::fs::write(dir.join(name), &bytes).unwrap();
        *counts.entry(target).or_default() += 1;
    }
    for (target, n) in counts {
        println!("{target}: {n} seeds");
    }
}
