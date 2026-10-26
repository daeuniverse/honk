#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| honk_netstack::fuzz_checks::schedule(data));
