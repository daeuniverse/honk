#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    honk_config::fuzz_checks::share_link(data);
});
