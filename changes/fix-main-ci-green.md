Security

- AES-GCM no longer uses a `ctutils` release whose mask generation and `u128` comparisons are not constant-time (RUSTSEC-2026-0385); `ctutils` is now 0.4.7.
