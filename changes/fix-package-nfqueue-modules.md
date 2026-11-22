Fixed

- Held-first-packet UDP is no longer disabled at startup when the `nfnetlink_queue` module is built but not loaded, as on Debian 13: honk binds the queue and the kernel loads the module. When the module cannot be loaded, the startup warning says so.
