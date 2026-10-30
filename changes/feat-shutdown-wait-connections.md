Changed

- Add reloadable `global.shutdown_wait_connections` (default `false`). Set `true` to retain the previous five-second connection grace; mandatory cleanup and native HTTP shutdown are unchanged.
