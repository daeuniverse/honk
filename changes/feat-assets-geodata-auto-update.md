Changed

- Automatic geodata updates run daily at 03:00 local time, plus the existing random delay of up to an hour, instead of every 24 hours. A schedule stored with `interval_hours` keeps its interval.
- `assets.geodata` takes `auto_update`, `cron` and `checksum`, written into the stored geodata settings at startup like the download URLs and route.
- The native API's geodata `auto_update` accepts a `cron` expression in place of `interval_hours` and reports it in `cron`.
- `docker-compose.yml` mounts the host's `/etc/localtime` read-only, so the container uses the host's time zone for log timestamps and the geodata schedule instead of UTC.
