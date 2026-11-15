Fixed

- Routing traces from the native API (`POST /api/v1/routing/trace`) no longer fail with `413 request_too_large` on larger policies; the step limit now covers the whole loaded policy.
