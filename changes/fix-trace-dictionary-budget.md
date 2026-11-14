Fixed

- Kernel route trace keeps decoding rule hits on large policies: the
  per-policy and retained rule-text dictionary budgets grow from 64 KiB /
  1 MiB to 128 KiB / 2 MiB; an oversized dictionary previously turned kernel
  route tracing off, with a warning at startup and reload.
