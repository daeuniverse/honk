Internal

- The DNS listener rebind test runs on a loopback address of its own, so a parallel test can no longer take its freed port and fail the rebind with AddrInUse.
