Changed

- The userspace stack computes common TCP/IP header checksums from their fields and uses a smaller scatter list for single-chunk sends.
- XDP skips TX-only wakeup work on a fully completed batch and reuses validated flow, peer and reply-header information on packet output.
