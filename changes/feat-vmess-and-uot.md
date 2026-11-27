Added

- VMess nodes can opt into UDP-over-TCP v2 with a compatible peer. Single nodes and configured chains can share one association across destinations. Existing TCP-only nodes keep their IDs.
- WebSocket upgrades now bracket IPv6 literals in the URI and Host header and accept relative paths. TLS uses the unbracketed IPv6 address from the WebSocket Host or endpoint for certificate verification.
