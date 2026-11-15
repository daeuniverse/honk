Fixed

- WebSocket TLS nodes without an explicit `sni` offer the WebSocket `Host` name as SNI, so CDN-fronted nodes addressed by edge IP connect instead of failing certificate verification.
