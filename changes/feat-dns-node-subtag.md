Added

- DNS request rules accept `subtag(...)`, which resolves the server hosts of nodes from matching subscriptions through a chosen `-> direct` upstream (for example a provider's own DoH) instead of the bootstrap resolver. Each DNS generation precomputes host policy outcomes; native flow traces explicitly mark consumption of these decisions as incomplete evidence (`not_instrumented`).
