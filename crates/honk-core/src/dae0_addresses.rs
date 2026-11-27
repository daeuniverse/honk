//! Addresses shared by real link setup and the internal-traffic exclusion contract.

pub(crate) const DAENS_HOST_IP: &str = "169.254.0.1";
pub(crate) const DAENS_PEER_IP: &str = "169.254.0.11";
/// IPv6 ULA addresses of the dae0/dae0peer link pair (fd00:686f:6e6b::/64).
/// The middle hextets are ASCII "honk" (`68 6f 6e 6b`) so the mnemonic
/// stays readable while remaining a valid IPv6 ULA prefix.
pub(crate) const DAENS_HOST_IPV6: &str = "fd00:686f:6e6b::1";
pub(crate) const DAENS_PEER_IPV6: &str = "fd00:686f:6e6b::2";
