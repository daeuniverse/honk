//! Stack role: a WireGuard-style endpoint owning fixed addresses, or a transparent terminator.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whom the stack answers for.
///
/// [`Mode::Endpoint`] (the default of `Config::new`) accepts packets for `Config::local_v4`/
/// `local_v6` only and has no passive open. [`Mode::Transparent`] accepts any unicast
/// destination that is not excluded: a flow's local end is the packet's original destination,
/// so replies are sourced from it.
#[derive(Clone, Debug, Default)]
pub enum Mode {
    #[default]
    Endpoint,
    Transparent {
        exclude: ExcludeSet,
    },
}

/// Destinations a transparent stack refuses. Only a backstop: the classifier in front of the
/// driver is what keeps such traffic out, and a packet dropped here is a black hole.
#[derive(Clone, Debug, Default)]
pub struct ExcludeSet {
    v4: Vec<(Ipv4Addr, u8)>,
    v6: Vec<(Ipv6Addr, u8)>,
}

impl ExcludeSet {
    pub(crate) fn overhead_bound(&self) -> Option<usize> {
        self.v4
            .capacity()
            .checked_mul(std::mem::size_of::<(Ipv4Addr, u8)>())?
            .checked_add(
                self.v6
                    .capacity()
                    .checked_mul(std::mem::size_of::<(Ipv6Addr, u8)>())?,
            )
    }

    /// Adds a prefix; `len` is clamped to the address width.
    pub fn insert(&mut self, addr: IpAddr, len: u8) -> &mut Self {
        match addr {
            IpAddr::V4(a) => self.v4.push((a, len.min(32))),
            IpAddr::V6(a) => self.v6.push((a, len.min(128))),
        }
        self
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                self.v4
                    .iter()
                    .any(|&(p, len)| prefix_eq(u128::from(a), u128::from(u32::from(p)), len, 32))
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                self.v6
                    .iter()
                    .any(|&(p, len)| prefix_eq(a, u128::from(p), len, 128))
            }
        }
    }
}

fn prefix_eq(a: u128, b: u128, len: u8, width: u32) -> bool {
    let len = u32::from(len);
    len == 0 || (a ^ b) >> (width - len) == 0
}

/// Addresses no flow can have as an endpoint: unspecified, multicast and limited broadcast.
/// This is where tun-generated RS/MLD/DAD noise ends up.
pub(crate) fn is_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => !(a.is_unspecified() || a.is_multicast() || a.is_broadcast()),
        IpAddr::V6(a) => !(a.is_unspecified() || a.is_multicast()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_match_on_bit_boundaries() {
        let mut set = ExcludeSet::default();
        set.insert("10.1.0.0".parse().unwrap(), 16)
            .insert("2001:db8::".parse().unwrap(), 32)
            .insert("192.0.2.7".parse().unwrap(), 32)
            .insert("0.0.0.0".parse().unwrap(), 0);
        assert!(set.contains("10.1.255.1".parse().unwrap()));
        assert!(set.contains("2001:db8:ffff::1".parse().unwrap()));
        assert!(set.contains("192.0.2.7".parse().unwrap()));
        // /0 matches every IPv4 address but never an IPv6 one.
        assert!(set.contains("8.8.8.8".parse().unwrap()));
        assert!(!set.contains("2001:db9::1".parse().unwrap()));
        let mut set = ExcludeSet::default();
        set.insert("10.1.0.0".parse().unwrap(), 16);
        assert!(!set.contains("10.2.0.1".parse().unwrap()));
        assert!(!set.contains("8.8.8.8".parse().unwrap()));
        assert!(!ExcludeSet::default().contains("10.1.0.1".parse().unwrap()));
    }

    #[test]
    fn only_unicast_is_terminable() {
        for addr in ["0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::2"] {
            assert!(!is_unicast(addr.parse().unwrap()), "{addr}");
        }
        for addr in ["10.0.0.1", "169.254.1.1", "fe80::1", "2001:db8::1"] {
            assert!(is_unicast(addr.parse().unwrap()), "{addr}");
        }
    }
}
