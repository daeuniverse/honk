//! Offload metadata at the driver boundary: where a packet's L4 checksum came from, super-packets
//! on receive, and TSO/USO packets on transmit.
//!
//! Only a [`Mode::Transparent`](crate::Mode) stack accepts any of it (a TUN driver reading from the
//! kernel); an endpoint stack, i.e. the WireGuard driver, only ever sees verified, single packets.

use crate::DropReason;
use crate::wire::{PROTO_TCP, PROTO_UDP};

/// Where the L4 checksum of a received packet stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Csum {
    /// Flags 0: nothing is vouched for, the stack verifies the checksum (the only choice for
    /// [`Stack::receive`](crate::Stack::receive) and for an endpoint stack).
    Verify,
    /// `DATA_VALID`: the device already verified the checksum; the field is not checked.
    Valid,
    /// `NEEDS_CSUM` (`CHECKSUM_PARTIAL`): the field holds only the pseudo-header sum, common for
    /// locally generated packets and GRO super-packets, so there is no complete checksum to
    /// verify. `start` is the L4 header offset and `offset` the checksum field within it; both must
    /// match the packet, or it is dropped as malformed.
    Partial { start: u16, offset: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GsoKind {
    Tcp,
    UdpL4,
}

/// A received super-packet: the payload is a run of `size`-byte segments (the last one may be
/// shorter) behind one header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GsoRx {
    pub kind: GsoKind,
    pub size: u16,
}

/// What the driver knows about a received packet beyond its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxMeta {
    pub csum: Csum,
    pub gso: Option<GsoRx>,
}

impl RxMeta {
    /// An ordinary packet: verify everything, no super-packet.
    pub const VERIFY: RxMeta = RxMeta {
        csum: Csum::Verify,
        gso: None,
    };
}

impl Default for RxMeta {
    fn default() -> RxMeta {
        RxMeta::VERIFY
    }
}

/// UDP segments one received super-packet may split into (the kernel's `UDP_MAX_SEGMENTS`).
pub const MAX_USO_RX: usize = 128;
/// UDP segments one transmitted super-packet may carry (portable limit; Linux 6.12 allows 128).
pub const MAX_USO_TX: usize = 64;

impl RxMeta {
    /// The stack-side validation shared by TCP and UDP: whether the L4 checksum must be verified,
    /// and the super-packet size (`0`: none) if it applies to this protocol.
    pub(crate) fn l4(
        &self,
        proto: u8,
        l4_start: usize,
        field: u16,
    ) -> Result<(bool, u16), DropReason> {
        let size = match self.gso {
            None => 0,
            Some(g) => {
                let want = match g.kind {
                    GsoKind::Tcp => PROTO_TCP,
                    GsoKind::UdpL4 => PROTO_UDP,
                };
                if g.size == 0 || want != proto {
                    return Err(DropReason::Malformed);
                }
                g.size
            }
        };
        let verify = match self.csum {
            Csum::Verify => true,
            Csum::Valid => false,
            Csum::Partial { start, offset } => {
                if usize::from(start) != l4_start || offset != field {
                    return Err(DropReason::Malformed);
                }
                false
            }
        };
        Ok((verify, size))
    }
}

/// What a driver can take on transmit (`TUN_F_*`). `TUN_F_TSO_ECN` is not supported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxCaps {
    pub tso4: bool,
    pub tso6: bool,
    pub uso4: bool,
    pub uso6: bool,
}

impl TxCaps {
    /// Plain packets only: [`Stack::poll_transmit_with`](crate::Stack::poll_transmit_with) then
    /// behaves exactly like `poll_transmit`.
    pub const NONE: TxCaps = TxCaps {
        tso4: false,
        tso6: false,
        uso4: false,
        uso6: false,
    };
    pub const ALL: TxCaps = TxCaps {
        tso4: true,
        tso6: true,
        uso4: true,
        uso6: true,
    };

    pub(crate) fn tso(&self, v6: bool) -> bool {
        if v6 { self.tso6 } else { self.tso4 }
    }

    pub(crate) fn uso(&self, v6: bool) -> bool {
        if v6 { self.uso6 } else { self.uso4 }
    }
}

/// How the driver must segment a transmitted super-packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GsoTx {
    pub kind: GsoKind,
    /// Payload bytes per segment (the last one may be shorter).
    pub size: u16,
    /// IP plus L4 header length (`virtio_net_hdr.hdr_len`).
    pub hdr_len: u16,
}

/// Who completes the L4 checksum of a transmitted packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxCsum {
    /// Complete.
    Full,
    /// The field holds the pseudo-header sum over the whole super-packet's L4 length (not
    /// complemented, as Linux's `CHECKSUM_PARTIAL`); the receiver of the descriptor (kernel or
    /// device) sums from `start` and stores the result at `start + offset`.
    Partial { start: u16, offset: u16 },
}

/// A packet written to the caller's buffer by [`Stack::poll_transmit_with`](crate::Stack).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transmit {
    pub len: usize,
    pub gso: Option<GsoTx>,
    pub csum: TxCsum,
}

impl Transmit {
    pub(crate) fn plain(len: usize) -> Transmit {
        Transmit {
            len,
            gso: None,
            csum: TxCsum::Full,
        }
    }
}
