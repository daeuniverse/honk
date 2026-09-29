//! Inner TLS observation for Vision.
//!
//! Decides where uplink padding ends and whether that end may switch to
//! Direct. Decisions follow TLS record structure, never read or write call
//! boundaries, so relay chunking cannot move or hide a switch point.

const INSPECT_LIMIT: usize = 64 * 1024;
// X25519MLKEM768 key shares make a ServerHello about 1.2 KiB.
const MAX_SERVER_HELLO: usize = 4096;
const RECORD_CHANGE_CIPHER_SPEC: u8 = 20;
const RECORD_HANDSHAKE: u8 = 22;
const RECORD_APPLICATION_DATA: u8 = 23;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const HANDSHAKE_SERVER_HELLO: u8 = 2;
const EXTENSION_SUPPORTED_VERSIONS: u16 = 0x002b;
// RFC 8446 section 4.1.3: HelloRetryRequest reuses ServerHello with this random.
const HELLO_RETRY_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Xray reshapes buffers of 8171 bytes or more, so frame content stays below.
const MAX_FRAME_CONTENT: usize = 8170;

/// How one uplink Vision frame ends; the discriminant is its wire command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Terminal {
    /// More padded frames follow.
    Continue = 0,
    /// Padding ends; later bytes keep the outer codec.
    End = 1,
    /// Padding ends; later bytes bypass the outer codec.
    Direct = 2,
}

/// The next uplink frame: its content length and command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct UplinkFrame {
    pub(super) take: usize,
    pub(super) terminal: Terminal,
    pub(super) long_padding: bool,
}

#[derive(Debug, Default)]
pub(super) struct InnerTls {
    uplink: Records,
    client: ClientKind,
    uplink_inspected: usize,
    server: ServerHello,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum ClientKind {
    #[default]
    Unknown,
    Tls,
    Other,
}

impl InnerTls {
    /// Plans the next padded frame from the head of `data`.
    ///
    /// A terminal frame always ends exactly where a complete client
    /// application-data record ends, as Xray's `IsCompleteRecord` requires.
    pub(super) fn plan_uplink(&mut self, data: &[u8], direct_capable: bool) -> UplinkFrame {
        let data = &data[..data.len().min(MAX_FRAME_CONTENT)];
        let end = |take, long_padding| UplinkFrame {
            take,
            terminal: Terminal::End,
            long_padding,
        };
        if self.client == ClientKind::Other {
            return end(data.len(), false);
        }
        let mut offset = 0;
        while offset < data.len() {
            let (used, step) = self.uplink.next(&data[offset..]);
            offset += used;
            let ended = match step {
                Step::Invalid => {
                    let was_tls = self.client == ClientKind::Tls;
                    self.client = ClientKind::Other;
                    return end(data.len(), was_tls);
                }
                Step::Header { ended } => ended,
                Step::Content {
                    record_type,
                    first,
                    last,
                } => {
                    if first && self.client == ClientKind::Unknown {
                        let hello = record_type == RECORD_HANDSHAKE
                            && data[offset - used] == HANDSHAKE_CLIENT_HELLO;
                        if !hello {
                            self.client = ClientKind::Other;
                            return end(data.len(), false);
                        }
                        self.client = ClientKind::Tls;
                    }
                    last.then_some(record_type)
                }
            };
            if ended == Some(RECORD_APPLICATION_DATA) && self.client == ClientKind::Tls {
                let terminal = if direct_capable && self.server.verdict == Verdict::Xtls {
                    Terminal::Direct
                } else {
                    Terminal::End
                };
                return UplinkFrame {
                    take: offset,
                    terminal,
                    long_padding: true,
                };
            }
        }
        self.uplink_inspected += data.len();
        if self.uplink_inspected >= INSPECT_LIMIT {
            return end(data.len(), self.client == ClientKind::Tls);
        }
        UplinkFrame {
            take: data.len(),
            terminal: Terminal::Continue,
            long_padding: self.client == ClientKind::Tls,
        }
    }

    /// Observes plaintext delivered downstream until the ServerHello decides
    /// whether a client-side Direct switch is allowed.
    pub(super) fn observe_downlink(&mut self, data: &[u8]) {
        self.server.observe(data);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Verdict {
    #[default]
    Pending,
    /// TLS 1.3 with a cipher Xray accepts for Direct.
    Xtls,
    Ineligible,
}

#[derive(Debug, Default)]
struct ServerHello {
    records: Records,
    message: Vec<u8>,
    inspected: usize,
    verdict: Verdict,
}

impl ServerHello {
    fn observe(&mut self, data: &[u8]) {
        if self.verdict != Verdict::Pending {
            return;
        }
        self.inspected += data.len();
        let mut offset = 0;
        while offset < data.len() && self.verdict == Verdict::Pending {
            let (used, step) = self.records.next(&data[offset..]);
            let bytes = &data[offset..offset + used];
            offset += used;
            match step {
                Step::Invalid => self.decide(Verdict::Ineligible),
                Step::Header { .. } => {}
                Step::Content {
                    record_type: RECORD_HANDSHAKE,
                    ..
                } => {
                    // One ServerHello, or a HelloRetryRequest and then one.
                    let room = (4 + MAX_SERVER_HELLO).saturating_sub(self.message.len());
                    self.message
                        .extend_from_slice(&bytes[..bytes.len().min(room)]);
                    self.parse_messages();
                }
                // Middlebox-compatibility CCS may separate HelloRetryRequest
                // from the real ServerHello; anything else ends the search.
                Step::Content {
                    record_type: RECORD_CHANGE_CIPHER_SPEC,
                    ..
                } => {}
                Step::Content { .. } => self.decide(Verdict::Ineligible),
            }
        }
        if self.verdict == Verdict::Pending && self.inspected >= INSPECT_LIMIT {
            self.decide(Verdict::Ineligible);
        }
    }

    fn parse_messages(&mut self) {
        while self.verdict == Verdict::Pending && self.message.len() >= 4 {
            let length =
                u32::from_be_bytes([0, self.message[1], self.message[2], self.message[3]]) as usize;
            if self.message[0] != HANDSHAKE_SERVER_HELLO || length > MAX_SERVER_HELLO {
                return self.decide(Verdict::Ineligible);
            }
            if self.message.len() < 4 + length {
                return;
            }
            match parse_server_hello(&self.message[4..4 + length]) {
                Some(Hello::Retry) => {
                    self.message.drain(..4 + length);
                }
                Some(Hello::Final { tls13, cipher }) => {
                    self.decide(if tls13 && (0x1301..=0x1304).contains(&cipher) {
                        Verdict::Xtls
                    } else {
                        Verdict::Ineligible
                    })
                }
                None => self.decide(Verdict::Ineligible),
            }
        }
    }

    fn decide(&mut self, verdict: Verdict) {
        self.verdict = verdict;
        self.message = Vec::new();
    }
}

enum Hello {
    Retry,
    Final { tls13: bool, cipher: u16 },
}

fn parse_server_hello(body: &[u8]) -> Option<Hello> {
    let random: [u8; 32] = body.get(2..34)?.try_into().ok()?;
    let session_len = *body.get(34)? as usize;
    let mut offset = 35 + session_len;
    let cipher = u16::from_be_bytes(body.get(offset..offset + 2)?.try_into().ok()?);
    offset += 3;
    if random == HELLO_RETRY_RANDOM {
        return Some(Hello::Retry);
    }
    let mut tls13 = false;
    if let Some(length) = body.get(offset..offset + 2) {
        let end = offset + 2 + u16::from_be_bytes([length[0], length[1]]) as usize;
        let mut extensions = body.get(offset + 2..end)?;
        while !extensions.is_empty() {
            let kind = u16::from_be_bytes(extensions.get(..2)?.try_into().ok()?);
            let size = u16::from_be_bytes(extensions.get(2..4)?.try_into().ok()?) as usize;
            let value = extensions.get(4..4 + size)?;
            tls13 |= kind == EXTENSION_SUPPORTED_VERSIONS && value == [3, 4];
            extensions = &extensions[4 + size..];
        }
    }
    Some(Hello::Final { tls13, cipher })
}

/// Walks TLS records across arbitrary slice boundaries.
#[derive(Debug, Default)]
struct Records {
    header: [u8; 5],
    filled: usize,
    remaining: usize,
}

enum Step {
    /// `ended` is the type of a record whose header was its last byte.
    Header {
        ended: Option<u8>,
    },
    Content {
        record_type: u8,
        first: bool,
        last: bool,
    },
    Invalid,
}

impl Records {
    /// Consumes the next header or content piece at the head of `data`.
    fn next(&mut self, data: &[u8]) -> (usize, Step) {
        if self.filled < self.header.len() {
            let used = (self.header.len() - self.filled).min(data.len());
            self.header[self.filled..self.filled + used].copy_from_slice(&data[..used]);
            self.filled += used;
            if self.filled < self.header.len() {
                return (used, Step::Header { ended: None });
            }
            if !(20..=23).contains(&self.header[0]) || self.header[1] != 3 {
                return (used, Step::Invalid);
            }
            self.remaining = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            let ended = (self.remaining == 0).then_some(self.header[0]);
            if ended.is_some() {
                self.filled = 0;
            }
            return (used, Step::Header { ended });
        }
        let record_type = self.header[0];
        let first = self.remaining == u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
        let used = self.remaining.min(data.len());
        self.remaining -= used;
        let last = self.remaining == 0;
        if last {
            self.filled = 0;
        }
        (
            used,
            Step::Content {
                record_type,
                first,
                last,
            },
        )
    }
}

#[cfg(test)]
mod tests;
