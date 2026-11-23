use anyhow::{Context as _, ensure};
use std::os::fd::AsRawFd as _;

pub(super) struct Features {
    socket: socket2::Socket,
    name: [libc::c_char; libc::IFNAMSIZ],
    count: usize,
    expected: Vec<u32>,
    scratch: Vec<u32>,
}

impl Features {
    pub fn configure(name: &str) -> anyhow::Result<Self> {
        ensure!(
            name.len() < libc::IFNAMSIZ && !name.as_bytes().contains(&0),
            "invalid private link name"
        );
        let mut result = Self {
            socket: socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?,
            name: [0; libc::IFNAMSIZ],
            count: 0,
            expected: Vec::new(),
            scratch: Vec::new(),
        };
        for (out, byte) in result.name.iter_mut().zip(name.bytes()) {
            *out = byte as libc::c_char;
        }
        let mut info = [0u32; 5];
        info[0] = 0x37;
        info[2] = 1 << 4; // GSSET_INFO, ETH_SS_FEATURES.
        result.query(&mut info)?;
        ensure!(
            info[2] == 1 << 4 && info[4] > 0 && info[4] <= 4096,
            "private ethtool feature names unavailable"
        );
        result.count = info[4] as usize;
        let mut names = vec![0u32; 3 + result.count * 8];
        names[0] = 0x1b;
        names[1] = 4;
        names[2] = result.count as u32;
        result.query(&mut names)?;
        let blocks = result.count.div_ceil(32);
        let mut set = vec![0u32; 2 + blocks * 2];
        set[0] = 0x3b;
        set[1] = blocks as u32;
        let mut vlan = false;
        for index in 0..result.count {
            let mut bytes = [0u8; 32];
            for (out, word) in bytes
                .as_chunks_mut::<4>()
                .0
                .iter_mut()
                .zip(&names[3 + index * 8..3 + (index + 1) * 8])
            {
                out.copy_from_slice(&word.to_ne_bytes());
            }
            let end = bytes
                .iter()
                .position(|&byte| byte == 0)
                .context("unterminated ethtool feature")?;
            let feature = std::str::from_utf8(&bytes[..end])?;
            let enabled = feature == "tx-vlan-hw-insert";
            let disabled = feature.starts_with("tx-checksum-")
                || feature.starts_with("tx-tcp")
                || feature.starts_with("tx-gso-")
                || feature.starts_with("tx-udp")
                || matches!(
                    feature,
                    "generic-segmentation-offload"
                        | "generic-receive-offload"
                        | "large-receive-offload"
                        | "rx-gro-list"
                        | "rx-udp-gro-forwarding"
                );
            if enabled || disabled {
                set[2 + index / 32 * 2] |= 1 << (index % 32);
                if enabled {
                    set[3 + index / 32 * 2] |= 1 << (index % 32);
                    vlan = true;
                }
            }
        }
        ensure!(
            vlan,
            "private accelerated VLAN transmit feature unavailable"
        );
        result.query(&mut set)?;
        let current = result.read()?;
        for block in 0..blocks {
            let valid = set[2 + block * 2];
            let wanted = set[3 + block * 2];
            ensure!(
                current[2 + block * 4 + 2] & valid == wanted,
                "private offload materialization readback failed"
            );
        }
        result.expected = current;
        result.scratch = vec![0; result.expected.len()];
        Ok(result)
    }
    fn query(&self, words: &mut [u32]) -> anyhow::Result<()> {
        let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
        request.ifr_name = self.name;
        request.ifr_ifru.ifru_data = words.as_mut_ptr().cast();
        // SFEATURES returns nonnegative flags; configure verifies the actual active bits.
        ensure!(
            unsafe {
                libc::ioctl(
                    self.socket.as_raw_fd(),
                    libc::SIOCETHTOOL as _,
                    &mut request,
                )
            } >= 0,
            "Host ethtool: {}",
            std::io::Error::last_os_error()
        );
        Ok(())
    }
    fn read(&self) -> anyhow::Result<Vec<u32>> {
        let mut words = vec![0; 2 + self.count.div_ceil(32) * 4];
        words[0] = 0x3a;
        words[1] = self.count.div_ceil(32) as u32;
        self.query(&mut words)?;
        Ok(words)
    }
    pub fn check(&mut self) -> anyhow::Result<()> {
        let mut scratch = std::mem::take(&mut self.scratch);
        scratch.fill(0);
        scratch[0] = 0x3a;
        scratch[1] = self.count.div_ceil(32) as u32;
        let result = self.query(&mut scratch);
        self.scratch = scratch;
        result?;
        if let Some(at) = self
            .scratch
            .iter()
            .zip(&self.expected)
            .position(|(now, was)| now != was)
        {
            anyhow::bail!(
                "Host private offloads changed at word {at}: expected {:#010x}, actual {:#010x}",
                self.expected[at],
                self.scratch[at]
            );
        }
        Ok(())
    }
}
