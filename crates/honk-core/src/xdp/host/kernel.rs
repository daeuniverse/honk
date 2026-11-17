//! Cold admission of actual kernel fields; parsing stays in the existing BTF reader.
use crate::ebpf::real::btf::{self, Btf};
use anyhow::{Context as _, ensure};
use honk_ebpf_common::host::HostConnectLayout;
use honk_netstack::MemoryBudget;
use std::fs::File;
use std::io::{BufRead as _, BufReader, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::sync::Arc;

pub(super) struct KernelLayout {
    kernel: btf::AccountedKernelBtf,
    pub connect: HostConnectLayout,
    pub socket_cookie: u32,
    pub skb_sk: u32,
    pub sock_net: u32,
    pub net_cookie: u32,
    pub skb_destructor: u32,
    pub skb_truesize: u32,
    pub sock_wfree: u64,
    pub task_mm: u32,
    pub mm_arg_start: u32,
}

#[derive(Clone, Copy)]
pub(crate) enum Leaf {
    Integer(u32),
    Pointer(&'static str),
    Function,
}

// Anonymous unions are real members, including sock's send_head/RTX alias.
fn member(btf: &Btf<'_>, owner: usize, name: &str, depth: u8) -> Option<(u32, u32)> {
    if depth == 8 || !matches!(btf.kind(owner)?, 4 | 5) {
        return None;
    }
    let info = btf.u32_at(owner + 4)?;
    let owner_size = btf.u32_at(owner + 8)?;
    let mut found = None;
    for index in 0..info & 0xffff {
        let at = owner.checked_add(12 + index as usize * 12)?;
        let member_name = btf.string(btf.u32_at(at)?)?;
        let ty = btf.u32_at(at + 4)?;
        let bits = btf.u32_at(at + 8)?;
        if info >> 31 != 0 && bits >> 24 != 0 {
            continue;
        }
        let bits = if info >> 31 != 0 {
            bits & 0xffffff
        } else {
            bits
        };
        if bits % 8 != 0 {
            continue;
        }
        let offset = bits / 8;
        if offset.checked_add(btf.type_size(ty)?)? > owner_size {
            return None;
        }
        let candidate = if member_name == name {
            Some((ty, offset))
        } else if member_name.is_empty() {
            member(btf, btf.resolve_composite(ty)?, name, depth + 1)
                .and_then(|(ty, inner)| Some((ty, offset.checked_add(inner)?)))
        } else {
            None
        };
        if let Some(candidate) = candidate {
            if found.is_some() {
                return None;
            }
            found = Some(candidate);
        }
    }
    found
}

pub(crate) fn field(btf: &Btf<'_>, root: &str, names: &[&str], leaf: Leaf) -> anyhow::Result<u32> {
    let mut owner = btf
        .find_type(4, root)
        .with_context(|| format!("Host BTF struct {root}"))?;
    let mut offset = 0u32;
    let mut terminal = None;
    for (index, name) in names.iter().enumerate() {
        let (ty, part) = member(btf, owner, name, 0)
            .with_context(|| format!("Host BTF {root}.{}", names.join(".")))?;
        offset = offset
            .checked_add(part)
            .context("Host BTF offset overflow")?;
        let cursor = btf.resolve_modifiers(ty).context("Host BTF member type")?;
        if index + 1 == names.len() {
            terminal = Some((ty, cursor));
        } else {
            owner = btf
                .resolve_composite(ty)
                .context("Host BTF non-composite member chain")?;
        }
    }
    let (ty, cursor) = terminal.context("empty Host BTF member chain")?;
    let width = match leaf {
        Leaf::Integer(width) => {
            ensure!(
                btf.kind(cursor) == Some(1) && btf.type_size(ty) == Some(width),
                "Host BTF integer width"
            );
            let encoding = btf
                .u32_at(cursor + 12)
                .context("Host BTF integer encoding")?;
            ensure!(
                encoding & 0x00ff_ffff == width * 8,
                "Host BTF partial integer"
            );
            width
        }
        Leaf::Pointer(target) => {
            ensure!(btf.kind(cursor) == Some(2), "Host BTF pointer required");
            let target = btf
                .find_type(4, target)
                .context("Host BTF pointer target")?;
            let pointee =
                btf.resolve_modifiers(btf.u32_at(cursor + 8).context("Host BTF pointer type")?);
            ensure!(pointee == Some(target), "Host BTF pointer target mismatch");
            8
        }
        Leaf::Function => {
            ensure!(
                btf.kind(cursor) == Some(2),
                "Host BTF function pointer required"
            );
            let pointee = btf
                .resolve_modifiers(
                    btf.u32_at(cursor + 8)
                        .context("Host BTF function pointer type")?,
                )
                .context("Host BTF function pointer target")?;
            ensure!(
                btf.kind(pointee) == Some(13),
                "Host BTF function prototype required"
            );
            8
        }
    };
    ensure!(
        offset.is_multiple_of(width) && offset <= i32::MAX as u32 - width,
        "Host BTF unaligned/out-of-range field"
    );
    Ok(offset)
}

impl KernelLayout {
    pub fn load(budget: &Arc<MemoryBudget>) -> anyhow::Result<Self> {
        ensure!(
            cfg!(target_arch = "x86_64") && cfg!(target_endian = "little"),
            "Host ordered ownership proof requires x86-64 little endian"
        );
        let kernel = btf::load_kernel_accounted(budget)?;
        let data = &kernel.data;
        let mut actual = File::open("/sys/kernel/btf/vmlinux")?;
        let mut buffer = [0u8; 8192];
        for chunk in data.chunks(buffer.len()) {
            actual.read_exact(&mut buffer[..chunk.len()])?;
            ensure!(
                &buffer[..chunk.len()] == chunk,
                "selected Host BTF differs from running-kernel kfunc BTF"
            );
        }
        ensure!(
            actual.read(&mut buffer[..1])? == 0,
            "selected Host BTF is truncated"
        );
        let btf = Btf::parse(data).context("Host kernel BTF")?;
        let integer = |root, names: &[&str], width| field(&btf, root, names, Leaf::Integer(width));
        let pointer =
            |root, names: &[&str], target| field(&btf, root, names, Leaf::Pointer(target));
        let connect = HostConnectLayout {
            valid: 1,
            state: integer("sock", &["__sk_common", "skc_state"], 1)?,
            lock_owned: integer("sock", &["sk_lock", "owned"], 4)?,
            wmem_alloc: integer("sock", &["sk_wmem_alloc", "refs", "counter"], 4)?,
            refcnt: integer("sock", &["__sk_common", "skc_refcnt", "refs", "counter"], 4)?,
            write_queue_len: integer("sock", &["sk_write_queue", "qlen"], 4)?,
            rtx_root: pointer("sock", &["tcp_rtx_queue", "rb_node"], "rb_node")?,
            send_head: pointer("sock", &["sk_send_head"], "sk_buff")?,
            backlog_head: pointer("sock", &["sk_backlog", "head"], "sk_buff")?,
            disconnect_generation: integer("sock", &["sk_disconnects"], 4)?,
            socket_mark: integer("sock", &["sk_mark"], 4)?,
            reserved: 0,
        };
        ensure!(
            connect.rtx_root == connect.send_head,
            "Host TCP send-head/RTX union is not the admitted alias"
        );
        Ok(Self {
            connect,
            socket_cookie: integer("sock", &["__sk_common", "skc_cookie", "counter"], 8)?,
            skb_sk: pointer("sk_buff", &["sk"], "sock")?,
            sock_net: pointer("sock", &["__sk_common", "skc_net", "net"], "net")?,
            net_cookie: integer("net", &["net_cookie"], 8)?,
            skb_destructor: field(&btf, "sk_buff", &["destructor"], Leaf::Function)?,
            skb_truesize: integer("sk_buff", &["truesize"], 4)?,
            sock_wfree: symbol("sock_wfree")?,
            task_mm: pointer("task_struct", &["mm"], "mm_struct")?,
            mm_arg_start: integer("mm_struct", &["arg_start"], 8)?,
            kernel,
        })
    }

    pub fn memory_bytes(&self) -> usize {
        self.kernel.memory_bytes()
    }

    pub fn btf(&self) -> &aya::Btf {
        &self.kernel.btf
    }
}

pub(super) fn symbol(name: &str) -> anyhow::Result<u64> {
    let mut result = None;
    for line in BufReader::new(File::open("/proc/kallsyms")?).lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        let (Some(address), Some(kind), Some(observed)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if observed != name {
            continue;
        }
        ensure!(
            matches!(kind, "T" | "t") && fields.next().is_none() && result.is_none(),
            "ambiguous Host kernel symbol {name}"
        );
        let address = u64::from_str_radix(address, 16)?;
        ensure!(address != 0, "Host kernel symbol {name} is hidden");
        result = Some(address);
    }
    result.with_context(|| format!("Host kernel symbol {name} unavailable"))
}

pub(crate) fn zero_monotonic_namespace() -> anyhow::Result<()> {
    ensure!(
        monotonic_namespace_offset()? == Some(0),
        "Host requires zero current monotonic offset"
    );
    Ok(())
}

pub(crate) fn monotonic_namespace_offset() -> anyhow::Result<Option<i128>> {
    let current = match File::open("/proc/self/ns/time") {
        Ok(current) => current,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            require_time_namespace_absence(|path| match File::open(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            })?;
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let children = File::open("/proc/self/ns/time_for_children")?;
    let worker = File::open("/proc/thread-self/ns/time")?;
    let identity = |file: &File| -> std::io::Result<_> {
        let m = file.metadata()?;
        Ok((m.dev(), m.ino()))
    };
    ensure!(
        identity(&current)? == identity(&children)? && identity(&current)? == identity(&worker)?,
        "Host current and children time namespaces differ"
    );
    let offsets = std::fs::read_to_string("/proc/self/timens_offsets")?;
    let mut monotonic = None;
    let mut boottime = false;
    for line in offsets.lines() {
        let words: Vec<_> = line.split_whitespace().collect();
        ensure!(words.len() == 3, "malformed Host time namespace offsets");
        let seconds: i64 = words[1].parse()?;
        let nanos: u32 = words[2].parse()?;
        ensure!(
            nanos < 1_000_000_000,
            "invalid Host time namespace nanoseconds"
        );
        match words[0] {
            "monotonic" => {
                ensure!(monotonic.is_none(), "duplicate monotonic offset");
                monotonic = Some(i128::from(seconds) * 1_000_000_000 + i128::from(nanos));
            }
            "boottime" => {
                ensure!(!boottime, "duplicate boottime offset");
                boottime = true;
            }
            _ => anyhow::bail!("unknown time namespace clock"),
        }
    }
    ensure!(boottime, "missing time namespace offsets");
    monotonic
        .context("missing time namespace offsets")
        .map(Some)
}

fn require_time_namespace_absence(
    mut present: impl FnMut(&str) -> std::io::Result<bool>,
) -> anyhow::Result<()> {
    for path in [
        "/proc/self/ns/time_for_children",
        "/proc/thread-self/ns/time",
        "/proc/self/timens_offsets",
    ] {
        ensure!(!present(path)?, "incomplete time namespace interfaces");
    }
    for path in ["/proc/self/ns/net", "/proc/thread-self/ns/net"] {
        ensure!(present(path)?, "process namespace inspection unavailable");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn absent_time_namespace_requires_complete_proc_evidence() {
        let without_timens = |path: &str| Ok(path.ends_with("/ns/net"));
        super::require_time_namespace_absence(without_timens).unwrap();
        for remaining in [
            "/proc/self/ns/time_for_children",
            "/proc/thread-self/ns/time",
            "/proc/self/timens_offsets",
        ] {
            assert!(
                super::require_time_namespace_absence(|path| {
                    Ok(path == remaining || path.ends_with("/ns/net"))
                })
                .is_err()
            );
        }
        assert!(super::require_time_namespace_absence(|_| Ok(false)).is_err());
        assert!(
            super::require_time_namespace_absence(|_| {
                Err(std::io::ErrorKind::PermissionDenied.into())
            })
            .is_err()
        );
    }
}
