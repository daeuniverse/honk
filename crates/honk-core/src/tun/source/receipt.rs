//! Create-new custody journal. Ambiguous intents survive errors and process death.
use anyhow::{Context as _, ensure};
use nix::fcntl::{AtFlags, OFlag, openat, renameat};
use nix::sys::stat::{Mode, fstat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use serde_json::{Value, json};
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub(super) struct Receipt {
    directory: File,
    file: File,
    name: String,
    value: Value,
}

fn create(directory: &File, name: &str) -> anyhow::Result<File> {
    Ok(openat(
        directory,
        name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )?
    .into())
}

fn owned(directory: &File, name: &str, file: &File) -> anyhow::Result<()> {
    let actual = fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
    let expected = fstat(file)?;
    ensure!(
        actual.st_mode & libc::S_IFMT == libc::S_IFREG
            && actual.st_dev == expected.st_dev
            && actual.st_ino == expected.st_ino,
        "Host custody receipt replaced; retaining all resources"
    );
    Ok(())
}

impl Receipt {
    pub fn create(
        data_dir: &Path,
        namespace: u64,
        attachment: u64,
        pin_root: &Path,
    ) -> anyhow::Result<Self> {
        ensure!(
            namespace != 0 && attachment != 0,
            "zero Host receipt authority"
        );
        let directory = crate::state::state_directory(data_dir, true, crate::state::private)?;
        let name = format!("host-{namespace}.json");
        let file =
            create(&directory, &name).context("stale Host receipt refuses startup; no adoption")?;
        let stat = std::fs::read_to_string("/proc/self/stat")?;
        let starttime: u64 = stat
            .rsplit_once(')')
            .context("process stat")?
            .1
            .split_whitespace()
            .nth(19)
            .context("process starttime")?
            .parse()?;
        let receipt = Self {
            directory,
            file,
            name,
            value: json!({
                "format": 1, "source_sha": env!("HONK_SOURCE_SHA"),
                "pid": std::process::id(), "starttime": starttime,
                "source_netns_cookie": namespace, "attachment": attachment,
                "pin_root": pin_root, "phase": "preparing", "resources": [],
            }),
        };
        receipt.write(&receipt.file)?;
        receipt.directory.sync_all()?;
        Ok(receipt)
    }

    fn write(&self, mut file: &File) -> anyhow::Result<()> {
        serde_json::to_writer_pretty(&mut file, &self.value)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    fn persist(&mut self) -> anyhow::Result<()> {
        owned(&self.directory, &self.name, &self.file)?;
        let temporary = format!("{}.tmp", self.name);
        let file = create(&self.directory, &temporary)?;
        self.write(&file)?;
        owned(&self.directory, &self.name, &self.file)?;
        renameat(
            &self.directory,
            temporary.as_str(),
            &self.directory,
            self.name.as_str(),
        )?;
        self.file = file;
        self.directory.sync_all()?;
        Ok(())
    }

    pub fn intent(&mut self, kind: &str, identity: Value) -> anyhow::Result<usize> {
        let resources = self.value["resources"]
            .as_array_mut()
            .expect("owned receipt array");
        let index = resources.len();
        resources.push(json!({"kind": kind, "state": "intent", "identity": identity}));
        self.persist()?;
        Ok(index)
    }

    pub fn acknowledge(&mut self, index: usize, observed: Value) -> anyhow::Result<()> {
        let entry = self.value["resources"]
            .get_mut(index)
            .context("unknown Host receipt intent")?;
        ensure!(
            entry["state"] == "intent",
            "Host receipt ACK without intent"
        );
        entry["state"] = json!("acknowledged");
        entry["observed"] = observed;
        self.persist()
    }

    pub fn phase(&mut self, phase: &str) -> anyhow::Result<()> {
        self.value["phase"] = json!(phase);
        self.persist()
    }

    pub fn begin_removal(&mut self, index: usize) -> anyhow::Result<()> {
        let entry = self.value["resources"]
            .get_mut(index)
            .context("unknown Host receipt resource")?;
        ensure!(
            entry["state"] == "acknowledged",
            "Host resource is not acknowledged"
        );
        entry["state"] = json!("removing");
        self.persist()
    }

    pub fn removed(&mut self, index: usize) -> anyhow::Result<()> {
        let entry = self.value["resources"]
            .get_mut(index)
            .context("unknown Host receipt removal")?;
        ensure!(
            entry["state"] == "removing",
            "Host removal ACK without intent"
        );
        entry["state"] = json!("removed");
        self.persist()
    }

    pub fn retire_pins(&mut self, root: &Path) -> anyhow::Result<()> {
        use std::os::fd::AsFd as _;
        let entries = self.value["resources"]
            .as_array()
            .expect("owned receipt array");
        use std::os::unix::fs::MetadataExt as _;
        let directory = entries
            .iter()
            .find(|entry| entry["kind"] == "pin_directory")
            .context("Host pin directory receipt absent")?;
        let metadata = std::fs::symlink_metadata(root)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && directory["observed"]["dev"].as_u64() == Some(metadata.dev())
                && directory["observed"]["inode"].as_u64() == Some(metadata.ino()),
            "Host pin directory replaced"
        );
        let mut pins = Vec::new();
        for entry in entries {
            if entry["state"] == "removed" {
                continue;
            }
            ensure!(
                entry["state"] == "acknowledged",
                "ambiguous Host mutation retains custody"
            );
            let kind = entry["kind"].as_str().context("Host receipt kind")?;
            let identity = &entry["identity"];
            let observed = &entry["observed"];
            if let Some(path) = identity["pin_path"].as_str() {
                let path = PathBuf::from(path);
                let (id, link) = match kind {
                    "map" => ("id", false),
                    "raw_program" => ("program_id", false),
                    "tracing_link" | "lsm_link" => ("link_id", false),
                    "selector" | "cgroup_link" => ("link_id", true),
                    _ => anyhow::bail!("unknown Host pinned resource"),
                };
                let expected =
                    u32::try_from(observed[id].as_u64().context("unobserved Host pin ID")?)?;
                ensure!(
                    path.starts_with(root) && expected != 0,
                    "Host pin outside custody"
                );
                let fd = super::sys::open_pin(&path, expected)?;
                pins.push((path, fd, link));
            }
        }
        let indices: Vec<_> = (0..entries.len())
            .filter(|&index| entries[index]["state"] == "acknowledged")
            .collect();
        for &index in &indices {
            self.begin_removal(index)?;
        }
        for (_, fd, link) in &pins {
            if *link {
                super::sys::detach(fd.as_fd())?;
            }
        }
        for (path, _, _) in &pins {
            std::fs::remove_file(path)?;
        }
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            ensure!(
                entry.file_type()?.is_dir(),
                "unexpected file in Host pin root"
            );
            std::fs::remove_dir(entry.path())?;
        }
        std::fs::remove_dir(root)?;
        for index in indices {
            self.removed(index)?;
        }
        Ok(())
    }

    pub fn finish(&self) -> anyhow::Result<()> {
        ensure!(
            self.value["resources"]
                .as_array()
                .expect("owned receipt array")
                .iter()
                .all(|entry| entry["state"] == "removed"),
            "unretired Host resources; retaining receipt"
        );
        owned(&self.directory, &self.name, &self.file)?;
        unlinkat(
            &self.directory,
            self.name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        )?;
        self.directory.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_requires_ack_and_observed_removal_before_release() {
        let directory = tempfile::tempdir().unwrap();
        let mut receipt =
            Receipt::create(directory.path(), 41, 7, Path::new("/sys/fs/bpf/test-host")).unwrap();
        let path = directory
            .path()
            .join(crate::state::STATE_DIR)
            .join("host-41.json");
        let index = receipt
            .intent("tun_filter", json!({"ifindex":17,"attachment":7}))
            .unwrap();
        assert!(receipt.finish().is_err());
        assert!(
            Receipt::create(directory.path(), 41, 8, Path::new("/sys/fs/bpf/test-host")).is_err()
        );
        receipt.acknowledge(index, json!({"ifindex":17})).unwrap();
        assert!(receipt.finish().is_err());
        receipt.begin_removal(index).unwrap();
        assert!(receipt.finish().is_err());
        receipt.removed(index).unwrap();
        receipt.finish().unwrap();
        assert!(!path.exists());
    }
}
