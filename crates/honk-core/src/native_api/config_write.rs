//! FD-relative configuration replacement; callers own authorization and dependency admission.

use std::ffi::OsString;
use std::fs::{File, Metadata, Permissions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{OFlag, open, openat, renameat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum WriteError {
    #[error("configuration source changed")]
    Conflict,
    #[error("configuration source already exists")]
    Exists,
    #[error("configuration source is unavailable")]
    Unavailable,
    #[error("configuration source exceeds the size limit")]
    TooLarge,
    #[error("configuration source path is unsafe")]
    UnsafePath,
    #[error("configuration source declares a listener secret")]
    SecretSource,
    #[error("configuration source contains a listener secret")]
    SecretContent,
    #[error("configuration source is not UTF-8")]
    InvalidUtf8,
    #[error("configuration source changed but durability is unconfirmed")]
    ChangedButNotDurable,
}

pub(crate) struct SourceFile {
    directory: File,
    parent_path: PathBuf,
    filename: OsString,
    // Pin the original inode until replacement finishes, including across external renames.
    file: File,
    metadata: Metadata,
    hash: String,
    max_bytes: usize,
    #[cfg(test)]
    sync_fault: Option<SyncFault>,
}

impl SourceFile {
    pub(crate) fn open(path: &Path, max_bytes: usize) -> Result<Self, WriteError> {
        Self::open_inner(path, max_bytes, true)
    }

    pub(crate) fn open_binary(path: &Path, max_bytes: usize) -> Result<Self, WriteError> {
        Self::open_inner(path, max_bytes, false)
    }

    fn open_inner(path: &Path, max_bytes: usize, text: bool) -> Result<Self, WriteError> {
        let Target {
            directory,
            parent_path,
            filename,
        } = Target::open(path)?;
        let file = open_source(&directory, &filename).map_err(path_error)?;
        let metadata = regular_metadata(&file, max_bytes)?;
        let (hash, length) = if text {
            let mut bytes = Vec::new();
            (&file)
                .take(read_limit(max_bytes))
                .read_to_end(&mut bytes)
                .map_err(|_| WriteError::Unavailable)?;
            if bytes.len() > max_bytes {
                return Err(WriteError::TooLarge);
            }
            if std::str::from_utf8(&bytes).is_err() {
                return Err(WriteError::InvalidUtf8);
            }
            (crate::configuration::digest(&bytes), bytes.len() as u64)
        } else {
            // Only text needs its bytes whole; a geodata asset is hashed as it is read.
            stream_digest(&file, max_bytes)?
        };
        if metadata.len() != length
            || !same_version(
                &metadata,
                &file.metadata().map_err(|_| WriteError::Unavailable)?,
            )
        {
            return Err(WriteError::Conflict);
        }
        Ok(Self {
            directory,
            parent_path,
            filename,
            file,
            metadata,
            hash,
            max_bytes,
            #[cfg(test)]
            sync_fault: None,
        })
    }

    /// Lowercase, unquoted SHA-256 of the exact source bytes.
    pub(crate) fn sha256(&self) -> String {
        self.hash.clone()
    }

    pub(crate) fn same_target(&self, other: &Self) -> bool {
        same_inode(&self.metadata, &other.metadata)
    }

    /// The callback must recheck the accepted root and complete dependency set.
    /// Neither this check nor the subsequent rename locks out external editors.
    pub(crate) fn replace(
        self,
        content: &str,
        before_rename: impl FnOnce() -> Result<(), WriteError>,
    ) -> Result<(), WriteError> {
        let installed = self
            .stage_into(None, content.as_bytes(), None)?
            .replace(before_rename)?;
        if installed.durability_confirmed {
            Ok(())
        } else {
            Err(WriteError::ChangedButNotDurable)
        }
    }

    pub(crate) fn stage(
        self,
        expected_hash: &str,
        content: &[u8],
    ) -> Result<StagedFile, WriteError> {
        self.stage_into(Some(expected_hash), content, None)
    }

    /// Stages `content` as a new file at `target`, leaving this file in place
    /// and pinned until the rename, which never replaces anything at `target`.
    pub(crate) fn stage_beside(
        self,
        expected_hash: &str,
        target: &Path,
        content: &[u8],
    ) -> Result<StagedFile, WriteError> {
        let target = Target::open(target)?;
        self.stage_into(Some(expected_hash), content, Some(target))
    }

    /// `expected_hash`, when given, must match the pinned bytes.
    fn stage_into(
        self,
        expected_hash: Option<&str>,
        content: &[u8],
        target: Option<Target>,
    ) -> Result<StagedFile, WriteError> {
        if expected_hash.is_some_and(|expected| self.hash != expected) {
            return Err(WriteError::Conflict);
        }
        if content.len() > self.max_bytes {
            return Err(WriteError::TooLarge);
        }
        let temporary = TemporaryFile::write(
            target
                .as_ref()
                .map_or(&self.directory, |target| &target.directory),
            content,
            self.metadata.mode(),
        )?;
        #[cfg(test)]
        if self.sync_fault == Some(SyncFault::File) {
            return Err(WriteError::Unavailable);
        }

        Ok(StagedFile {
            source: self,
            temporary,
            hash: crate::configuration::digest(content),
            target,
        })
    }

    pub(crate) fn recheck(&self) -> Result<(), WriteError> {
        recheck_directory(&self.directory, &self.parent_path)?;
        let current = open_source(&self.directory, &self.filename).map_err(recheck_error)?;
        let metadata = regular_metadata(&current, self.max_bytes)?;
        if !same_version(&self.metadata, &metadata)
            || !same_version(
                &self.metadata,
                &self.file.metadata().map_err(|_| WriteError::Unavailable)?,
            )
        {
            return Err(WriteError::Conflict);
        }
        let (hash, total) = stream_digest(&current, self.max_bytes)?;
        if total != metadata.len()
            || hash != self.hash
            || !same_version(
                &metadata,
                &current.metadata().map_err(|_| WriteError::Unavailable)?,
            )
        {
            return Err(WriteError::Conflict);
        }
        Ok(())
    }
}

/// The SHA-256 and length of at most `max_bytes` of `file`, read in chunks.
fn stream_digest(file: &File, max_bytes: usize) -> Result<(String, u64), WriteError> {
    let mut reader = file.take(read_limit(max_bytes));
    let mut digest = Sha256::new();
    let mut buffer = [0; 8192];
    let mut total = 0u64;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(WriteError::Unavailable),
        };
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > max_bytes as u64 {
            return Err(WriteError::TooLarge);
        }
        digest.update(&buffer[..count]);
    }
    Ok((
        crate::configuration::encode_digest(&digest.finalize()),
        total,
    ))
}

pub(crate) struct StagedFile {
    source: SourceFile,
    temporary: TemporaryFile,
    hash: String,
    /// Where a new file goes instead of replacing `source`.
    target: Option<Target>,
}

struct Target {
    directory: File,
    parent_path: PathBuf,
    filename: OsString,
}

impl Target {
    fn open(path: &Path) -> Result<Self, WriteError> {
        let path = std::path::absolute(path).map_err(|_| WriteError::Unavailable)?;
        let parent_path = path.parent().ok_or(WriteError::UnsafePath)?.to_owned();
        let filename = path.file_name().ok_or(WriteError::UnsafePath)?.to_owned();
        let directory = open_directory(&parent_path).map_err(path_error)?;
        Ok(Self {
            directory,
            parent_path,
            filename,
        })
    }

    /// Moves `temporary` to the target name; never replaces anything already there.
    fn install(&self, temporary: &mut TemporaryFile) -> Result<(), WriteError> {
        crate::state::rename_noreplace(
            &self.directory,
            temporary.name.as_str(),
            self.filename.as_os_str(),
        )
        .map_err(|error| match error {
            Errno::EEXIST => WriteError::Conflict,
            error => path_error(error),
        })?;
        temporary.renamed = true;
        Ok(())
    }
}

/// Creates `path` with `content` and `mode` through a temporary file and a rename that
/// never replaces anything at `path`. The callback must recheck the candidate.
pub(crate) fn create_new(
    path: &Path,
    content: &[u8],
    mode: u32,
    before_rename: impl FnOnce() -> Result<(), WriteError>,
) -> Result<(), WriteError> {
    let target = Target::open(path)?;
    let mut temporary = TemporaryFile::write(&target.directory, content, mode)?;
    recheck_directory(&target.directory, &target.parent_path)?;
    before_rename()?;
    recheck_directory(&target.directory, &target.parent_path)?;
    // The no-replace rename is the only conflict `install` reports.
    target
        .install(&mut temporary)
        .map_err(|error| match error {
            WriteError::Conflict => WriteError::Exists,
            error => error,
        })?;
    if target.directory.sync_all().is_err() {
        return Err(WriteError::ChangedButNotDurable);
    }
    Ok(())
}

pub(crate) struct InstalledFile {
    pub(crate) file: SourceFile,
    pub(crate) durability_confirmed: bool,
}

impl StagedFile {
    pub(crate) fn sha256(&self) -> &str {
        &self.hash
    }

    pub(crate) fn same_target(&self, other: &SourceFile) -> bool {
        self.source.same_target(other)
    }

    pub(crate) fn recheck(&self) -> Result<(), WriteError> {
        self.source.recheck()
    }

    pub(crate) fn modified_at(&self) -> Option<std::time::SystemTime> {
        self.temporary.file.metadata().ok()?.modified().ok()
    }

    pub(crate) fn replace(
        mut self,
        before_rename: impl FnOnce() -> Result<(), WriteError>,
    ) -> Result<InstalledFile, WriteError> {
        self.source.recheck()?;
        before_rename()?;
        self.source.recheck()?;
        let Some(target) = self.target.take() else {
            renameat(
                &self.source.directory,
                self.temporary.name.as_str(),
                &self.source.directory,
                self.source.filename.as_os_str(),
            )
            .map_err(path_error)?;
            self.temporary.renamed = true;
            let metadata = self
                .temporary
                .file
                .metadata()
                .map_err(|_| WriteError::ChangedButNotDurable)?;
            let durability_confirmed = self.source.directory.sync_all().is_ok();
            #[cfg(test)]
            let durability_confirmed =
                durability_confirmed && self.source.sync_fault != Some(SyncFault::Directory);
            std::mem::swap(&mut self.source.file, &mut self.temporary.file);
            self.source.metadata = metadata;
            self.source.hash = self.hash;
            return Ok(InstalledFile {
                file: self.source,
                durability_confirmed,
            });
        };
        recheck_directory(&target.directory, &target.parent_path)?;
        target.install(&mut self.temporary)?;
        let file = self
            .temporary
            .file
            .try_clone()
            .map_err(|_| WriteError::ChangedButNotDurable)?;
        let metadata = file
            .metadata()
            .map_err(|_| WriteError::ChangedButNotDurable)?;
        let durability_confirmed = target.directory.sync_all().is_ok();
        #[cfg(test)]
        let durability_confirmed =
            durability_confirmed && self.source.sync_fault != Some(SyncFault::Directory);
        Ok(InstalledFile {
            file: SourceFile {
                directory: target.directory,
                parent_path: target.parent_path,
                filename: target.filename,
                file,
                metadata,
                hash: self.hash,
                max_bytes: self.source.max_bytes,
                #[cfg(test)]
                sync_fault: self.source.sync_fault,
            },
            durability_confirmed,
        })
    }
}

fn read_limit(max_bytes: usize) -> u64 {
    (max_bytes as u64).saturating_add(1)
}

fn open_directory(path: &Path) -> Result<File, Errno> {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory = File::from(open(Path::new("/"), flags, Mode::empty())?);
    for component in path.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir => std::ffi::OsStr::new(".."),
            Component::Prefix(_) => return Err(Errno::EINVAL),
        };
        directory = File::from(openat(&directory, name, flags, Mode::empty())?);
    }
    Ok(directory)
}

fn open_source(directory: &File, filename: &OsString) -> Result<File, Errno> {
    openat(
        directory,
        filename.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

fn regular_metadata(file: &File, max_bytes: usize) -> Result<Metadata, WriteError> {
    let metadata = file.metadata().map_err(|_| WriteError::Unavailable)?;
    if !metadata.is_file() {
        return Err(WriteError::UnsafePath);
    }
    if metadata.len() > max_bytes as u64 {
        return Err(WriteError::TooLarge);
    }
    Ok(metadata)
}

fn same_inode(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

fn same_version(a: &Metadata, b: &Metadata) -> bool {
    same_inode(a, b)
        && a.len() == b.len()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn path_error(error: Errno) -> WriteError {
    match error {
        Errno::ELOOP | Errno::ENOTDIR | Errno::EINVAL => WriteError::UnsafePath,
        _ => WriteError::Unavailable,
    }
}

/// Fails unless `parent_path` still walks, without symlinks, to `directory`.
fn recheck_directory(directory: &File, parent_path: &Path) -> Result<(), WriteError> {
    let current = open_directory(parent_path).map_err(recheck_error)?;
    if !same_inode(
        &directory.metadata().map_err(|_| WriteError::Unavailable)?,
        &current.metadata().map_err(|_| WriteError::Unavailable)?,
    ) {
        return Err(WriteError::Conflict);
    }
    Ok(())
}

fn recheck_error(error: Errno) -> WriteError {
    match error {
        Errno::ENOENT => WriteError::Conflict,
        _ => path_error(error),
    }
}

const TEMPORARY_PREFIX: &str = ".honk-config-";
const TEMPORARY_SUFFIX: &str = ".tmp";

/// Removes temporary files a killed process left in `directory` and returns their paths.
/// Only call this before any write of this process can have staged one.
pub(crate) fn remove_stale_temporaries(directory: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut removed = Vec::new();
    for entry in entries.flatten() {
        let is_temporary = entry.file_name().to_str().is_some_and(|name| {
            name.strip_prefix(TEMPORARY_PREFIX)
                .and_then(|name| name.strip_suffix(TEMPORARY_SUFFIX))
                .is_some_and(|id| {
                    uuid::Uuid::try_parse(id).is_ok_and(|uuid| uuid.hyphenated().to_string() == id)
                })
        });
        if is_temporary
            && entry.file_type().is_ok_and(|kind| kind.is_file())
            && std::fs::remove_file(entry.path()).is_ok()
        {
            removed.push(entry.path());
        }
    }
    removed
}

struct TemporaryFile {
    directory: File,
    name: String,
    file: File,
    renamed: bool,
}

impl TemporaryFile {
    fn create(directory: &File) -> Result<Self, WriteError> {
        let directory = directory.try_clone().map_err(|_| WriteError::Unavailable)?;
        let name = format!(
            "{TEMPORARY_PREFIX}{}{TEMPORARY_SUFFIX}",
            uuid::Uuid::new_v4()
        );
        let descriptor = openat(
            &directory,
            name.as_str(),
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_EXCL
                | OFlag::O_NOFOLLOW
                | OFlag::O_NONBLOCK
                | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(path_error)?;
        Ok(Self {
            directory,
            name,
            file: File::from(descriptor),
            renamed: false,
        })
    }

    /// A synced temporary file holding `content` with the permission bits of `mode`.
    fn write(directory: &File, content: &[u8], mode: u32) -> Result<Self, WriteError> {
        let mut temporary = Self::create(directory)?;
        temporary
            .file
            .write_all(content)
            .map_err(|_| WriteError::Unavailable)?;
        temporary
            .file
            .set_permissions(Permissions::from_mode(mode & 0o7777))
            .map_err(|_| WriteError::Unavailable)?;
        temporary
            .file
            .sync_all()
            .map_err(|_| WriteError::Unavailable)?;
        Ok(temporary)
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        if !self.renamed {
            let _ = unlinkat(
                &self.directory,
                self.name.as_str(),
                UnlinkatFlags::NoRemoveDir,
            );
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum SyncFault {
    File,
    Directory,
}

#[cfg(test)]
mod tests;
