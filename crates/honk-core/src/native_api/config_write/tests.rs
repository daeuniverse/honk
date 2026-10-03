use std::fs;
use std::os::unix::fs::symlink;

use super::*;

const ORIGINAL: &str = "# Keep this source comment: π\nrouting {\n    fallback: direct\n}\n";
const REPLACEMENT: &str =
    "# Edited comment, unchanged policy: λ\r\nrouting {\r\n    fallback: direct\r\n}\r\n";
const LIMIT: usize = 4096;

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.dae");
    fs::write(&path, ORIGINAL).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o640)).unwrap();
    (directory, path)
}

fn assert_only_config(directory: &Path) {
    let names: Vec<_> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [OsString::from("config.dae")]);
}

#[test]
fn replacement_preserves_exact_bytes_mode_and_old_open_inode() {
    let (directory, path) = fixture();
    let mut old_file = File::open(&path).unwrap();
    let old_metadata = old_file.metadata().unwrap();
    let source = SourceFile::open(&path, LIMIT).unwrap();
    source
        .replace(REPLACEMENT, || {
            assert_eq!(fs::read(&path).unwrap(), ORIGINAL.as_bytes());
            Ok(())
        })
        .unwrap();

    assert_eq!(fs::read(&path).unwrap(), REPLACEMENT.as_bytes());
    let mut retained = String::new();
    old_file.read_to_string(&mut retained).unwrap();
    assert_eq!(retained, ORIGINAL);
    assert_ne!(fs::metadata(&path).unwrap().ino(), old_metadata.ino());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o640);
    assert_eq!(old_file.metadata().unwrap().mode() & 0o7777, 0o640);
    let replaced = SourceFile::open(&path, LIMIT).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), REPLACEMENT);
    assert_eq!(
        replaced.sha256(),
        crate::configuration::digest(REPLACEMENT.as_bytes())
    );
    assert_only_config(directory.path());
}

#[test]
fn conflicting_disk_edits_never_overwrite_the_editor() {
    for rename in [false, true] {
        let (directory, path) = fixture();
        let source = SourceFile::open(&path, LIMIT).unwrap();
        let editor_content = if rename {
            ORIGINAL
        } else {
            "# editor changed the open inode\n"
        };
        if rename {
            let replacement = directory.path().join("editor.dae");
            fs::write(&replacement, editor_content).unwrap();
            fs::set_permissions(&replacement, Permissions::from_mode(0o640)).unwrap();
            fs::rename(replacement, &path).unwrap();
        } else {
            fs::write(&path, editor_content).unwrap();
        }
        assert_eq!(
            source.replace(REPLACEMENT, || panic!("changed target reached admission")),
            Err(WriteError::Conflict)
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), editor_content);
        assert_only_config(directory.path());
    }
}

#[test]
fn wrong_precondition_and_dependency_rejection_leave_disk_unchanged() {
    let (directory, path) = fixture();
    let source = SourceFile::open(&path, LIMIT).unwrap();
    assert_eq!(
        source.stage(&"0".repeat(64), REPLACEMENT.as_bytes()).err(),
        Some(WriteError::Conflict)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
    assert_only_config(directory.path());

    let source = SourceFile::open(&path, LIMIT).unwrap();
    assert_eq!(
        source.replace(REPLACEMENT, || Err(WriteError::Conflict)),
        Err(WriteError::Conflict)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
    assert_only_config(directory.path());
}

#[test]
fn target_edit_during_dependency_admission_is_preserved() {
    let (directory, path) = fixture();
    let source = SourceFile::open(&path, LIMIT).unwrap();
    let external = "# edited while dependencies were being validated\n";
    assert_eq!(
        source.replace(REPLACEMENT, || {
            fs::write(&path, external).unwrap();
            Ok(())
        }),
        Err(WriteError::Conflict)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), external);
    assert_only_config(directory.path());
}

#[test]
fn target_symlinks_are_never_read_or_replaced() {
    let (directory, path) = fixture();
    let source = SourceFile::open(&path, LIMIT).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let private = outside.path().join("private.dae");
    fs::write(&private, "private content").unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&private, &path).unwrap();

    assert!(matches!(
        SourceFile::open(&path, LIMIT),
        Err(WriteError::UnsafePath)
    ));
    assert_eq!(
        source.replace(REPLACEMENT, || panic!("symlink reached admission")),
        Err(WriteError::UnsafePath)
    );
    assert!(
        fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read_to_string(private).unwrap(), "private content");
    assert_only_config(directory.path());
}

#[test]
fn moved_parent_cannot_redirect_writes_or_leave_temporary_files() {
    for replace_with_symlink in [false, true] {
        let outer = tempfile::tempdir().unwrap();
        let parent = outer.path().join("parent");
        let retained = outer.path().join("retained");
        let outside = outer.path().join("outside");
        fs::create_dir(&parent).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(parent.join("config.dae"), ORIGINAL).unwrap();
        fs::write(outside.join("config.dae"), "outside").unwrap();
        let source = SourceFile::open(&parent.join("config.dae"), LIMIT).unwrap();
        fs::rename(&parent, &retained).unwrap();
        if replace_with_symlink {
            symlink(&outside, &parent).unwrap();
        } else {
            fs::create_dir(&parent).unwrap();
            fs::write(parent.join("config.dae"), "new parent").unwrap();
        }

        assert_eq!(
            source.replace(REPLACEMENT, || panic!("changed parent reached admission")),
            Err(if replace_with_symlink {
                WriteError::UnsafePath
            } else {
                WriteError::Conflict
            })
        );
        assert_eq!(
            fs::read_to_string(retained.join("config.dae")).unwrap(),
            ORIGINAL
        );
        assert_eq!(
            fs::read_to_string(outside.join("config.dae")).unwrap(),
            "outside"
        );
        assert_only_config(&retained);
        if !replace_with_symlink {
            assert_eq!(
                fs::read_to_string(parent.join("config.dae")).unwrap(),
                "new parent"
            );
            assert_only_config(&parent);
        }
    }
}

#[test]
fn ancestor_symlinks_are_rejected() {
    let (directory, path) = fixture();
    let outer = tempfile::tempdir().unwrap();
    let link = outer.path().join("link");
    symlink(directory.path(), &link).unwrap();
    fs::create_dir(directory.path().join("nested")).unwrap();
    fs::write(directory.path().join("nested/config.dae"), ORIGINAL).unwrap();
    assert!(matches!(
        SourceFile::open(&link.join("nested/config.dae"), LIMIT),
        Err(WriteError::UnsafePath)
    ));
    assert_eq!(fs::read_to_string(path).unwrap(), ORIGINAL);
}

#[test]
fn reads_and_replacements_enforce_byte_limit_and_regular_utf8_files() {
    let (directory, path) = fixture();
    assert!(matches!(
        SourceFile::open(&path, ORIGINAL.len() - 1),
        Err(WriteError::TooLarge)
    ));
    let source = SourceFile::open(&path, ORIGINAL.len()).unwrap();
    assert_eq!(
        source.replace(REPLACEMENT, || panic!("oversized write reached admission")),
        Err(WriteError::TooLarge)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
    assert_only_config(directory.path());

    fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(matches!(
        SourceFile::open(&path, LIMIT),
        Err(WriteError::InvalidUtf8)
    ));
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(matches!(
        SourceFile::open(&path, LIMIT),
        Err(WriteError::UnsafePath)
    ));
    fs::remove_dir(&path).unwrap();
    nix::unistd::mkfifo(&path, Mode::from_bits_truncate(0o600)).unwrap();
    assert!(matches!(
        SourceFile::open(&path, LIMIT),
        Err(WriteError::UnsafePath)
    ));
}

#[test]
fn file_sync_failure_is_invisible_but_directory_sync_failure_keeps_new_bytes() {
    for fault in [SyncFault::File, SyncFault::Directory] {
        let (directory, path) = fixture();
        let old_inode = fs::metadata(&path).unwrap().ino();
        let mut source = SourceFile::open(&path, LIMIT).unwrap();
        source.sync_fault = Some(fault);
        let mut admitted = false;
        let result = source.replace(REPLACEMENT, || {
            admitted = true;
            assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
            Ok(())
        });
        if fault == SyncFault::File {
            assert_eq!(result, Err(WriteError::Unavailable));
            assert!(!admitted);
            assert_eq!(fs::read_to_string(&path).unwrap(), ORIGINAL);
            assert_eq!(fs::metadata(&path).unwrap().ino(), old_inode);
        } else {
            assert_eq!(result, Err(WriteError::ChangedButNotDurable));
            assert!(admitted);
            assert_eq!(fs::read_to_string(&path).unwrap(), REPLACEMENT);
            assert_ne!(fs::metadata(&path).unwrap().ino(), old_inode);
        }
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o640);
        assert_only_config(directory.path());
    }
}

#[test]
fn binary_staging_preserves_old_files_until_commit_and_reports_directory_failure() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("geosite.dat");
    let second = directory.path().join("geoip.dat");
    fs::write(&first, [0xff, 0, 1]).unwrap();
    fs::write(&second, [0xfe, 0, 2]).unwrap();
    let first_file = SourceFile::open_binary(&first, LIMIT).unwrap();
    let mut second_file = SourceFile::open_binary(&second, LIMIT).unwrap();
    let first_hash = first_file.sha256();
    let second_hash = second_file.sha256();
    second_file.sync_fault = Some(SyncFault::Directory);
    let first_staged = first_file.stage(&first_hash, &[0xff, 3]).unwrap();
    let second_staged = second_file.stage(&second_hash, &[0xfe, 4]).unwrap();
    assert_eq!(fs::read(&first).unwrap(), [0xff, 0, 1]);
    assert_eq!(fs::read(&second).unwrap(), [0xfe, 0, 2]);
    assert!(first_staged.modified_at().is_some());
    let installed = first_staged.replace(|| second_staged.recheck()).unwrap();
    assert!(installed.durability_confirmed);
    installed.file.recheck().unwrap();
    let undurable = second_staged.replace(|| Ok(())).unwrap();
    assert!(!undurable.durability_confirmed);
    undurable.file.recheck().unwrap();
    assert_eq!(fs::read(&first).unwrap(), [0xff, 3]);
    assert_eq!(fs::read(&second).unwrap(), [0xfe, 4]);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
}

#[test]
fn installed_guard_detects_later_replacement_and_content_edits() {
    for rename in [false, true] {
        let (directory, path) = fixture();
        let source = SourceFile::open(&path, LIMIT).unwrap();
        let staged = source
            .stage(
                &crate::configuration::digest(ORIGINAL.as_bytes()),
                REPLACEMENT.as_bytes(),
            )
            .unwrap();
        let installed = staged.replace(|| Ok(())).unwrap();
        installed.file.recheck().unwrap();
        assert_eq!(
            installed.file.sha256(),
            crate::configuration::digest(REPLACEMENT.as_bytes())
        );
        if rename {
            let replacement = directory.path().join("editor.dae");
            fs::write(&replacement, REPLACEMENT).unwrap();
            fs::rename(replacement, &path).unwrap();
        } else {
            fs::write(&path, ORIGINAL).unwrap();
        }
        assert_eq!(installed.file.recheck(), Err(WriteError::Conflict));
    }
}

#[test]
fn staging_beside_creates_a_new_file_and_never_replaces_one() {
    let (packaged, path) = fixture();
    let data = tempfile::tempdir().unwrap();
    let target = data.path().join("config.dae");
    let source = SourceFile::open_binary(&path, LIMIT).unwrap();
    let hash = source.sha256();
    let installed = source
        .stage_beside(&hash, &target, REPLACEMENT.as_bytes())
        .unwrap()
        .replace(|| Ok(()))
        .unwrap();
    assert!(installed.durability_confirmed);
    installed.file.recheck().unwrap();
    assert_eq!(fs::read(&target).unwrap(), REPLACEMENT.as_bytes());
    assert_eq!(fs::read(&path).unwrap(), ORIGINAL.as_bytes());
    assert_only_config(packaged.path());
    assert_only_config(data.path());

    fs::write(&target, "concurrent").unwrap();
    let source = SourceFile::open_binary(&path, LIMIT).unwrap();
    let staged = source
        .stage_beside(&hash, &target, REPLACEMENT.as_bytes())
        .unwrap();
    assert_eq!(staged.replace(|| Ok(())).err(), Some(WriteError::Conflict));
    assert_eq!(fs::read(&target).unwrap(), b"concurrent");
    assert_eq!(fs::read(&path).unwrap(), ORIGINAL.as_bytes());
    assert_only_config(data.path());
}

#[test]
fn staging_beside_refuses_a_swapped_target_directory() {
    let (_packaged, path) = fixture();
    let data = tempfile::tempdir().unwrap();
    let parent = data.path().join("config.d");
    fs::create_dir(&parent).unwrap();
    let source = SourceFile::open_binary(&path, LIMIT).unwrap();
    let hash = source.sha256();
    let staged = source
        .stage_beside(&hash, &parent.join("config.dae"), REPLACEMENT.as_bytes())
        .unwrap();
    let moved = data.path().join("moved.d");
    let result = staged.replace(|| {
        fs::rename(&parent, &moved).unwrap();
        symlink(&moved, &parent).unwrap();
        Ok(())
    });
    assert_eq!(result.err(), Some(WriteError::UnsafePath));
    assert_eq!(fs::read_dir(&moved).unwrap().count(), 0);
    assert_eq!(fs::read(&path).unwrap(), ORIGINAL.as_bytes());
}

#[test]
fn create_new_never_replaces_and_refuses_a_swapped_directory() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("config.d");
    fs::create_dir(&parent).unwrap();
    let target = parent.join("new.dae");
    create_new(&target, REPLACEMENT.as_bytes(), 0o100640, || Ok(())).unwrap();
    assert_eq!(fs::read(&target).unwrap(), REPLACEMENT.as_bytes());
    assert_eq!(fs::metadata(&target).unwrap().mode() & 0o7777, 0o640);
    assert_eq!(
        create_new(&target, ORIGINAL.as_bytes(), 0o640, || Ok(())).err(),
        Some(WriteError::Exists)
    );
    assert_eq!(fs::read(&target).unwrap(), REPLACEMENT.as_bytes());

    let moved = directory.path().join("moved.d");
    let result = create_new(
        &parent.join("other.dae"),
        ORIGINAL.as_bytes(),
        0o640,
        || {
            fs::rename(&parent, &moved).unwrap();
            symlink(&moved, &parent).unwrap();
            Ok(())
        },
    );
    assert_eq!(result.err(), Some(WriteError::UnsafePath));
    let names: Vec<_> = fs::read_dir(&moved)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(names, [OsString::from("new.dae")]);
}

#[test]
fn stale_temporaries_are_removed_and_other_files_kept() {
    let (directory, _) = fixture();
    let stale = directory
        .path()
        .join(format!(".honk-config-{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&stale, "partial").unwrap();
    let foreign = [
        ".honk-config-backup.tmp",
        ".honk-config-00000000-0000-0000-0000-00000000000G.tmp",
        ".honk-config-00000000000000000000000000000000.tmp",
        "honk-config-00000000-0000-0000-0000-000000000000.tmp",
    ];
    for name in foreign {
        fs::write(directory.path().join(name), "keep").unwrap();
    }
    let linked = directory
        .path()
        .join(format!(".honk-config-{}.tmp", uuid::Uuid::new_v4()));
    symlink("config.dae", &linked).unwrap();

    assert_eq!(
        remove_stale_temporaries(directory.path()),
        std::slice::from_ref(&stale)
    );
    assert!(!stale.exists());
    for name in foreign {
        assert!(directory.path().join(name).exists(), "{name}");
    }
    assert!(linked.symlink_metadata().is_ok());
    assert!(remove_stale_temporaries(directory.path()).is_empty());
}
