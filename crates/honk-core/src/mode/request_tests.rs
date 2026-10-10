use super::*;
use crate::observe::catalog::Catalog;
use crate::{
    ebpf::{EbpfBackend, mock::MockEbpfBackend},
    mode::{ModeOverride, SharedModeState},
};
use honk_config::{Config, node::Node};
use std::sync::Arc;

type Backend = Arc<tokio::sync::RwLock<Box<dyn EbpfBackend>>>;

fn config() -> Config {
    let mut config = Config::default();
    config.experimental.native_api.enabled = true;
    config.nodes = vec![
        Node {
            id: uuid::Uuid::from_u128(1),
            name: "duplicate".into(),
            ..Default::default()
        },
        Node {
            id: uuid::Uuid::from_u128(2),
            name: "duplicate".into(),
            ..Default::default()
        },
    ];
    config.groups.push(honk_config::group::Group {
        name: "Proxy".into(),
        nodes: vec![config.nodes[0].id],
        ..Default::default()
    });
    config.ensure_builtin_nodes();
    config
}

async fn owner(
    mode: ModeState,
    cache: Option<Arc<crate::state::cache::CacheDb>>,
) -> (DatapathFlagsHandle, Backend) {
    let backend: Backend = Arc::new(tokio::sync::RwLock::new(Box::new(MockEbpfBackend::new())));
    let state: SharedModeState = Arc::new(parking_lot::RwLock::new(mode));
    let flags = DatapathFlagsHandle::new(backend.clone(), state, cache);
    flags.initialize(true, true).await.unwrap();
    (flags, backend)
}

#[tokio::test]
async fn native_mode_and_target_publish_once_and_failure_preserves_both() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
    };
    let config = config();
    let catalog = Catalog::new(&config);
    let identity = catalog.snapshot();
    let (flags, backend) = owner(ModeState::native(), None).await;
    let first = flags
        .set_clash_mode("Global", &config, &identity.groups)
        .await
        .unwrap();
    assert!(first.is_global());
    assert!(
        matches!(&first.selection, Selection::Target(Some(ModeTarget::Group { id, .. })) if *id == identity.groups["Proxy"])
    );
    assert_eq!(first.source, ModeSource::Runtime);
    assert_eq!(backend.read().await.datapath_flags_write_log().len(), 2);
    assert_eq!(
        backend.read().await.datapath_flags_write_log()[1],
        ENABLED | READY
    );
    let before = flags.snapshot();
    backend
        .write()
        .await
        .arm_datapath_flags_write_fault(1)
        .unwrap();
    assert!(
        flags
            .set_clash_mode("Direct", &config, &identity.groups)
            .await
            .is_err()
    );
    let after = flags.snapshot();
    assert_eq!(after.mode, before.mode);
    assert_eq!(after.selection, before.selection);
    assert_eq!(after.source, before.source);
    assert!(
        backend
            .read()
            .await
            .datapath_flags_write_trace()
            .last()
            .unwrap()
            .failed
    );
}

#[tokio::test]
async fn concurrent_fence_and_atomic_mode_write_never_reopen_nfqueue() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
        DATAPATH_FLAG_OFFLOAD_ALL as ALL,
    };
    let config = config();
    let catalog = Catalog::new(&config);
    let identity = catalog.snapshot();
    let (flags, backend) = owner(ModeState::native(), None).await;
    let (mode, fence) = tokio::join!(
        flags.set_clash_mode("Direct", &config, &identity.groups),
        flags.fence_nfqueue(),
    );
    mode.unwrap();
    fence.unwrap();
    assert_eq!(
        backend
            .read()
            .await
            .datapath_flags_write_log()
            .last()
            .copied(),
        Some(ALL | ENABLED)
    );
    flags
        .set_clash_mode("Global", &config, &identity.groups)
        .await
        .unwrap();
    assert_eq!(
        backend
            .read()
            .await
            .datapath_flags_write_log()
            .last()
            .copied(),
        Some(ENABLED)
    );
    assert_eq!(
        backend
            .read()
            .await
            .datapath_flags_write_log()
            .last()
            .unwrap()
            & READY,
        0
    );
}

#[tokio::test]
async fn refresh_retains_identity_and_missing_or_recreated_targets_fail_closed() {
    let mut config = config();
    assert!(
        ModeTarget::from_name(
            "duplicate",
            &config,
            &Catalog::new(&config).snapshot().groups
        )
        .is_none()
    );
    config.nodes[1].name = "chosen".into();
    let catalog = Catalog::new(&config);
    let (flags, _) = owner(ModeState::native(), None).await;
    let chosen = config.nodes[1].id;
    flags
        .set_clash_global_selection("chosen".into(), &config, &catalog.snapshot().groups)
        .await
        .unwrap();
    flags
        .set_clash_mode("Global", &config, &catalog.snapshot().groups)
        .await
        .unwrap();
    assert_eq!(
        flags
            .snapshot()
            .native_override("direct", false, &config, &catalog.snapshot().groups),
        ModeOverride::Node(chosen)
    );
    config.nodes[1].name = "renamed".into();
    catalog.install(&config);
    assert_eq!(
        flags
            .snapshot()
            .native_override("direct", false, &config, &catalog.snapshot().groups),
        ModeOverride::Node(chosen)
    );
    config.nodes.remove(1);
    catalog.install(&config);
    assert_eq!(
        flags
            .snapshot()
            .native_override("direct", false, &config, &catalog.snapshot().groups),
        ModeOverride::Block
    );
    assert_eq!(flags.snapshot().source, ModeSource::Runtime);
    assert!(
        matches!(flags.snapshot().selection, Selection::Target(Some(ModeTarget::Node { id, .. })) if id == chosen)
    );

    let group_id = catalog.snapshot().groups["Proxy"].clone();
    flags
        .set_clash_global_selection("Proxy".into(), &config, &catalog.snapshot().groups)
        .await
        .unwrap();
    let group = config.groups.remove(0);
    catalog.install(&config);
    assert_eq!(
        flags
            .snapshot()
            .native_override("direct", false, &config, &catalog.snapshot().groups),
        ModeOverride::Block
    );
    config.groups.push(group);
    catalog.install(&config);
    assert_ne!(catalog.snapshot().groups["Proxy"], group_id);
    assert_eq!(
        flags
            .snapshot()
            .native_override("direct", false, &config, &catalog.snapshot().groups),
        ModeOverride::Block
    );
    assert!(
        flags
            .set_clash_mode("Global", &config, &catalog.snapshot().groups)
            .await
            .is_err()
    );
    for (outbound, must) in [("direct", true), ("Proxy", true), ("block", false)] {
        assert_eq!(
            flags
                .snapshot()
                .native_override(outbound, must, &config, &catalog.snapshot().groups),
            ModeOverride::Unchanged
        );
    }
}

#[tokio::test]
async fn explicit_activation_reset_is_transactional_and_keeps_the_fence() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_OFFLOAD_RULE_DIRECT as RULE,
        DATAPATH_FLAG_TRACE_ENABLED as TRACE,
    };
    let config = config();
    let catalog = Catalog::new(&config);
    let (flags, backend) = owner(ModeState::native(), None).await;
    flags.reconcile_kernel_trace(|| true).await.unwrap();
    flags
        .set_clash_mode("Direct", &config, &catalog.snapshot().groups)
        .await
        .unwrap();
    flags.fence_nfqueue().await.unwrap();
    {
        let mut publication = flags.publication().await;
        let mut backend = backend.write().await;
        backend.arm_datapath_flags_write_fault(1).unwrap();
        assert!(publication.reset_for_activation(backend.as_mut()).is_err());
        assert_eq!(flags.snapshot().mode, "Direct");
        assert_eq!(flags.snapshot().source, ModeSource::Runtime);
        publication.reset_for_activation(backend.as_mut()).unwrap();
        assert_eq!(flags.snapshot().mode, "Rule");
        assert_eq!(flags.snapshot().source, ModeSource::Config);
        assert_eq!(flags.snapshot().selection, Selection::Target(None));
        assert_eq!(
            backend.datapath_flags_write_log().last().copied(),
            Some(RULE | ENABLED | TRACE)
        );
    }
    // A no-op explicit activation has the same reset semantics; ordinary reads do not.
    flags
        .set_clash_mode("Rule", &config, &catalog.snapshot().groups)
        .await
        .unwrap();
    assert_eq!(flags.snapshot().source, ModeSource::Runtime);
    flags
        .publication()
        .await
        .reset_for_activation(backend.write().await.as_mut())
        .unwrap();
    assert_eq!(flags.snapshot().source, ModeSource::Config);
}

#[tokio::test]
async fn native_clash_mutations_do_not_restore_or_persist_legacy_mode_cache() {
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(crate::state::cache::CacheDb::in_dir(directory.path()));
    db.save_clash_mode("Direct");
    db.save_clash_global("old-choice");
    let config = config();
    let catalog = Catalog::new(&config);
    let (native, _) = owner(ModeState::native(), Some(db.clone())).await;
    assert!(native.snapshot().is_rule());
    assert_eq!(native.snapshot().source, ModeSource::Config);
    native
        .set_clash_global_selection("Proxy".into(), &config, &catalog.snapshot().groups)
        .await
        .unwrap();
    native
        .set_clash_mode("Global", &config, &catalog.snapshot().groups)
        .await
        .unwrap();
    assert!(
        matches!(native.snapshot().selection, Selection::Target(Some(ModeTarget::Group { id, .. })) if id == catalog.snapshot().groups["Proxy"])
    );
    assert_eq!(native.snapshot().source, ModeSource::Runtime);
    assert_eq!(db.load_clash_mode().as_deref(), Some("Direct"));
    assert_eq!(db.load_clash_global().as_deref(), Some("old-choice"));
    assert!(native.set_mode("Rule").await.is_err());
    assert!(native.set_global_selection("Proxy".into()).await.is_err());

    let (legacy, backend) = owner(ModeState::new("Direct", "old-choice"), Some(db.clone())).await;
    legacy.set_mode("Global").await.unwrap();
    legacy.set_global_selection("Proxy".into()).await.unwrap();
    assert_eq!(db.load_clash_mode().as_deref(), Some("Global"));
    assert_eq!(db.load_clash_global().as_deref(), Some("Proxy"));
    legacy
        .publication()
        .await
        .reset_for_activation(backend.write().await.as_mut())
        .unwrap();
    assert_eq!(legacy.snapshot().mode, "Global");
    assert_eq!(
        legacy.snapshot().override_outbound("other", false, false),
        "other"
    );
}

#[tokio::test]
async fn unknown_mode_target_never_mutates_the_owner() {
    let config = config();
    let catalog = Catalog::new(&config);
    let (flags, backend) = owner(ModeState::native(), None).await;
    assert!(
        flags
            .set_clash_global_selection("missing".into(), &config, &catalog.snapshot().groups)
            .await
            .is_err()
    );
    assert_eq!(flags.snapshot().mode, "Rule");
    assert_eq!(flags.snapshot().source, ModeSource::Config);
    assert_eq!(backend.read().await.datapath_flags_write_log().len(), 1);
}

#[tokio::test]
async fn incomplete_fence_blocks_mode_ready_resurrection_and_explicit_reopen() {
    use honk_ebpf_common::{
        DATAPATH_FLAG_NFQ_ENABLED as ENABLED, DATAPATH_FLAG_NFQ_READY as READY,
        DATAPATH_FLAG_OFFLOAD_ALL as ALL,
    };
    let config = config();
    let catalog = Catalog::new(&config);
    let (flags, backend) = owner(ModeState::native(), None).await;
    backend.write().await.arm_quiesce_fault();
    assert!(flags.fence_nfqueue().await.is_err());
    flags
        .set_clash_mode("Direct", &config, &catalog.snapshot().groups)
        .await
        .unwrap();
    assert_eq!(
        backend
            .read()
            .await
            .datapath_flags_write_log()
            .last()
            .copied(),
        Some(ALL | ENABLED)
    );
    let written = backend.read().await.datapath_flags_write_log().len();
    assert!(flags.reopen_nfqueue().await.is_err());
    assert_eq!(
        backend.read().await.datapath_flags_write_log().len(),
        written
    );
    flags.fence_nfqueue().await.unwrap();
    flags.reopen_nfqueue().await.unwrap();
    assert_eq!(
        backend
            .read()
            .await
            .datapath_flags_write_log()
            .last()
            .copied(),
        Some(ALL | ENABLED | READY)
    );
}
