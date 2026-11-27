use aya_ebpf::{btf_maps::SkStorage, macros::btf_map};
use honk_ebpf_common::host::{HostSkDecision, HostSkIdentity};

#[btf_map]
pub static HOST_SK_IDENTITY: SkStorage<HostSkIdentity> = SkStorage::new();
#[btf_map]
pub static HOST_SK_DECISION: SkStorage<HostSkDecision> = SkStorage::new();
