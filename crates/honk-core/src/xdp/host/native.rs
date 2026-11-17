//! Original LOCAL_OUT resources belonging to the existing Host receipt.
use super::{kernel, receipt::Receipt};
use anyhow::{Context as _, ensure};
use honk_netstack::{MemoryBudget, MemoryReservation};
use honk_nfqueue::native::{NativeAction, NativeRoutes};
use honk_xsk::{
    HostNativeCandidate, HostNativeConfig, HostNativeHook, HostNativeLayoutAdmission,
    HostNativeMaps, HostNativePrograms, HostSourceConfig, NativeProgramConfig,
};
use parking_lot::Mutex;
use std::sync::Arc;

pub(crate) struct HostNativeTarget {
    inner: Mutex<Inner>,
    receipt: Arc<Mutex<Receipt>>,
    memory: Vec<MemoryReservation>,
    pub(crate) namespace: u64,
    pub(crate) attachment: u64,
    pub(crate) scope: u64,
    bank: crate::ebpf::host_bank::HostSocketBank,
    custody: Mutex<Option<Arc<super::custody::CustodySnapshot>>>,
    retained_sources: Mutex<Option<usize>>,
}
struct Family {
    programs: HostNativePrograms,
    routes: NativeRoutes,
}
struct Inner {
    families: Vec<Family>,
}
pub(crate) struct HostNativeGeneration {
    programs: Vec<HostNativeCandidate>,
    _memory: std::mem::ManuallyDrop<MemoryReservation>,
}

impl HostNativeTarget {
    pub(super) fn load(
        source: HostSourceConfig,
        scope: u64,
        layout: &kernel::KernelLayout,
        maps: HostNativeMaps<'_>,
        receipt: Arc<Mutex<Receipt>>,
        budget: &Arc<MemoryBudget>,
        pins: &std::path::Path,
    ) -> anyhow::Result<Arc<Self>> {
        let stable = budget
            .reserve(4 << 20)
            .context("Host Native stable owner budget")?;
        let preparation_bytes = HostNativeLayoutAdmission::preparation_memory_bytes()?;
        let _preparation = budget
            .reserve(
                preparation_bytes
                    .checked_add(HostNativePrograms::stable_preparation_memory_bytes())
                    .context("Host Native preparation overflow")?,
            )
            .context("Host Native layout budget")?;
        let mut owner = Self {
            inner: Mutex::new(Inner {
                families: Vec::with_capacity(2),
            }),
            receipt,
            memory: vec![stable],
            namespace: source.source_netns,
            attachment: source.attachment,
            scope,
            bank: crate::ebpf::host_bank::HostSocketBank::map(maps.sockets)?,
            custody: Mutex::new(None),
            retained_sources: Mutex::new(None),
        };
        let mut instance = [0; 16];
        instance[..8].copy_from_slice(&source.source_netns.to_ne_bytes());
        instance[8..].copy_from_slice(&source.attachment.to_ne_bytes());
        for family in [2, 10] {
            let admission = HostNativeLayoutAdmission::read(
                preparation_bytes,
                kernel::symbol("nf_hook_run_bpf")?,
            )?;
            let config = HostNativeConfig {
                source,
                layout: admission.layout(),
                family,
                scope,
            };
            let name = format!(
                "honk_native_{:x}_{:x}_{family}",
                source.source_netns, source.attachment
            );
            let routes = NativeRoutes::prepare(&name, &instance, family)?;
            let intent = owner.receipt.lock().intent(
                "native_hooks",
                serde_json::json!({
                "namespace":source.source_netns,"attachment":source.attachment,"family":family,
                "producer_priority":-452,"binding_priority":-199,"exclusive_unpinned_links":true}),
            )?;
            let programs = HostNativePrograms::load_closed(&config, layout.btf(), maps, admission)?;
            let hooks: Vec<_> = programs
                .hooks()
                .iter()
                .map(|h| {
                    serde_json::json!({
                "family":h.family,"hook":h.hook,"priority":h.priority,"flags":h.flags,
                "program_id":h.program_id,"link_id":h.link_id})
                })
                .collect();
            let ids = programs.map_ids()?;
            let program_bytes = programs.memory_bytes()?;
            owner
                .inner
                .get_mut()
                .families
                .push(Family { programs, routes });
            let producer = owner
                .inner
                .get_mut()
                .families
                .last()
                .expect("retained Host family")
                .programs
                .producer();
            let path = pins.join(format!("native-producer-{family}"));
            let pin = owner
                .receipt
                .lock()
                .intent("raw_program", serde_json::json!({"pin_path":path}))?;
            super::sys::pin(producer.0, &path)?;
            let actual = super::sys::newly_pinned_id(&path)?;
            ensure!(
                actual == producer.1,
                "Host Native producer pin identity changed"
            );
            owner
                .receipt
                .lock()
                .acknowledge(pin, serde_json::json!({"program_id":actual}))?;
            owner.receipt.lock().acknowledge(
                intent,
                serde_json::json!({"hooks":hooks,"maps":ids,
                "program_bytes":program_bytes,"stable_reserved_bytes":4usize << 20}),
            )?;
        }
        let measured = owner
            .inner
            .get_mut()
            .families
            .iter()
            .try_fold(0usize, |sum, f| {
                sum.checked_add(f.programs.memory_bytes()?)
                    .context("Host Native stable allocation overflow")
            })?;
        ensure!(
            measured <= 4 << 20,
            "Host Native stable allocations exceed admission"
        );
        Ok(Arc::new(owner))
    }

    pub(crate) fn set_custody(
        &self,
        custody: Arc<super::custody::CustodySnapshot>,
    ) -> anyhow::Result<()> {
        let mut slot = self.custody.lock();
        ensure!(slot.is_none(), "Host Native custody already registered");
        *slot = Some(custody);
        Ok(())
    }
    pub(crate) fn check_publication(&self) -> anyhow::Result<()> {
        self.check()?;
        if let Some(custody) = self.custody.lock().as_ref() {
            custody.revalidate()?;
        }
        Ok(())
    }
    pub(crate) fn source_alive(
        &self,
        key: &honk_ebpf_common::xdp::NativeKey,
        claim: &honk_ebpf_common::xdp::NativeClaim,
    ) -> anyhow::Result<bool> {
        ensure!(
            key.namespace_cookie == self.namespace
                && claim.attachment_generation == self.attachment
                && claim.scope == self.scope,
            "Host Native source namespace/attachment/scope mismatch"
        );
        let bucket =
            (claim.owner_cookie & (honk_ebpf_common::host::HOST_SOCKET_BUCKETS as u64 - 1)) as u32;
        Ok(self
            .bank
            .read(bucket)?
            .value
            .iter()
            .any(|entry| retains_source_attempt(entry, key, claim)))
    }
    pub(crate) fn retained_sources(&self) -> Option<usize> {
        *self.retained_sources.lock()
    }
    pub(crate) fn record_retained_sources(&self, count: Option<usize>) {
        *self.retained_sources.lock() = count;
    }
    pub(crate) fn preparation_memory_bytes(
        bytecode: usize,
        actions: usize,
    ) -> anyhow::Result<usize> {
        Ok(
            HostNativePrograms::preparation_memory_bytes(bytecode, actions)?
                .checked_add(honk_nfqueue::native::MAX_REQUEST_BYTES)
                .and_then(|v| v.checked_add(honk_nfqueue::native::MAX_READBACK_BYTES))
                .context("Host Native staging overflow")?,
        )
    }
    pub(crate) fn generation_memory_bytes(
        &self,
        config: &NativeProgramConfig<'_>,
        actions: &[Option<u32>],
    ) -> anyhow::Result<usize> {
        let inner = self.inner.lock();
        let programs = inner.families.iter().try_fold(0usize, |sum, family| {
            sum.checked_add(family.programs.program_memory_bytes(config, actions)?)
                .context("Host Native program allocation overflow")
        })?;
        programs
            .checked_add(route_memory_bytes(actions.len(), inner.families.len())?)
            .context("Host Native generation allocation overflow")
    }
    pub(crate) fn prepare(
        &self,
        config: &NativeProgramConfig<'_>,
        actions: &[Option<u32>],
        memory: MemoryReservation,
    ) -> anyhow::Result<HostNativeGeneration> {
        let mut generation = HostNativeGeneration {
            programs: Vec::with_capacity(2),
            _memory: std::mem::ManuallyDrop::new(memory),
        };
        for family in &self.inner.lock().families {
            generation
                .programs
                .push(family.programs.prepare(config, actions)?);
        }
        let measured = generation.programs.iter().try_fold(
            route_memory_bytes(actions.len(), generation.programs.len())?,
            |sum, program| {
                sum.checked_add(program.memory_bytes())
                    .context("Host Native actual allocation overflow")
            },
        )?;
        ensure!(
            measured <= generation._memory.bytes(),
            "Host Native actual allocation exceeds its prepared reservation"
        );
        Ok(generation)
    }
    pub(crate) fn publish(&self, candidate: &HostNativeGeneration) -> anyhow::Result<()> {
        let mut inner = self.inner.lock();
        ensure!(
            inner.families.len() == candidate.programs.len(),
            "Host Native family mismatch"
        );
        for (family, programs) in inner.families.iter_mut().zip(&candidate.programs) {
            let mut receipt = self.receipt.lock();
            let intent = receipt.intent("native_routes", serde_json::json!({
                "before":route_evidence(family.routes.receipt()),"epoch":programs.epoch,
                "scope":programs.scope,"selector_id":programs.selector_id(),
                "program_bytes":programs.memory_bytes(),"generation_reserved_bytes":candidate._memory.bytes(),
                "family_nft_kernel_bound_bytes":NativeRoutes::kernel_memory_bound(programs.actions().len())?,
                "family_nft_userspace_bound_bytes":NativeRoutes::userspace_memory_bound(programs.actions().len())?}))?;
            let actions: Vec<_> = programs
                .actions()
                .map(|(mark, matcher, _)| NativeAction { matcher, mark })
                .collect();
            let result = if family.routes.receipt().install_attempted {
                family
                    .routes
                    .replace(&actions, programs.candidate_scope().0)
            } else {
                family
                    .routes
                    .install(&actions, programs.candidate_scope().0)
            };
            // Preserve pending handles and ACK state even on an unsuccessful prefix.
            receipt.acknowledge(
                intent,
                serde_json::json!({"routes":route_evidence(family.routes.receipt()),
                "complete":result.is_ok()}),
            )?;
            result?;
            drop(receipt);
            family.programs.publish_selector(programs)?;
        }
        Ok(())
    }
    pub(crate) fn check(&self) -> anyhow::Result<()> {
        for family in &self.inner.lock().families {
            family.programs.check_links()?;
            if family.routes.receipt().install_attempted {
                family.routes.check()?;
            }
        }
        Ok(())
    }
    pub(crate) fn hooks(&self) -> Vec<HostNativeHook> {
        self.inner
            .lock()
            .families
            .iter()
            .flat_map(|f| f.programs.hooks().iter().copied())
            .collect()
    }
    pub(crate) fn tables(&self) -> Vec<(u8, String, [u8; 16])> {
        self.inner
            .lock()
            .families
            .iter()
            .filter(|f| f.routes.receipt().active.is_some())
            .map(|f| {
                let r = f.routes.receipt();
                (r.family, r.table.clone(), r.owner)
            })
            .collect()
    }
    pub(crate) fn close_admission(&self) -> anyhow::Result<()> {
        for family in &self.inner.lock().families {
            family.programs.close_admission()?;
        }
        Ok(())
    }
    pub(crate) fn finish_close(&self) -> anyhow::Result<()> {
        ensure!(
            self.retained_sources() == Some(0),
            "Host Native source custody has not joined; retaining hooks and rules"
        );
        self.check_publication()?;
        let mut inner = self.inner.lock();
        for family in &mut inner.families {
            family.programs.check_links()?;
            let mut receipt = self.receipt.lock();
            let intent =
                receipt.intent("native_remove", route_evidence(family.routes.receipt()))?;
            let result = family.routes.remove();
            receipt.acknowledge(intent, route_evidence(family.routes.receipt()))?;
            result?;
            family.programs.detach_links()?;
        }
        Ok(())
    }
}

fn retains_source_attempt(
    entry: &honk_ebpf_common::host::HostSocketEntry,
    key: &honk_ebpf_common::xdp::NativeKey,
    claim: &honk_ebpf_common::xdp::NativeClaim,
) -> bool {
    entry.cookie == claim.owner_cookie
        && !(key.l4proto == 6
            && entry.selection == honk_ebpf_common::host::HOST_SOCKET_NATIVE
            && entry.operation_incarnation > claim.owner_incarnation)
}

impl Drop for HostNativeTarget {
    fn drop(&mut self) {
        for memory in self.memory.drain(..) {
            std::mem::forget(memory);
        }
    }
}
fn route_memory_bytes(actions: usize, families: usize) -> anyhow::Result<usize> {
    let rules = NativeRoutes::kernel_memory_bound(actions)?
        .checked_mul(families)
        .context("Host Native nft allocation overflow")?;
    ensure!(
        rules.checked_mul(2).is_some_and(|v| v <= 4 << 20),
        "Host Native active/candidate nft generations exceed 4MiB partition"
    );
    NativeRoutes::userspace_memory_bound(actions)?
        .checked_mul(families)
        .and_then(|userspace| rules.checked_add(userspace))
        .context("Host Native rule owner allocation overflow")
}
fn route_evidence(r: &honk_nfqueue::native::NativeReceipt) -> serde_json::Value {
    fn generation(g: &honk_nfqueue::native::NativeGenerationReceipt) -> serde_json::Value {
        serde_json::json!({"generation":g.generation,"mutation_acked":g.mutation_acked,
            "rules":g.rules.iter().map(|r| serde_json::json!({"handle":r.handle,"userdata":r.userdata,
                "matcher_program_id":r.matcher_program_id,"matcher_tag":r.matcher_tag,
                "mark":r.mark,"candidate_scope":r.candidate_scope,"conntrack_anchor":r.conntrack_anchor,
                "expressions":r.expressions})).collect::<Vec<_>>()})
    }
    serde_json::json!({"table":r.table,"chain":r.chain,"family":r.family,"owner":r.owner,
        "socket_receive_bytes":r.socket_receive_bytes,"socket_send_bytes":r.socket_send_bytes,
        "table_handle":r.table_handle,"chain_handle":r.chain_handle,"table_create_acked":r.table_create_acked,
        "install_attempted":r.install_attempted,"removing":r.removing,"remove_acked":r.remove_acked,
        "removed":r.removed,"active":r.active.as_ref().map(generation),"pending":r.pending.as_ref().map(generation)})
}
#[cfg(test)]
mod tests {
    use super::*;
    use honk_ebpf_common::host::{
        HOST_SOCKET_ENDPOINT, HOST_SOCKET_NATIVE, HOST_SOCKET_TRANSITION, HostSocketEntry,
    };
    use honk_ebpf_common::xdp::{NativeClaim, NativeKey};

    #[test]
    fn only_a_newer_native_tcp_attempt_ends_the_old_source() {
        let claim = NativeClaim {
            owner_cookie: 7,
            owner_incarnation: 4,
            ..NativeClaim::default()
        };
        for (protocol, selection, incarnation, retained) in [
            (6, HOST_SOCKET_NATIVE, 4, true),
            (6, HOST_SOCKET_NATIVE, 3, true),
            (6, HOST_SOCKET_NATIVE, 5, false),
            (17, HOST_SOCKET_NATIVE, 5, true),
            (6, HOST_SOCKET_ENDPOINT, 5, true),
            (6, HOST_SOCKET_TRANSITION, 5, true),
        ] {
            let key = NativeKey {
                l4proto: protocol,
                ..NativeKey::default()
            };
            let entry = HostSocketEntry {
                cookie: 7,
                operation_incarnation: incarnation,
                selection,
                ..HostSocketEntry::default()
            };
            assert_eq!(retains_source_attempt(&entry, &key, &claim), retained);
        }
    }
}
