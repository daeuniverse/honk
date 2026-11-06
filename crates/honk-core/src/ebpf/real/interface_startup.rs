//! Bind configured interfaces before publishing the real backend.
//! Startup binds before backend publication/admission; watcher rounds need async lock handoffs.

use std::os::fd::OwnedFd;
use std::path::Path;

use super::RealEbpfBackend;
use super::interface_state::{self, InterfaceState};
use crate::degradations::Degradations;
use crate::ebpf::interface::status::{BindFailure, ReconcileStep};
use crate::ebpf::interface::{self, InterfacePlan, Topology};

/// What startup hands the watcher: the subscription opened before the first
/// dump (none when the kernel refused it) and the episode/sysctl bookkeeping
/// startup already advanced.
pub(crate) struct InterfaceHandoff {
    pub(super) subscription: Option<OwnedFd>,
    pub(super) state: InterfaceState,
}

/// Fails only when the topology cannot be read (after the bounded dump retry),
/// the default route cannot be read for an `auto` entry, or `load` fails.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_interfaces(
    obj: &[u8],
    pin_root: &Path,
    tproxy_port: u16,
    dae0: &crate::daens::Dae0Setup,
    lan: &[String],
    wan: &[String],
    degradations: &Degradations,
    read_topology: impl Fn(bool) -> anyhow::Result<Topology>,
) -> anyhow::Result<(RealEbpfBackend, InterfaceHandoff)> {
    let subscription = super::iface_watch::subscribe(degradations);
    let mut state = InterfaceState::default();
    let mut topology = read_topology(interface::any_auto(lan, wan)).map_err(|error| {
        error.context("read the network topology for the configured interfaces")
    })?;
    let mut plan = interface::plan(lan, wan, &topology);
    write_sysctls(&mut state, &plan, &topology);
    let mut backend =
        RealEbpfBackend::load(obj, pin_root, tproxy_port, dae0, interface::local_ip(&plan)).await?;

    let mut report = backend.bind_interfaces(&plan, &topology);
    if report.topology_changed {
        match read_topology(interface::any_auto(lan, wan)) {
            Ok(current) => {
                topology = current;
                plan = interface::plan(lan, wan, &topology);
                write_sysctls(&mut state, &plan, &topology);
                report = backend.bind_interfaces(&plan, &topology);
            }
            Err(error) => state.step_failed(ReconcileStep::Topology, &error),
        }
    }
    let owned: Vec<_> = backend
        .owned_bindings()
        .map(|binding| binding.key())
        .collect();
    let failures: Vec<_> = report
        .failed
        .iter()
        .map(|(binding, error)| BindFailure::new(binding, error))
        .collect();
    state.settle(&plan, &owned, &failures, degradations);
    Ok((
        backend,
        InterfaceHandoff {
            subscription,
            state,
        },
    ))
}

/// Startup writes run on the startup task (the only place besides the watcher's
/// blocking step where `sysctl -w` may be spawned).
fn write_sysctls(state: &mut InterfaceState, plan: &InterfacePlan, topology: &Topology) {
    let owed = state.claim_sysctls(plan, topology, tokio::time::Instant::now());
    interface_state::perform(&owed, &interface_state::write_sysctl);
}
