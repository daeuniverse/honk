use std::collections::HashMap;
use std::os::fd::AsFd;
use std::sync::Arc;

use aya::Ebpf;
use aya::maps::{Map, MapData};
use parking_lot::Mutex;

use super::bindings::PreparedTcProgram;
use crate::ebpf::interface::TcProgram;

pub(super) type KernelMaps = HashMap<String, Map>;
pub(crate) type TcProgramBatch = Vec<(TcProgram, anyhow::Result<PreparedTcProgram>)>;
pub(crate) type TcProgramPreparation = Box<dyn FnOnce() -> TcProgramBatch + Send>;

#[cfg(test)]
#[derive(Default)]
pub(crate) struct TcProgramPreparationFixture(pub Mutex<Option<TcProgramPreparation>>);

#[cfg(test)]
impl std::fmt::Debug for TcProgramPreparationFixture {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcProgramPreparationFixture")
            .field("pending", &self.0.lock().is_some())
            .finish()
    }
}
#[cfg(feature = "native-api")]
pub(crate) type ReceiveTracePreparation =
    Box<dyn FnOnce() -> Option<Arc<super::receive_trace::ReceiveTrace>> + Send>;

/// Owns the original relocation FDs even when a blocking load outlives its caller.
pub(super) struct ProgramLoader {
    object: Mutex<Ebpf>,
    _maps: KernelMaps,
    #[cfg(feature = "native-api")]
    trace: Mutex<TraceState>,
    #[cfg(feature = "native-api")]
    trace_available: bool,
}

#[cfg(feature = "native-api")]
#[derive(Default)]
struct TraceState {
    result: Option<Option<Arc<super::receive_trace::ReceiveTrace>>>,
    closed: bool,
}

/// Consumers must not own the FD numbers already embedded in unloaded bytecode.
pub(super) fn retain_consumer_maps(bpf: &mut Ebpf) -> anyhow::Result<KernelMaps> {
    let mut originals = KernelMaps::new();
    for name in ["AYA_LOGS", "EVENT_RINGBUF", "TCP_LIVE_PINS"] {
        let Some(map) = bpf.map_mut(name) else {
            continue;
        };
        let data = match map {
            Map::RingBuf(data) | Map::HashMap(data) => data,
            _ => anyhow::bail!("consumer map '{name}' has an incompatible type"),
        };
        let duplicate = MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?;
        let duplicate = Map::from_map_data(duplicate)?;
        originals.insert(name.to_owned(), std::mem::replace(map, duplicate));
    }
    Ok(originals)
}

impl ProgramLoader {
    pub(super) fn new(
        mut object: Ebpf,
        mut maps: KernelMaps,
        #[cfg(feature = "native-api")] trace_available: bool,
    ) -> anyhow::Result<(Arc<Self>, KernelMaps)> {
        let names: Vec<_> = object.maps().map(|(name, _)| name.to_owned()).collect();
        for name in names {
            // A retained consumer original takes precedence over its duplicate.
            maps.entry(name.clone())
                .or_insert_with(|| object.take_map(&name).expect("enumerated object map"));
        }
        let backend_maps = maps
            .iter()
            .map(|(name, map)| {
                let data = super::syscall::map_data(map);
                let duplicate = MapData::from_fd(data.fd().as_fd().try_clone_to_owned()?)?;
                Ok((name.clone(), Map::from_map_data(duplicate)?))
            })
            .collect::<anyhow::Result<KernelMaps>>()?;
        let loader = Arc::new(Self {
            object: Mutex::new(object),
            _maps: maps,
            #[cfg(feature = "native-api")]
            trace: Mutex::new(TraceState::default()),
            #[cfg(feature = "native-api")]
            trace_available,
        });
        Ok((loader, backend_maps))
    }

    pub(super) fn startup_object_mut(&mut self) -> &mut Ebpf {
        self.object.get_mut()
    }

    pub(super) fn try_object(&self) -> Option<parking_lot::MutexGuard<'_, Ebpf>> {
        self.object.try_lock()
    }

    #[cfg(test)]
    pub(super) fn object(&self) -> parking_lot::MutexGuard<'_, Ebpf> {
        self.object.lock()
    }

    pub(super) fn prepare(self: &Arc<Self>, programs: Vec<TcProgram>) -> TcProgramPreparation {
        let loader = Arc::clone(self);
        Box::new(move || {
            let mut object = loader.object.lock();
            programs
                .into_iter()
                .map(|program| (program, PreparedTcProgram::load(&mut object, program)))
                .collect()
        })
    }

    #[cfg(feature = "native-api")]
    pub(super) fn prepare_receive_trace(self: &Arc<Self>) -> ReceiveTracePreparation {
        let loader = Arc::clone(self);
        Box::new(move || {
            let mut object = loader.object.lock();
            {
                let state = loader.trace.lock();
                if state.closed {
                    return None;
                }
                if let Some(result) = &state.result {
                    return result.clone();
                }
            }
            let result = if !loader.trace_available {
                tracing::warn!(
                    ipv4_unavailable = true,
                    ipv6_unavailable = true,
                    "kernel UDP trace unavailable: checked BTF offsets missing"
                );
                None
            } else {
                let result = super::btf::load_kernel().and_then(|(_, btf)| {
                    super::receive_trace::ReceiveTrace::attach(
                        &mut object,
                        &btf,
                        loader._maps.get("RECEIVE_TRACE"),
                    )
                });
                match result {
                    Ok(trace) => Some(trace),
                    Err(error) => {
                        tracing::warn!(
                            error = %format_args!("{error:#}"),
                            ipv4_unavailable = true,
                            ipv6_unavailable = true,
                            "kernel UDP trace attach unavailable"
                        );
                        None
                    }
                }
            };
            let mut state = loader.trace.lock();
            if state.closed {
                return None;
            }
            state.result = Some(result.clone());
            result
        })
    }

    #[cfg(feature = "native-api")]
    pub(super) fn close_receive_trace(&self) {
        let result = {
            let mut state = self.trace.lock();
            state.closed = true;
            state.result.take()
        };
        drop(result);
    }
}
