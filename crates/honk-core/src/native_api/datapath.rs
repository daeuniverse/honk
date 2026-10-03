//! One projection of backend-owned observations for runtime and datapath reads.

use super::{
    NativeState, full_detail, parse_query, timestamp,
    types::{ApiError, DatapathSummary, RequestId},
};
use crate::ebpf::{DatapathCheck, DatapathKind, DatapathObservation, DatapathObservationError};
use axum::{
    Json,
    http::Uri,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::{sync::atomic::Ordering, time::SystemTime};

#[derive(Clone, Serialize)]
pub(super) struct EbpfSummary {
    backend: &'static str,
    programs: &'static str,
    hooks: &'static str,
    routing: RoutingSummary,
    health: &'static str,
    last_error: Option<&'static str>,
    checked_at: String,
}

#[derive(Clone, Serialize)]
struct RoutingSummary {
    state: &'static str,
    generation_id: Option<String>,
    epoch: Option<String>,
}

#[derive(Serialize)]
struct Datapath {
    observed_at: String,
    kind: &'static str,
    state: &'static str,
    visibility: &'static str,
    ebpf: Option<EbpfDetail>,
    errors: Vec<SafeError>,
}

/// The kernel detail is optional in the contract: `detail=summary` (the
/// default) answers without attachments and maps.
#[derive(Serialize)]
struct EbpfDetail {
    #[serde(flatten)]
    summary: EbpfSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    attachments: Option<Vec<Attachment>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    maps: Option<Maps>,
}

#[derive(Serialize)]
struct Attachment {
    name: String,
    /// honk reports only its tc attachments.
    kind: &'static str,
    interface: String,
    direction: &'static str,
    state: &'static str,
}

#[derive(Serialize)]
struct Maps {
    state: &'static str,
    conn_state: Option<MapOccupancy>,
}

#[derive(Serialize)]
struct MapOccupancy {
    occupancy: Option<u32>,
    capacity: u32,
    occupancy_known: bool,
}

#[derive(Serialize)]
struct SafeError {
    code: &'static str,
    message: &'static str,
}

fn safe_error(error: DatapathObservationError) -> SafeError {
    let (code, message) = match error {
        DatapathObservationError::Programs => (
            "program_observation_failed",
            "Program state could not be verified.",
        ),
        DatapathObservationError::Hooks => (
            "hook_observation_incomplete",
            "One or more owned hooks could not be verified.",
        ),
        DatapathObservationError::Routing => (
            "routing_observation_failed",
            "The routing root could not be matched to its owner.",
        ),
        DatapathObservationError::Admission => (
            "admission_observation_failed",
            "Datapath admission could not be verified.",
        ),
        DatapathObservationError::Maps => (
            "map_observation_failed",
            "Map metadata could not be verified.",
        ),
        DatapathObservationError::Limit => (
            "observation_limit_reached",
            "The bounded datapath observation is incomplete.",
        ),
    };
    SafeError { code, message }
}

pub(super) fn summary(
    observation: &DatapathObservation,
    instance: &str,
    healthy: bool,
) -> DatapathSummary {
    let kind = match observation.kind {
        DatapathKind::Real => "ebpf",
        DatapathKind::Mock => "mock",
        DatapathKind::Unknown => "unknown",
    };
    if observation.kind != DatapathKind::Real {
        return DatapathSummary {
            kind,
            state: if observation.kind == DatapathKind::Mock {
                "disabled"
            } else {
                "unknown"
            },
            visibility: "none",
            ebpf: None,
        };
    }
    let verified = healthy
        && observation.programs == DatapathCheck::Verified
        && observation.hooks == DatapathCheck::Verified
        && observation.routing == DatapathCheck::Verified
        && observation.routing_generation.is_some()
        && observation.admission == Some(true)
        && observation.listeners_published == Some(true)
        && observation.conn_state_capacity.is_some()
        && observation.errors.is_empty();
    let state = if !healthy || !observation.errors.is_empty() {
        "degraded"
    } else if observation.programs == DatapathCheck::Absent
        || observation.hooks == DatapathCheck::Absent
    {
        "detached"
    } else if observation.admission == Some(false) {
        "disabled"
    } else if verified {
        "active"
    } else {
        "unknown"
    };
    DatapathSummary {
        kind,
        state,
        visibility: "partial",
        ebpf: Some(EbpfSummary {
            backend: "real",
            programs: match observation.programs {
                DatapathCheck::Verified => "loaded",
                DatapathCheck::Absent => "not_loaded",
                DatapathCheck::Error => "error",
                DatapathCheck::Unknown => "unknown",
            },
            hooks: match observation.hooks {
                DatapathCheck::Verified => "attached",
                DatapathCheck::Absent => "detached",
                _ if observation
                    .attachments
                    .iter()
                    .any(|attachment| attachment.state == DatapathCheck::Absent) =>
                {
                    "partially_attached"
                }
                _ => "unknown",
            },
            routing: RoutingSummary {
                state: match observation.routing {
                    DatapathCheck::Verified => "published",
                    DatapathCheck::Absent => "not_published",
                    DatapathCheck::Error => "error",
                    DatapathCheck::Unknown => "unknown",
                },
                generation_id: observation
                    .routing_generation
                    .filter(|_| observation.routing == DatapathCheck::Verified)
                    .map(|generation| format!("{instance}:datapath:{generation}")),
                epoch: None,
            },
            health: if verified {
                "healthy"
            } else if state == "degraded" {
                "degraded"
            } else {
                "unknown"
            },
            last_error: observation
                .errors
                .last()
                .map(|error| safe_error(*error).code),
            checked_at: timestamp(observation.checked_at),
        }),
    }
}

fn detail(observation: DatapathObservation, instance: &str, healthy: bool, full: bool) -> Datapath {
    let summary = summary(&observation, instance, healthy);
    Datapath {
        observed_at: timestamp(SystemTime::now()),
        kind: summary.kind,
        state: summary.state,
        visibility: summary.visibility,
        ebpf: summary.ebpf.map(|summary| EbpfDetail {
            summary,
            attachments: full.then(|| {
                observation
                    .attachments
                    .into_iter()
                    .map(|attachment| Attachment {
                        name: attachment.program,
                        kind: "interface",
                        interface: attachment.interface,
                        direction: if attachment.egress {
                            "egress"
                        } else {
                            "ingress"
                        },
                        state: match attachment.state {
                            DatapathCheck::Verified => "attached",
                            DatapathCheck::Absent => "detached",
                            DatapathCheck::Error => "error",
                            DatapathCheck::Unknown => "unknown",
                        },
                    })
                    .collect()
            }),
            maps: full.then(|| Maps {
                state: if observation.errors.contains(&DatapathObservationError::Maps) {
                    "error"
                } else if observation.conn_state_capacity.is_some() {
                    "partial"
                } else {
                    "unknown"
                },
                conn_state: observation
                    .conn_state_capacity
                    .map(|capacity| MapOccupancy {
                        occupancy: None,
                        capacity,
                        occupancy_known: false,
                    }),
            }),
        }),
        errors: observation.errors.into_iter().map(safe_error).collect(),
    }
}

pub(super) async fn get(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let full = full_detail(&parse_query(uri, &["detail"], id)?, id)?;
    let (observation, healthy) = {
        let _config = state.config.read().await;
        let backend = state.backend.read().await;
        (
            backend.observe_datapath(),
            state.healthy.load(Ordering::Acquire),
        )
    };
    Ok(Json(detail(observation, &state.instance_id, healthy, full)).into_response())
}

pub(super) fn capability() -> Value {
    json!({"available": true, "kinds": ["ebpf", "mock"], "details": ["attachments", "maps"]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::{DatapathAttachment, EbpfBackend, mock::MockEbpfBackend};

    #[test]
    fn mock_admission_never_claims_kernel_activity() {
        let mut backend = MockEbpfBackend::new();
        backend.datapath_ready = true;
        backend.listener_sockets_published = true;
        let before = SystemTime::now();
        let observation = backend.observe_datapath();
        assert!(observation.checked_at >= before);
        assert!(observation.checked_at <= SystemTime::now());
        let body = serde_json::to_value(detail(observation, "instance", true, true)).unwrap();
        assert_eq!(body["kind"], "mock");
        assert_eq!(body["state"], "disabled");
        assert_eq!(body["visibility"], "none");
        assert!(body["ebpf"].is_null());
        assert!(backend.datapath_ready);
    }

    #[test]
    fn incomplete_observations_preserve_unknowns_and_checked_time() {
        let mut observation = DatapathObservation::unknown(DatapathKind::Real);
        observation.checked_at = SystemTime::UNIX_EPOCH;
        observation.programs = DatapathCheck::Verified;
        observation.routing = DatapathCheck::Verified;
        observation.routing_generation = Some(91);
        observation.admission = Some(true);
        observation.listeners_published = Some(true);
        observation.conn_state_capacity = Some(524_288);
        let mut backend = MockEbpfBackend::new();
        backend.datapath_observation_fixture = Some(observation);
        // The default projection stops at the summary; the kernel detail is asked for.
        let brief =
            serde_json::to_value(detail(backend.observe_datapath(), "instance", true, false))
                .unwrap();
        assert_eq!(
            brief["ebpf"]["routing"]["generation_id"],
            "instance:datapath:91"
        );
        assert!(brief["ebpf"].get("attachments").is_none());
        assert!(brief["ebpf"].get("maps").is_none());
        let body = serde_json::to_value(detail(backend.observe_datapath(), "instance", true, true))
            .unwrap();
        assert_eq!(body["state"], "unknown");
        assert_eq!(body["ebpf"]["checked_at"], "1970-01-01T00:00:00.000Z");
        assert_eq!(
            body["ebpf"]["routing"]["generation_id"],
            "instance:datapath:91"
        );
        assert!(body["ebpf"]["routing"]["epoch"].is_null());
        assert_eq!(body["ebpf"]["maps"]["conn_state"]["capacity"], 524_288);
        assert_eq!(body["ebpf"]["maps"]["conn_state"]["occupancy_known"], false);
        assert!(body["ebpf"]["maps"]["conn_state"]["occupancy"].is_null());
    }

    #[test]
    fn read_errors_are_bounded_safe_and_cannot_claim_active() {
        let mut observation = DatapathObservation::unknown(DatapathKind::Real);
        observation.programs = DatapathCheck::Verified;
        observation.hooks = DatapathCheck::Verified;
        observation.routing = DatapathCheck::Verified;
        observation.routing_generation = Some(1);
        observation.admission = Some(true);
        observation.listeners_published = Some(true);
        observation.conn_state_capacity = Some(1);
        assert_eq!(summary(&observation, "instance", true).state, "active");
        observation.admission = None;
        assert_eq!(summary(&observation, "instance", true).state, "unknown");
        observation.admission = Some(false);
        assert_eq!(summary(&observation, "instance", true).state, "disabled");
        observation.admission = Some(true);
        for _ in 0..1024 {
            observation.record_error(DatapathObservationError::Routing);
            observation.record_error(DatapathObservationError::Maps);
        }
        assert_eq!(observation.errors.len(), 2);
        observation.routing = DatapathCheck::Error;
        let body = serde_json::to_value(detail(observation, "instance", true, true)).unwrap();
        assert_eq!(body["state"], "degraded");
        assert!(body["ebpf"]["routing"]["generation_id"].is_null());
        assert_eq!(body["errors"][0]["code"], "routing_observation_failed");
        assert_eq!(body["ebpf"]["last_error"], "map_observation_failed");
        assert!(!body.to_string().contains("/sys/fs/bpf"));
    }

    fn tcx_observation(states: &[DatapathCheck]) -> DatapathObservation {
        let mut observation = DatapathObservation::unknown(DatapathKind::Real);
        observation.programs = DatapathCheck::Verified;
        observation.routing = DatapathCheck::Verified;
        observation.routing_generation = Some(1);
        observation.admission = Some(true);
        observation.listeners_published = Some(true);
        observation.conn_state_capacity = Some(1);
        for (index, state) in states.iter().enumerate() {
            if *state != DatapathCheck::Verified {
                observation.record_error(DatapathObservationError::Hooks);
            }
            observation.attachments.push(DatapathAttachment {
                program: "tc_ingress".to_owned(),
                interface: format!("eth{index}"),
                egress: false,
                state: *state,
            });
        }
        observation
    }

    #[test]
    fn attachments_report_their_interface_kind() {
        let body = serde_json::to_value(detail(
            tcx_observation(&[DatapathCheck::Verified]),
            "instance",
            true,
            true,
        ))
        .unwrap();
        assert_eq!(
            body["ebpf"]["attachments"],
            json!([{"name": "tc_ingress", "kind": "interface", "interface": "eth0",
                "direction": "ingress", "state": "attached"}])
        );
    }

    #[test]
    fn every_required_hook_verified_reports_active() {
        let mut observation = tcx_observation(&[DatapathCheck::Verified; 2]);
        observation.verify_required_hooks(2);
        let summary = summary(&observation, "instance", true);
        let ebpf = summary.ebpf.unwrap();
        assert_eq!(summary.state, "active");
        assert_eq!(summary.visibility, "partial");
        assert_eq!(ebpf.hooks, "attached");
        assert_eq!(ebpf.health, "healthy");
    }

    #[test]
    fn unchecked_required_hook_keeps_hooks_unknown() {
        let mut observation = tcx_observation(&[DatapathCheck::Verified; 2]);
        observation.verify_required_hooks(5);
        let unchecked = summary(&observation, "instance", true);
        let ebpf = unchecked.ebpf.unwrap();
        assert_eq!(unchecked.state, "unknown");
        assert_eq!(ebpf.hooks, "unknown");
        assert_eq!(ebpf.health, "unknown");

        let mut unqueried = tcx_observation(&[DatapathCheck::Verified]);
        unqueried.record_error(DatapathObservationError::Hooks);
        unqueried.verify_required_hooks(2);
        let summary = summary(&unqueried, "instance", true);
        let ebpf = summary.ebpf.unwrap();
        assert_eq!(summary.state, "degraded");
        assert_eq!(ebpf.hooks, "unknown");
        assert_eq!(ebpf.health, "degraded");
    }

    #[test]
    fn absent_required_hook_reports_partially_attached() {
        for required in [2, 5] {
            let mut observation =
                tcx_observation(&[DatapathCheck::Verified, DatapathCheck::Absent]);
            observation.verify_required_hooks(required);
            let summary = summary(&observation, "instance", true);
            let ebpf = summary.ebpf.unwrap();
            assert_eq!(summary.state, "degraded");
            assert_eq!(ebpf.hooks, "partially_attached");
            assert_eq!(ebpf.health, "degraded");
        }
    }

    #[test]
    fn no_owned_hook_reports_detached() {
        let mut observation = tcx_observation(&[]);
        observation.hooks = DatapathCheck::Absent;
        observation.verify_required_hooks(0);
        let summary = summary(&observation, "instance", true);
        let ebpf = summary.ebpf.unwrap();
        assert_eq!(summary.state, "detached");
        assert_eq!(ebpf.hooks, "detached");
        assert_eq!(ebpf.health, "unknown");
    }
}
