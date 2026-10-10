use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) async fn execute(
    state: &NativeState,
    plan: &mut PreparedPlan,
    deadline: Instant,
    stop: watch::Receiver<bool>,
) -> Result<(), honk_outbound::runtime::RuntimeCleanupError> {
    let mut cleanup = Ok(());
    for skipped in &plan.skipped {
        for &row in &skipped.rows {
            plan.result.results[row].error = Some("address_unavailable");
            plan.result.results[row].observed_at = timestamp(skipped.observed_at);
        }
    }
    for attempt in &plan.attempts {
        let candidate = &attempt.candidate;
        if *stop.borrow() || Instant::now() >= deadline {
            for &row in &candidate.rows {
                plan.result.results[row].error = Some(if *stop.borrow() {
                    "cancelled"
                } else {
                    "deadline"
                });
                plan.result.results[row].observed_at = timestamp(SystemTime::now());
            }
            continue;
        }
        let outcome = attempt_wire(state, &plan.context, attempt, deadline, stop.clone()).await;
        cleanup = cleanup.and(outcome.cleanup);
        let sample = outcome.sample;
        let completed = outcome.completed;
        let error = outcome.error;
        let warmth = if sample.is_some() {
            if plan.context.spec.kind == Kind::Http && plan.context.spec.warmth == Warmth::Warm {
                "warm"
            } else {
                "cold"
            }
        } else {
            "unknown"
        };
        let observed_at = outcome.observed_at;
        let observation = HealthObservation {
            transport: if candidate.transport == Transport::Tcp {
                HealthTransport::Tcp
            } else {
                HealthTransport::Udp
            },
            purpose: if plan.context.spec.purpose == Purpose::Data {
                HealthPurpose::Data
            } else {
                HealthPurpose::Dns
            },
            measurement: match plan.context.spec.kind {
                Kind::TcpConnect => HealthMeasurement::TcpConnect,
                Kind::Http => HealthMeasurement::HttpHeaders,
                Kind::Dns => HealthMeasurement::DnsRoundTrip,
            },
            ip_version: candidate.family.ip(),
            warmth: match warmth {
                "cold" => HealthWarmth::Cold,
                "warm" => HealthWarmth::Warm,
                _ => HealthWarmth::Unknown,
            },
            state: if sample.is_some() {
                HealthState::Healthy
            } else {
                HealthState::Unavailable
            },
            latency: sample.map(|sample| sample.latency),
            observed_at,
            error,
        };
        for &index in &candidate.rows {
            let row = &mut plan.result.results[index];
            let context = match &plan.context.spec.target {
                Target::Group { group_id } => Some(GroupProbeContext {
                    group_id: Uuid::parse_str(group_id).expect("catalog UUID"),
                    member_id: Uuid::parse_str(&row.member_id).expect("catalog member UUID"),
                }),
                Target::Node { .. } => None,
            };
            row.health_updated = completed
                && state
                    .alive_set
                    .complete_probe(&candidate.ticket, context, observation);
            row.state = if sample.is_some() {
                "healthy"
            } else if completed {
                "unavailable"
            } else {
                "unknown"
            };
            row.latency_ms = sample.map(|sample| sample.latency.as_secs_f64() * 1000.0);
            row.warmth = warmth;
            row.error = error;
            row.observed_at = timestamp(observed_at);
        }
    }
    plan.result.selection_after = planning::selections(
        &plan.context.manager,
        &plan.context.identity,
        plan.context.group.as_deref(),
    );
    plan.result.selection_changed = TransportMap {
        tcp: plan.result.selection_before.tcp != plan.result.selection_after.tcp,
        udp: plan.result.selection_before.udp != plan.result.selection_after.udp,
    };
    cleanup
}

pub(super) async fn bounded<T>(
    deadline: Instant,
    mut cancel: watch::Receiver<bool>,
    future: impl Future<Output = T>,
) -> std::io::Result<T> {
    if *cancel.borrow() {
        return Err(std::io::ErrorKind::Interrupted.into());
    }
    tokio::select! {
        biased;
        _ = cancel.changed() => Err(std::io::ErrorKind::Interrupted.into()),
        result = tokio::time::timeout_at(deadline, future) => result.map_err(|_| std::io::ErrorKind::TimedOut.into()),
    }
}

pub(super) struct AttemptOutcome {
    pub(super) sample: Option<ProbeMeasurement>,
    pub(super) completed: bool,
    pub(super) error: Option<&'static str>,
    pub(super) observed_at: SystemTime,
    pub(super) cleanup: Result<(), honk_outbound::runtime::RuntimeCleanupError>,
}
impl AttemptOutcome {
    fn completed(
        result: anyhow::Result<ProbeMeasurement>,
        deadline: Instant,
        cancel: &watch::Receiver<bool>,
    ) -> Self {
        match result {
            Ok(sample) => Self {
                sample: Some(sample),
                completed: true,
                error: None,
                observed_at: sample.observed_at,
                cleanup: Ok(()),
            },
            Err(error) => {
                let io = error
                    .chain()
                    .find_map(|cause| cause.downcast_ref::<std::io::Error>())
                    .map(std::io::Error::kind);
                let reason = if io == Some(std::io::ErrorKind::Interrupted) && *cancel.borrow() {
                    "cancelled"
                } else if io == Some(std::io::ErrorKind::TimedOut) && Instant::now() >= deadline {
                    "deadline"
                } else if honk_outbound::proxy::is_packet_rejection(&error)
                    || io == Some(std::io::ErrorKind::Interrupted)
                {
                    "local_refusal"
                } else {
                    "probe_failed"
                };
                Self {
                    sample: None,
                    completed: reason == "probe_failed",
                    error: Some(reason),
                    observed_at: SystemTime::now(),
                    cleanup: Ok(()),
                }
            }
        }
    }
    fn refused() -> Self {
        Self {
            sample: None,
            completed: false,
            error: Some("local_refusal"),
            observed_at: SystemTime::now(),
            cleanup: Ok(()),
        }
    }
}
async fn attempt_wire(
    state: &NativeState,
    plan: &Context,
    attempt: &Attempt,
    deadline: Instant,
    cancel: watch::Receiver<bool>,
) -> AttemptOutcome {
    let addr = attempt.addr;
    let candidate = &attempt.candidate;
    if plan.spec.kind == Kind::TcpConnect {
        let result = bounded(deadline, cancel.clone(), async {
            let _permit = plan.registry.acquire_dial_permit().await;
            let start = std::time::Instant::now();
            let socket = honk_outbound::util::connect_marked_addr(
                addr,
                Some(honk_outbound::util::bypass_mark()),
                deadline.saturating_duration_since(Instant::now()),
            )
            .await?;
            let sample = ProbeMeasurement {
                latency: start.elapsed(),
                observed_at: SystemTime::now(),
            };
            drop(socket);
            Ok(sample)
        })
        .await
        .map_err(anyhow::Error::from)
        .and_then(|result| result);
        return AttemptOutcome::completed(result, deadline, &cancel);
    }
    let Some(entry) = state.proxy_registry.find(candidate.node.protocol()) else {
        return AttemptOutcome::refused();
    };
    // Disposable runtime identity remains the canonical node's identity. Only its
    // inherited dial scope pins the previously validated physical server address.
    let Ok(mut ephemeral) = plan.registry.try_ephemeral_guarded(&candidate.node) else {
        return AttemptOutcome::refused();
    };
    let runtime = ephemeral.runtime();
    let operation = async {
        if plan.spec.kind == Kind::Http {
            let timeout = deadline.saturating_duration_since(Instant::now());
            bounded(
                deadline,
                cancel.clone(),
                honk_outbound::urltest::measure_pinned_http_probe(
                    &runtime,
                    entry.tcp.as_ref(),
                    plan.http.as_ref().expect("HTTP plan"),
                    addr,
                    plan.spec.warmth == Warmth::Cold,
                    timeout,
                ),
            )
            .await?
        } else {
            bounded(deadline, cancel.clone(), async {
                let connect_timeout = Duration::from_millis(plan.config.global.connect_timeout_ms)
                    .min(deadline.saturating_duration_since(Instant::now()));
                match candidate.transport {
                    Transport::Tcp => {
                        let mut proxy = entry
                            .tcp
                            .dial_runtime(Arc::clone(&runtime), addr, None, connect_timeout)
                            .await?;
                        tcp_dns(&mut proxy.stream).await
                    }
                    Transport::Udp => {
                        let packet = entry
                            .packet
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("packet handler unavailable"))?;
                        let transport = packet
                            .dial_udp_transport_runtime(
                                Arc::clone(&runtime),
                                addr,
                                None,
                                connect_timeout,
                            )
                            .await?;
                        crate::dns::forwarder::udp_dns_probe(transport.as_ref()).await
                    }
                }
            })
            .await?
        }
    };
    let result = if let Some(server) = attempt.server {
        runtime
            .scope_tasks(
                plan.registry
                    .scope_pinned_dials(candidate.node.host(), server, operation),
            )
            .await
    } else {
        runtime
            .scope_tasks(plan.registry.scope_dials(operation))
            .await
    };
    let mut outcome = AttemptOutcome::completed(result, deadline, &cancel);
    drop(runtime);
    // Never cancel this owner boundary: close must drain every factory/driver
    // admitted before the request deadline, even when the HTTP caller is gone.
    outcome.cleanup = ephemeral.close().await;
    outcome
}

async fn tcp_dns<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
) -> anyhow::Result<ProbeMeasurement> {
    let query = crate::dns::forwarder::dns_probe_query();
    let start = std::time::Instant::now();
    stream.write_u16(u16::try_from(query.len())?).await?;
    stream.write_all(&query).await?;
    stream.flush().await?;
    let length = usize::from(stream.read_u16().await?);
    let mut response = vec![0; length];
    stream.read_exact(&mut response).await?;
    crate::dns::forwarder::validate_dns_probe_response(&query, &response)?;
    Ok(ProbeMeasurement {
        latency: start.elapsed(),
        observed_at: SystemTime::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_error_survives_later_cancel_and_deadline() {
        let (cancel, receiver) = watch::channel(false);
        let error = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        cancel.send_replace(true);
        let outcome = AttemptOutcome::completed(Err(error), Instant::now(), &receiver);
        assert!(outcome.completed);
        assert_eq!(outcome.error, Some("probe_failed"));
    }

    #[tokio::test]
    async fn dns_probes_validate_framed_tcp_and_udp_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let tcp = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let size = stream.read_u16().await.unwrap() as usize;
            let mut query = vec![0; size];
            stream.read_exact(&mut query).await.unwrap();
            query[2] |= 0x80;
            stream.write_u16(size as u16).await.unwrap();
            stream.write_all(&query).await.unwrap();
        });
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let sample = tcp_dns(&mut stream).await.unwrap();
        assert!(sample.observed_at <= SystemTime::now());
        tcp.await.unwrap();
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let udp = tokio::spawn(async move {
            let mut query = [0; 512];
            let (size, peer) = server.recv_from(&mut query).await.unwrap();
            query[2] |= 0x80;
            // Echoing the right transaction is insufficient: the question must match.
            query[13] = b'x';
            server.send_to(&query[..size], peer).await.unwrap();
        });
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(address).await.unwrap();
        let transport = honk_outbound::proxy::UdpSocketTransport::new(Arc::new(socket), address);
        assert!(
            crate::dns::forwarder::udp_dns_probe(&transport)
                .await
                .is_err()
        );
        udp.await.unwrap();
    }
}
