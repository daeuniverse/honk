use super::*;
use aya::maps::IterableMap;

#[test]
#[ignore = "requires root and Linux 6.12+; run in the isolated VM gate"]
fn locked_flow_snapshots_are_coherent_during_native_in_place_updates() -> anyhow::Result<()> {
    use std::os::fd::AsFd;
    use std::sync::{Arc, Barrier};

    // Real concurrent syscalls, not a simulated reader or a forced kernel
    // instruction interleaving. Every correlated field must come from one copy.
    fn exercise<K, V>(
        backend: &mut RealEbpfBackend,
        name: &str,
        key: K,
        values: [V; 2],
    ) -> anyhow::Result<()>
    where
        K: aya::Pod + Send + Sync,
        V: aya::Pod + Send + Sync + std::fmt::Debug,
    {
        backend.flow_insert(name, &key, &values[0])?;
        let map = backend.hash_map::<K, FlowMapValue<V>>(name)?;
        let data = aya::maps::MapData::from_fd(map.map().fd().as_fd().try_clone_to_owned()?)?;
        let mut writer =
            aya::maps::HashMap::<_, K, FlowMapValue<V>>::try_from(aya::maps::Map::HashMap(data))?;
        let start = Arc::new(Barrier::new(2));
        let writer_start = Arc::clone(&start);
        std::thread::scope(|scope| -> anyhow::Result<()> {
            let thread = scope.spawn(move || -> anyhow::Result<()> {
                writer_start.wait();
                for index in 0..8192 {
                    writer.insert(&key, &FlowMapValue::new(values[index % 2]), 2 | 4)?;
                }
                Ok(())
            });
            let expected = values.map(|value| format!("{value:?}"));
            start.wait();
            for _ in 0..2048 {
                let value = backend
                    .flow_lookup::<K, V>(name, &key)?
                    .expect("stable element disappeared");
                assert!(
                    expected.contains(&format!("{value:?}")),
                    "torn locked singleton in {name}: {value:?}"
                );
                let mut seen = 0;
                backend.flow_for_each_chunk::<K, V>(name, 1, &mut |chunk| {
                    for (_, value) in chunk {
                        assert!(
                            expected.contains(&format!("{value:?}")),
                            "torn locked batch in {name}: {value:?}"
                        );
                        seen += 1;
                    }
                    true
                })?;
                assert_eq!(
                    seen, 1,
                    "native in-place writer recycled an element in {name}"
                );
            }
            thread.join().expect("native locked writer panicked")?;
            Ok(())
        })
    }

    let mut backend = retirement_fixture();
    let key = TuplesKey {
        src_ip: honk_ebpf_common::dae_ip::In6Addr::from_ipv6_addr("2001:db8::81".parse()?),
        dst_ip: honk_ebpf_common::dae_ip::In6Addr::from_ipv6_addr("2001:db8:1::82".parse()?),
        src_port: 41300,
        dst_port: 443,
        l4proto: 6,
        ..Default::default()
    };
    exercise(
        &mut backend,
        "CONN_STATE_MAP",
        key,
        [
            ConnState {
                incarnation: 1,
                decision_token: 7,
                last_seen_ns: 101,
                trace_id: 31,
                ..Default::default()
            },
            ConnState {
                incarnation: 2,
                decision_token: 8,
                last_seen_ns: 202,
                trace_id: 32,
                ..Default::default()
            },
        ],
    )?;
    exercise(
        &mut backend,
        "ROUTING_HANDOFF_MAP",
        key,
        [
            RoutingHandoffEntry {
                incarnation: 1,
                last_seen_ns: 101,
                trace_id: 31,
                result: RoutingResult {
                    decision_token: 7,
                    ..Default::default()
                },
                ..Default::default()
            },
            RoutingHandoffEntry {
                incarnation: 2,
                last_seen_ns: 202,
                trace_id: 32,
                result: RoutingResult {
                    decision_token: 8,
                    ..Default::default()
                },
                ..Default::default()
            },
        ],
    )?;
    exercise(
        &mut backend,
        "REDIRECT_TRACK",
        RedirectTuple::from_tuples(&key),
        [
            RedirectEntry {
                incarnation: 1,
                decision_token: 7,
                last_seen_ns: 101,
                ifindex: 31,
                ..Default::default()
            },
            RedirectEntry {
                incarnation: 2,
                decision_token: 8,
                last_seen_ns: 202,
                ifindex: 32,
                ..Default::default()
            },
        ],
    )?;
    Ok(())
}
