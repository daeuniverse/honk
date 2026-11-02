//! Raw pinned-map access for fixtures that edit or inspect publications behind the engine.

use super::*;

pub(super) const MAP_LOCK: u64 = aya_obj::generated::BPF_F_LOCK as u64;

pub(super) fn conn_map()
-> anyhow::Result<HashMap<aya::maps::MapData, TuplesKey, FlowMapValue<ConnState>>> {
    Ok(HashMap::try_from(pinned_map(
        Path::new(ROOT),
        "CONN_STATE_MAP",
    )?)?)
}

pub(super) fn handoff_map()
-> anyhow::Result<HashMap<aya::maps::MapData, TuplesKey, FlowMapValue<RoutingHandoffEntry>>> {
    Ok(HashMap::try_from(pinned_map(
        Path::new(ROOT),
        "ROUTING_HANDOFF_MAP",
    )?)?)
}

pub(super) fn redirect_map()
-> anyhow::Result<HashMap<aya::maps::MapData, RedirectTuple, FlowMapValue<RedirectEntry>>> {
    Ok(HashMap::try_from(pinned_map(
        Path::new(ROOT),
        "REDIRECT_TRACK",
    )?)?)
}

/// Raw fixture write of one publication; the backend lock keeps the retirement worker
/// from reading a half-edited tuple.
pub(super) async fn mutate_conn(
    handle: &ControlPlaneHandle,
    key: &TuplesKey,
    change: impl FnOnce(&mut ConnState),
) -> anyhow::Result<()> {
    let _backend = handle.ebpf.write().await;
    let mut conns = conn_map()?;
    let mut state = conns.get(key, MAP_LOCK)?.value;
    change(&mut state);
    conns.insert(key, &FlowMapValue::new(state), 2 | MAP_LOCK)?;
    Ok(())
}

pub(super) async fn mutate_handoff(
    handle: &ControlPlaneHandle,
    key: &TuplesKey,
    change: impl FnOnce(&mut RoutingHandoffEntry),
) -> anyhow::Result<()> {
    let _backend = handle.ebpf.write().await;
    let mut handoffs = handoff_map()?;
    let mut entry = handoffs.get(key, MAP_LOCK)?.value;
    change(&mut entry);
    handoffs.insert(key, &FlowMapValue::new(entry), 2 | MAP_LOCK)?;
    Ok(())
}

/// Polls the real conn-state until `ready` holds for it.
pub(super) async fn await_conn(
    handle: &ControlPlaneHandle,
    key: &TuplesKey,
    what: &str,
    ready: impl Fn(&ConnState) -> bool,
) -> anyhow::Result<ConnState> {
    tokio::time::timeout(NETNS_TEST_TIMEOUT, async {
        loop {
            let conn = handle.ebpf.read().await.conn_state_lookup(key)?;
            if let Some(conn) = conn.filter(&ready) {
                return Ok::<_, anyhow::Error>(conn);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .with_context(|| format!("conn-state never became: {what}"))?
}
