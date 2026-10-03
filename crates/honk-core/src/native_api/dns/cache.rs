use std::time::{Duration, Instant, SystemTime};

use axum::{http::Uri, response::Response};
use serde_json::json;
use uuid::Uuid;

use super::{
    ApiError, MAX_RESPONSE_BYTES, NativeState, RequestId, canonical_name, full_detail,
    invalid_query, json_response, parameters, records, timestamp, unavailable,
};
use crate::dns::cache::{CacheUsage, ExactCacheEntry};

const SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

#[derive(PartialEq, Eq)]
struct Filters {
    name: Option<String>,
    domain: Option<String>,
    types: Vec<u16>,
    expired: bool,
    full: bool,
}

pub(super) struct Snapshot {
    id: String,
    instance: String,
    created: Instant,
    observed_at: String,
    filters: Filters,
    limit: usize,
    entries: Vec<ExactCacheEntry>,
    usage: CacheUsage,
    bytes: usize,
    wall: SystemTime,
}

pub(super) async fn serve(
    state: &NativeState,
    uri: &Uri,
    id: &RequestId,
) -> Result<Response, ApiError> {
    let (values, mut types) = parameters(
        uri,
        &[
            "name",
            "domain",
            "type",
            "include_expired",
            "limit",
            "cursor",
            "detail",
        ],
        id,
    )?;
    types.sort_unstable();
    let filters = Filters {
        name: values
            .get("name")
            .map(|name| canonical_name(name, id))
            .transpose()?,
        domain: values
            .get("domain")
            .map(|domain| domain.to_ascii_lowercase()),
        types,
        expired: match values
            .get("include_expired")
            .map(String::as_str)
            .unwrap_or("false")
        {
            "true" => true,
            "false" => false,
            _ => return Err(invalid_query(id)),
        },
        full: full_detail(&values, id)?,
    };
    let limit = crate::native_api::pages::limit(&values, id)?;
    let api = &state.observation.dns;
    let mut snapshots = api.snapshots.lock().await;
    snapshots.retain(|snapshot| snapshot.created.elapsed() < SNAPSHOT_TTL);
    if let Some(cursor) = values.get("cursor") {
        let expired = || super::super::catalog::snapshot_expired(id);
        let (snapshot_id, position) = cursor.rsplit_once(':').ok_or_else(expired)?;
        let position = position.parse::<usize>().map_err(|_| expired())?;
        let snapshot = snapshots
            .iter()
            .find(|snapshot| {
                snapshot.id == snapshot_id && snapshot.instance == api.recorder.instance()
            })
            .ok_or_else(expired)?;
        if position == 0 || position >= snapshot.entries.len() {
            return Err(expired());
        }
        if snapshot.filters != filters || snapshot.limit != limit {
            return Err(invalid_query(id));
        }
        return page(snapshot, position, limit, id).map(|(response, _)| response);
    }
    let full = || super::super::catalog::snapshot_unavailable(id);
    if snapshots.len() == 8 {
        return Err(full());
    }
    let retained = snapshots
        .iter()
        .map(|snapshot| snapshot.bytes)
        .sum::<usize>();
    let overhead = std::mem::size_of::<Snapshot>()
        + api.recorder.instance().len()
        + 256
        + filters.name.as_ref().map_or(0, String::capacity)
        + filters.domain.as_ref().map_or(0, String::capacity)
        + filters.types.capacity() * std::mem::size_of::<u16>();
    let available = SNAPSHOT_BYTES
        .checked_sub(retained.saturating_add(overhead))
        .ok_or_else(full)?;
    let created = Instant::now();
    let wall = SystemTime::now();
    let inspection = state
        .dns
        .inspect_cache(available, created, |key, expires_at| {
            if !filters.expired && expires_at <= created {
                return false;
            }
            let Ok(question) = records::question(key.wire_identity(), key.ingress()) else {
                return false;
            };
            let name = question.name.to_ascii_lowercase();
            filters.name.as_ref().is_none_or(|filter| filter == &name)
                && filters
                    .domain
                    .as_ref()
                    .is_none_or(|filter| name.contains(filter))
                && (filters.types.is_empty()
                    || records::parse_type(&question.rtype)
                        .is_some_and(|qtype| filters.types.contains(&qtype)))
        })
        .await
        .map_err(|_| full())?;
    let mut entries = inspection.entries;
    entries.sort_unstable_by(|left, right| left.id.cmp(&right.id));
    let bytes = overhead
        + entries.iter().map(|entry| entry.cost).sum::<usize>()
        + (entries.capacity() - entries.len()) * std::mem::size_of::<ExactCacheEntry>();
    let snapshot = Snapshot {
        id: Uuid::new_v4().to_string(),
        instance: api.recorder.instance().to_owned(),
        created,
        observed_at: timestamp(wall),
        filters,
        limit,
        entries,
        usage: inspection.usage,
        bytes,
        wall,
    };
    let (response, more) = page(&snapshot, 0, limit, id)?;
    if more {
        snapshots.push_back(snapshot);
    }
    Ok(response)
}

fn at(snapshot: &Snapshot, instant: Instant) -> String {
    let wall = if instant >= snapshot.created {
        snapshot
            .wall
            .checked_add(instant.duration_since(snapshot.created))
    } else {
        snapshot
            .wall
            .checked_sub(snapshot.created.duration_since(instant))
    };
    timestamp(wall.unwrap_or(snapshot.wall))
}

/// Returns the page and whether it ends before the snapshot does.
fn page(
    snapshot: &Snapshot,
    offset: usize,
    limit: usize,
    id: &RequestId,
) -> Result<(Response, bool), ApiError> {
    let mut end = offset.saturating_add(limit).min(snapshot.entries.len());
    let mut budget = MAX_RESPONSE_BYTES.saturating_sub(1024);
    let mut rows = Vec::with_capacity(end - offset);
    for (position, entry) in snapshot.entries[offset..end].iter().enumerate() {
        let question = records::question(entry.key.wire_identity(), entry.key.ingress())
            .map_err(|_| unavailable(id))?;
        let metadata_cost = entry
            .id
            .len()
            .saturating_add(question.name.len())
            .saturating_add(512);
        let first = rows.is_empty();
        match budget.checked_sub(metadata_cost) {
            Some(rest) => budget = rest,
            None if first => budget = 0,
            None => {
                end = offset + position;
                break;
            }
        }
        let status = if let Some(rcode) = entry.negative {
            match rcode {
                0 => "NODATA".to_owned(),
                2 => "SERVFAIL".to_owned(),
                3 => "NXDOMAIN".to_owned(),
                5 => "REFUSED".to_owned(),
                other => format!("RCODE{other}"),
            }
        } else if let Some(response) = &entry.response {
            if response.get(3).is_some_and(|value| value & 15 == 0)
                && response.get(6..8) == Some(&[0, 0])
            {
                "NODATA".to_owned()
            } else {
                records::status(response)
            }
        } else {
            return Err(unavailable(id));
        };
        let mut row = json!({"entry_id":entry.id,"domain":question.name,"type":question.rtype,"class":question.class,"status":status,
            "expires_at":at(snapshot,entry.expires_at),"stale_until":entry.stale_until.map(|value| at(snapshot,value))});
        if snapshot.filters.full {
            let answers = if let Some(response) =
                entry.response.as_ref().filter(|_| entry.negative.is_none())
            {
                let Some(answers) = records::page_row(
                    entry.key.wire_identity(),
                    response,
                    entry.key.ingress(),
                    &mut budget,
                    first,
                )
                .map_err(|_| unavailable(id))?
                else {
                    end = offset + position;
                    break;
                };
                answers
            } else {
                Vec::new()
            };
            row["answers"] = json!(answers);
        }
        rows.push(row);
    }
    let more = end < snapshot.entries.len();
    let cursor = more.then(|| format!("{}:{end}", snapshot.id));
    let usage = &snapshot.usage;
    // A single entry is served whole; see `records::page_row`.
    let cap = if rows.len() > 1 {
        MAX_RESPONSE_BYTES
    } else {
        usize::MAX
    };
    let response = json_response(
        &json!({"observed_at":snapshot.observed_at,"coverage":{"positive":true,"negative":true,"persistent":false},
        "entries":rows,"total":snapshot.entries.len(),"next_cursor":cursor,
        "usage":{"entries":usage.entries.to_string(),"entry_capacity":usage.entry_capacity.to_string()}}),
        cap,
        id,
    )?;
    Ok((response, more))
}
