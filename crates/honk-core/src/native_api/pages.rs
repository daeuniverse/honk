//! Frozen list snapshots behind live `next_cursor`s, bounded by age, count and bytes.

use std::{
    collections::{HashMap, VecDeque},
    ops::Range,
    time::{Duration, Instant},
};

use axum::response::Response;
use parking_lot::Mutex;
use uuid::Uuid;

use super::{
    ApiError,
    catalog::{snapshot_expired, snapshot_unavailable},
    invalid_query,
    types::RequestId,
};

pub(super) const MAX_PAGE_SIZE: usize = 1000;
pub(super) const MAX_SNAPSHOTS: usize = 8;
pub(super) const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
pub(super) const SNAPSHOT_TTL: Duration = Duration::from_secs(30);

/// A frozen list and the response for any slice of it.
pub(crate) trait Snapshot {
    fn len(&self) -> usize;
    /// Retained size, charged against `MAX_SNAPSHOT_BYTES`.
    fn bytes(&self) -> usize;
    /// `next_cursor` resumes after `rows`, and is `None` on the last page.
    fn page(&self, rows: Range<usize>, next_cursor: Option<String>) -> Response;
}

pub(super) struct Held<T> {
    id: Uuid,
    pub(super) created: Instant,
    pub(super) bytes: usize,
    /// Page size the cursor was issued for; resuming with another is refused.
    limit: usize,
    snapshot: T,
}

pub(crate) struct Pages<T>(pub(super) Mutex<VecDeque<Held<T>>>);

impl<T> Default for Pages<T> {
    fn default() -> Self {
        Self(Mutex::new(VecDeque::new()))
    }
}

impl<T: Snapshot> Pages<T> {
    /// Serves the first page, retaining `snapshot` only when more pages follow.
    pub(super) fn first(
        &self,
        snapshot: T,
        limit: usize,
        id: &RequestId,
    ) -> Result<Response, ApiError> {
        let key = Uuid::new_v4();
        let response = page(&snapshot, key, 0, limit);
        if snapshot.len() > limit {
            let bytes = snapshot.bytes();
            let mut held = self.0.lock();
            held.retain(|held| held.created.elapsed() < SNAPSHOT_TTL);
            while held.len() >= MAX_SNAPSHOTS
                || held.iter().map(|held| held.bytes).sum::<usize>() + bytes > MAX_SNAPSHOT_BYTES
            {
                if held.pop_front().is_none() {
                    return Err(snapshot_unavailable(id));
                }
            }
            held.push_back(Held {
                id: key,
                created: Instant::now(),
                bytes,
                limit,
                snapshot,
            });
        }
        Ok(response)
    }

    /// An unknown, expired, exhausted or noncanonical cursor is `410 snapshot_expired`;
    /// one resumed with another `limit`, or refused by `accept` as taken under
    /// other request parameters, is `400 invalid_request`.
    pub(super) fn resume(
        &self,
        cursor: &str,
        limit: usize,
        accept: impl Fn(&T) -> bool,
        id: &RequestId,
    ) -> Result<Response, ApiError> {
        let expired = || snapshot_expired(id);
        let (raw_key, raw_offset) = cursor.split_once(':').ok_or_else(expired)?;
        let key = Uuid::parse_str(raw_key).map_err(|_| expired())?;
        let offset: usize = raw_offset.parse().map_err(|_| expired())?;
        let mut held = self.0.lock();
        held.retain(|held| held.created.elapsed() < SNAPSHOT_TTL);
        let held = held
            .iter()
            .find(|held| held.id == key)
            .ok_or_else(expired)?;
        if offset == 0 || offset >= held.snapshot.len() {
            return Err(expired());
        }
        if held.limit != limit || !accept(&held.snapshot) {
            return Err(invalid_query(id));
        }
        if !offset.is_multiple_of(held.limit)
            || raw_key != &*key.hyphenated().encode_lower(&mut [0; 36])
            || raw_offset.starts_with(['0', '+'])
        {
            return Err(expired());
        }
        Ok(page(&held.snapshot, key, offset, limit))
    }
}

fn page(snapshot: &impl Snapshot, key: Uuid, offset: usize, limit: usize) -> Response {
    let len = snapshot.len();
    let end = offset.saturating_add(limit).min(len);
    snapshot.page(offset..end, (end < len).then(|| format!("{key}:{end}")))
}

/// The `limit` query value: 100 when absent, otherwise 1 to `MAX_PAGE_SIZE`.
pub(super) fn limit(query: &HashMap<String, String>, id: &RequestId) -> Result<usize, ApiError> {
    let limit = query
        .get("limit")
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| invalid_query(id))?
        .unwrap_or(100);
    if (1..=MAX_PAGE_SIZE).contains(&limit) {
        Ok(limit)
    } else {
        Err(invalid_query(id))
    }
}
