use crate::dns::query::IngressProfile;
pub(crate) use crate::dns::response::native::{
    DnsAnswer, DnsQuestion, MAX_JSON_BYTES, ProjectionError, parse_type, project, question,
    record_type, status,
};

/// Projects one row of a listing page; `None` ends a page that already holds rows. The first row of a page is
/// always served, past the budget if it must, because its 65535-byte wire bounds the expansion and refusing it
/// would strand every row after it. The budget is then spent, so the page ends with that row.
pub(super) fn page_row(
    query: &[u8],
    response: &[u8],
    ingress: IngressProfile,
    budget: &mut usize,
    first: bool,
) -> Result<Option<Vec<DnsAnswer>>, ProjectionError> {
    match project(query, response, ingress, budget) {
        Ok(answers) => Ok(Some(answers)),
        Err(ProjectionError::Budget) if first => {
            *budget = 0;
            let mut unbounded = usize::MAX;
            project(query, response, ingress, &mut unbounded).map(Some)
        }
        Err(ProjectionError::Budget) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn json_size(value: &impl serde::Serialize) -> Result<usize, serde_json::Error> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}
