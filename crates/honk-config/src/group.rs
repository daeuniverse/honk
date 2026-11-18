// Re-export Group and GroupPolicy from node module to keep them together
pub use crate::node::{Group, GroupPolicy, OwnOptions};

/// Groups one selection path may cross: the root is at depth 0 and a group
/// at depth `d` is entered only while `d < MAX_GROUP_DEPTH`.
pub const MAX_GROUP_DEPTH: usize = 8;
