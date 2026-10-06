//! H2 XHTTP: a node-owned carrier pool and bounded, cancellation-owned logical streams.

const MAX_CARRIERS: usize = 2;
const MAX_REQUESTS: usize = 128;
const MAX_PIPELINE: usize = 8;
const STREAM_WRITE: usize = 16 * 1024;
const RECEIVE_WINDOW: u32 = 256 * 1024;
const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;

mod preparation;
pub(crate) use preparation::XhttpPreparation;

mod runtime;
pub(crate) use runtime::XhttpRuntime;
mod request;
mod session;
pub(crate) use session::XhttpSession;
mod response;
mod stream;
mod upload;

#[cfg(test)]
mod tests;
