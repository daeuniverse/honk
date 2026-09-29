//! VLESS outbound handler and reusable carrier backends.

pub(crate) mod cool;
#[cfg(feature = "rprx")]
mod encryption;
#[cfg(feature = "rprx")]
mod handler;
pub(crate) mod mux;

#[cfg(feature = "rprx")]
pub use cool::{VlessXudpTransport, is_vless_source_post_admission_cancel};
#[cfg(feature = "rprx")]
pub use handler::{VLessHandler, VisionSplice};
