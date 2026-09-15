use std::sync::Arc;

/// Cloneable failure for shared initialization waiters, preserving typed causes.
/// An `Arc<anyhow::Error>` alone becomes an opaque message when re-wrapped.
#[derive(Clone)]
pub struct SharedError(Arc<anyhow::Error>);

impl SharedError {
    pub fn new(error: anyhow::Error) -> Self {
        Self(Arc::new(error))
    }
}

impl std::fmt::Debug for SharedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0.as_ref(), formatter)
    }
}

impl std::fmt::Display for SharedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}
