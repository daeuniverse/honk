use super::Config;
use crate::diagnostic::{DetailedDiagnostic, SafeValue, SettingPath, SourceRef};

impl Config {
    /// Append typed-field warnings for a loaded or constructed configuration.
    /// Repeated collection within one source table does not duplicate warnings.
    pub fn append_diagnostics(&self, source: SourceRef, diagnostics: &mut Vec<DetailedDiagnostic>) {
        let mut emit = |diagnostic: DetailedDiagnostic| {
            if !diagnostics.iter().any(|d| {
                d.code == diagnostic.code
                    && d.setting == diagnostic.setting
                    && d.source.same_table(&source)
            }) {
                diagnostics.push(diagnostic);
            }
        };
        if let Some(diagnostic) = self
            .experimental
            .clash_api
            .exposure_diagnostic(source.clone())
        {
            emit(diagnostic);
        }
    }
}

impl crate::experimental::ClashApiConfig {
    pub(crate) fn exposure_diagnostic(&self, source: SourceRef) -> Option<DetailedDiagnostic> {
        let listen = if let Some(port) = self.external_controller.strip_prefix(':') {
            port.parse::<u16>()
                .ok()
                .map(|port| std::net::SocketAddr::from(([0, 0, 0, 0], port)))
        } else {
            self.external_controller
                .parse::<std::net::SocketAddr>()
                .ok()
        };
        (self.secret.is_empty() && listen.is_some_and(|listen| !listen.ip().is_loopback())).then(|| {
            DetailedDiagnostic::warning(
                "unsafe-api-bind",
                source,
                SettingPath::new("experimental")
                    .field("clash_api")
                    .field("external_controller"),
                SafeValue::Redacted,
                "Clash API authentication is disabled on a non-loopback address; the API has no TLS",
            )
        })
    }
}
