mod canonical;

use std::fmt;
use std::sync::Arc;

use honk_config::dns::DnsConfig;
use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PolicyId {
    digest: [u8; 32],
    canonical: Arc<[u8]>,
    artifacts: Option<Arc<ArtifactFingerprints>>,
}

#[derive(PartialEq, Eq, Hash)]
struct ArtifactFingerprints {
    hosts: [u8; 32],
    dns_geo: [u8; 32],
}

impl PolicyId {
    pub fn from_config(config: &DnsConfig) -> Result<Self, PolicyError> {
        let canonical = canonical::encode(config)?;
        let digest = Sha256::digest(&canonical).into();
        Ok(Self {
            digest,
            canonical: canonical.into(),
            artifacts: None,
        })
    }

    pub fn from_config_with_artifacts(
        config: &DnsConfig,
        hosts_fingerprint: &[u8; 32],
        dns_geo_fingerprint: &[u8; 32],
    ) -> Result<Self, PolicyError> {
        let canonical = canonical::encode(config)?;
        let mut hash = Sha256::new();
        hash.update(&canonical);
        hash.update(b"\0honk.dns-policy.hosts.v1\0");
        hash.update(hosts_fingerprint);
        hash.update(b"\0honk.dns-policy.geo.v1\0");
        hash.update(dns_geo_fingerprint);
        Ok(Self {
            digest: hash.finalize().into(),
            canonical: canonical.into(),
            artifacts: Some(Arc::new(ArtifactFingerprints {
                hosts: *hosts_fingerprint,
                dns_geo: *dns_geo_fingerprint,
            })),
        })
    }

    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    pub(crate) fn matches_artifacts(
        &self,
        hosts_fingerprint: &[u8; 32],
        dns_geo_fingerprint: &[u8; 32],
    ) -> bool {
        self.artifacts.as_deref().is_some_and(|artifacts| {
            artifacts.hosts == *hosts_fingerprint && artifacts.dns_geo == *dns_geo_fingerprint
        })
    }

    pub fn digest_hex(&self) -> String {
        format!("{self}")
    }
}

impl fmt::Debug for PolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PolicyId")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.digest {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("DNS upstream '{upstream}' has an invalid endpoint: {source}")]
    InvalidEndpoint {
        upstream: String,
        #[source]
        source: anyhow::Error,
    },
    #[error("DNS policy contains an empty {field}")]
    EmptyName { field: &'static str },
    #[error("DNS policy contains invalid endpoint host '{value}'")]
    InvalidHost { value: String },
    #[error("DNS policy contains invalid client subnet: {source}")]
    InvalidClientSubnet {
        #[source]
        source: honk_config::dns::DnsClientSubnetError,
    },
    #[error("DNS policy contains invalid CIDR '{value}'")]
    InvalidCidr { value: String },
    #[error("DNS policy contains invalid regex '{value}': {source}")]
    InvalidRegex {
        value: String,
        #[source]
        source: regex::Error,
    },
    #[error("DNS canonical field is too large to encode")]
    FieldTooLarge,
}

#[cfg(test)]
mod normalization_tests;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod artifact_tests {
    use super::*;

    #[test]
    fn artifact_digests_are_domain_separated_from_canonical_config() {
        let config = DnsConfig::default();
        let zero = [0; 32];
        let one = [1; 32];
        let base = PolicyId::from_config_with_artifacts(&config, &zero, &zero).unwrap();
        let hosts_changed = PolicyId::from_config_with_artifacts(&config, &one, &zero).unwrap();
        let geo_changed = PolicyId::from_config_with_artifacts(&config, &zero, &one).unwrap();
        let isolated = PolicyId::from_config(&config).unwrap();

        assert_ne!(base, hosts_changed);
        assert_ne!(base, geo_changed);
        assert_ne!(hosts_changed, geo_changed);
        assert_ne!(base, isolated);
        assert_eq!(base.canonical_bytes(), isolated.canonical_bytes());
    }
}
