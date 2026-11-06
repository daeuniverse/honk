use parking_lot::RwLockWriteGuard;
use sha2::{Digest, Sha256};

use super::*;

const MAX_LIVE_FORMATS: usize = 8;

pub(crate) struct Profile {
    pub(super) identity: Identity,
    format: honk_config::syslog::CompiledFormat,
    version: serde_json::Value,
    source: (String, String),
    pub(super) slot: Option<OwnedSemaphorePermit>,
}

impl Profile {
    pub(super) fn compile(
        global: &honk_config::config::GlobalConfig,
        identity: Identity,
    ) -> anyhow::Result<Self> {
        let format = honk_config::syslog::CompiledFormat::compile(
            &global.syslog_dns_template,
            &global.syslog_dns_json,
        )?;
        let source = (
            global.syslog_dns_template.clone(),
            global.syslog_dns_json.clone(),
        );
        let mut hash = Sha256::new();
        for value in [&source.0, &source.1] {
            hash.update((value.len() as u64).to_be_bytes());
            hash.update(value.as_bytes());
        }
        Ok(Self {
            identity,
            format,
            version: serde_json::Value::String(
                hash.finalize()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect(),
            ),
            source,
            slot: None,
        })
    }

    pub(super) fn write(
        &self,
        event: &serde_json::Value,
        output: &mut impl std::io::Write,
    ) -> std::io::Result<()> {
        static VERSION: std::sync::LazyLock<serde_json::Value> =
            std::sync::LazyLock::new(|| serde_json::Value::String(crate::VERSION.into()));
        self.format.write(event, &VERSION, &self.version, output)
    }
}

pub(crate) struct FormatPublication<'a> {
    guard: RwLockWriteGuard<'a, Option<Arc<Profile>>>,
    replacement: Option<Arc<Profile>>,
}

impl FormatPublication<'_> {
    pub(crate) fn commit(&mut self) {
        if let Some(replacement) = self.replacement.take() {
            *self.guard = Some(replacement);
        }
    }
}

impl DnsAudit {
    pub(crate) fn prepare_format(
        &self,
        global: &honk_config::config::GlobalConfig,
    ) -> anyhow::Result<Option<Arc<Profile>>> {
        let Some(current) = self.format.read().clone() else {
            return Ok(None);
        };
        if current.source.0 == global.syslog_dns_template
            && current.source.1 == global.syslog_dns_json
        {
            return Ok(None);
        }
        let slot = Arc::clone(&self.admission.formats)
            .try_acquire_owned()
            .map_err(|_| {
                anyhow::anyhow!(
                    "DNS audit retains eight template versions; retry after older requests drain"
                )
            })?;
        let mut profile = Profile::compile(global, current.identity.clone())?;
        profile.slot = Some(slot);
        Ok(Some(Arc::new(profile)))
    }

    pub(crate) fn prepare_publication(
        &self,
        replacement: Option<Arc<Profile>>,
    ) -> Option<FormatPublication<'_>> {
        replacement.map(|replacement| FormatPublication {
            guard: self.format.write(),
            replacement: Some(replacement),
        })
    }
}

pub(super) fn slots() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MAX_LIVE_FORMATS))
}
