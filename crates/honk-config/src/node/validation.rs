use std::collections::HashMap;

use crate::diagnostic::{DiagnosticSources, SafeValue, SettingPath, SourceRef};
use crate::error::{DetailedConfigError, ErrorCategory};
use crate::node::{Node, OutboundConfig};
use crate::options::vocab::{
    optional_flow, packet_network, parse_port_hopping, vmess_cipher, xhttp_stream_transport,
};
/// Longest accepted proxy chain. Each hop adds a round trip and a handshake
/// to every connection.
pub const MAX_CHAIN_HOPS: usize = 4;

pub(super) fn semantic_error(
    source: &SourceRef,
    setting: SettingPath,
    message: &'static str,
) -> crate::error::DetailedConfigError {
    crate::error::DetailedConfigError::new(
        crate::error::ErrorCategory::Validation,
        "invalid-config-value",
        source.clone(),
        setting,
        message,
    )
}

#[derive(Debug)]
pub(super) struct ValidationFailure {
    field: Option<&'static str>,
    message: &'static str,
}

impl ValidationFailure {
    pub(super) fn new(field: Option<&'static str>, message: &'static str) -> Self {
        Self { field, message }
    }

    pub(super) fn into_detailed(
        self,
        source: SourceRef,
        mut setting: SettingPath,
    ) -> DetailedConfigError {
        if let Some(field) = self.field {
            setting = setting.field(field);
        }
        DetailedConfigError::new(
            ErrorCategory::Validation,
            "invalid-config-value",
            source,
            setting,
            self.message,
        )
    }

    fn at_node(self) -> DetailedConfigError {
        self.into_detailed(
            DiagnosticSources::new(None).root(),
            SettingPath::new("nodes"),
        )
    }

    pub(super) fn into_legacy(self) -> crate::ConfigError {
        self.at_node().into_legacy()
    }
}

impl Node {
    /// Validate intrinsic node settings through the legacy error API.
    pub fn validate(&self) -> Result<(), crate::ConfigError> {
        self.validate_inner()
            .map_err(ValidationFailure::into_legacy)
    }

    pub(crate) fn validate_detailed(&self) -> Result<(), DetailedConfigError> {
        self.validate_inner().map_err(ValidationFailure::at_node)
    }

    pub(crate) fn validate_detailed_at(
        &self,
        source: &SourceRef,
        setting: &SettingPath,
    ) -> Result<(), DetailedConfigError> {
        self.validate_inner()
            .map_err(|error| error.into_detailed(source.clone(), setting.clone()))
    }

    fn validate_inner(&self) -> Result<(), ValidationFailure> {
        let invalid = ValidationFailure::new;
        if matches!(
            self.outbound,
            OutboundConfig::Direct | OutboundConfig::Block
        ) {
            let (name, id) = match self.outbound {
                OutboundConfig::Direct => ("direct", crate::config::DIRECT_NODE_ID),
                _ => ("block", crate::config::BLOCK_NODE_ID),
            };
            return if self.name == name
                && self.id == id
                && self.host.is_empty()
                && self.address.is_empty()
                && self.port == 0
            {
                Ok(())
            } else {
                Err(invalid(
                    None,
                    "node name and builtin identity must satisfy the protocol contract",
                ))
            };
        }
        if self.name.is_empty() {
            return Err(invalid(Some("name"), "node name must not be empty"));
        }
        if let Some(hops) = self.chain_hops() {
            return self.validate_chain(hops);
        }
        if self.host().trim().is_empty()
            || self.port == 0
            || (self.host.is_empty() && self.address.matches(':').count() > 1)
        {
            return Err(invalid(
                None,
                "node requires an effective host and nonzero explicit port; address-only IPv6 is unsupported",
            ));
        }
        if let Some(transport) = self.transport() {
            xhttp_stream_transport(&transport.transport)
                .map_err(|message| invalid(Some("transport"), message))?;
        }
        if let Some(network) = self.network() {
            packet_network(network)
                .and_then(|network| network.ok_or("invalid packet network"))
                .map_err(|message| invalid(Some("network"), message))?;
        }
        if self
            .tls()
            .is_some_and(|tls| tls.sni.as_deref().is_some_and(|sni| sni.trim().is_empty()))
        {
            return Err(invalid(
                Some("sni"),
                "canonical TLS server name must not be empty",
            ));
        }
        let uuid = match &self.outbound {
            OutboundConfig::Vmess(config) => {
                if config.encryption.is_some() {
                    vmess_cipher(config.encryption.as_deref())
                        .and_then(|cipher| cipher.ok_or("unsupported VMess cipher"))
                        .map_err(|message| invalid(Some("encryption"), message))?;
                }
                config.uuid.as_deref()
            }
            OutboundConfig::Vless(config) => {
                if let Some(flow) = config.flow.as_deref() {
                    optional_flow(Some(flow))
                        .and_then(|flow| flow.ok_or("unsupported VLESS flow"))
                        .map_err(|message| invalid(Some("flow"), message))?;
                    if !config.is_encrypted()
                        && !config.tls.enabled
                        && config.tls.reality_public_key.is_none()
                    {
                        return Err(invalid(Some("flow"), "VLESS flow requires TLS or REALITY"));
                    }
                }
                if config.encryption.as_deref().is_some_and(|value| {
                    let value = value.trim();
                    !value.is_empty()
                        && value != "none"
                        && !value.starts_with("mlkem768x25519plus.")
                }) {
                    return Err(invalid(Some("encryption"), "unsupported VLESS encryption"));
                }
                config.uuid.as_deref()
            }
            OutboundConfig::Tuic(config) => config.uuid.as_deref(),
            OutboundConfig::Juicity(config) => config.uuid.as_deref(),
            OutboundConfig::Hysteria2(config) => {
                if config
                    .port_hopping
                    .as_deref()
                    .is_some_and(|spec| parse_port_hopping(spec).is_none())
                {
                    return Err(invalid(
                        Some("hy2_port_hopping"),
                        "hopping ports must be nonzero, valid ranges, and nonrepeating",
                    ));
                }
                return self.validate_protocol_inner();
            }
            _ => return self.validate_protocol_inner(),
        };
        let uuid = uuid.ok_or_else(|| invalid(None, "protocol requires a valid UUID"))?;
        uuid::Uuid::parse_str(uuid).map_err(|_| invalid(None, "protocol requires a valid UUID"))?;
        self.validate_protocol_inner()
    }

    /// A chain owns no endpoint; its hops are names resolved after assembly
    /// by `Config::validate_assembled`.
    fn validate_chain(&self, hops: &[String]) -> Result<(), ValidationFailure> {
        let invalid = ValidationFailure::new;
        if !self.host.is_empty() || !self.address.is_empty() || self.port != 0 {
            return Err(invalid(None, "chain node must not set an address or port"));
        }
        if hops.len() < 2 {
            return Err(invalid(Some("hops"), "chain node needs at least two hops"));
        }
        if hops.len() > MAX_CHAIN_HOPS {
            return Err(invalid(Some("hops"), "chain node allows at most four hops"));
        }
        if hops.iter().any(|hop| hop.trim().is_empty()) {
            return Err(invalid(Some("hops"), "chain hop names must not be empty"));
        }
        if hops.contains(&self.name) {
            return Err(invalid(
                Some("hops"),
                "chain node must not use itself as a hop",
            ));
        }
        Ok(())
    }

    pub fn validate_protocol(&self) -> Result<(), crate::ConfigError> {
        self.validate_protocol_inner()
            .map_err(ValidationFailure::into_legacy)
    }

    fn validate_protocol_inner(&self) -> Result<(), ValidationFailure> {
        if let Some(transport) = self.transport() {
            transport
                .check()
                .map_err(|(field, message)| ValidationFailure::new(Some(field), message))?;
        }
        if let Some(config) = self.vless() {
            config.validate_fields()?;
        }
        let Some(tls) = self.tls() else { return Ok(()) };
        tls.validate_alpn()?;
        let reality = tls
            .effective_reality_public_key()
            .map_err(|message| ValidationFailure::new(Some("reality_public_key"), message))?
            .is_some();
        if self.is_xhttp() {
            if let Some(view) = self.xhttp_download_view() {
                // REALITY's auto mode would also need Xray's stream-up switch for download peers.
                if reality {
                    return Err(ValidationFailure::new(
                        Some("xhttp"),
                        "XHTTP download settings require a non-REALITY upload",
                    ));
                }
                view.validate_inner()
                    .map_err(|failure| ValidationFailure::new(Some("xhttp"), failure.message))?;
            }
            return tls
                .check_xhttp_alpn()
                .map_err(|message| ValidationFailure::new(Some("tls_alpn"), message));
        }
        if tls.alpn.is_empty() {
            return Ok(());
        }
        let raw_tcp = self.anytls().is_some()
            || self
                .transport()
                .is_some_and(|transport| matches!(transport.transport.as_str(), "" | "tcp"));
        if !tls.enabled || reality || !raw_tcp {
            return Err(ValidationFailure::new(
                Some("tls_alpn"),
                "TLS ALPN requires enabled non-REALITY raw TCP TLS",
            ));
        }
        Ok(())
    }
}

fn collection_error(
    index: usize,
    code: &'static str,
    message: &'static str,
) -> DetailedConfigError {
    let ordinal = index + 1;
    let mut error = DetailedConfigError::new(
        ErrorCategory::Validation,
        code,
        DiagnosticSources::new(None).root(),
        SettingPath::new("nodes").index(ordinal),
        message,
    );
    error.diagnostic.value = SafeValue::Ordinal(ordinal);
    error.diagnostic.entry_index = Some(ordinal);
    error
}

/// Validate an assembled node collection without changing any supplied value.
pub fn validate_node_collection(nodes: &[Node]) -> Result<(), DetailedConfigError> {
    for (index, node) in nodes.iter().enumerate() {
        if node.id.is_nil() {
            return Err(collection_error(
                index,
                "nil-node-id",
                "node ID must not be nil",
            ));
        }
    }
    for (index, node) in nodes.iter().enumerate() {
        if let Err(error) = node.validate_inner() {
            let ordinal = index + 1;
            let mut error = error.into_detailed(
                DiagnosticSources::new(None).root(),
                SettingPath::new("nodes").index(ordinal),
            );
            error.diagnostic.value = SafeValue::Ordinal(ordinal);
            error.diagnostic.entry_index = Some(ordinal);
            return Err(error);
        }
    }
    for (index, node) in nodes.iter().enumerate() {
        if matches!(
            node.outbound,
            OutboundConfig::Direct | OutboundConfig::Block
        ) {
            continue;
        }
        if node.id != node.derive_id() {
            return Err(collection_error(
                index,
                "noncanonical-node-id",
                "node ID does not match canonical identity",
            ));
        }
    }
    if nodes.len() > 1 {
        let mut ids = HashMap::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            if let Some(first) = ids.insert(node.id, index) {
                let mut error = collection_error(
                    index,
                    "duplicate-node-id",
                    "node ID duplicates another node",
                );
                error.diagnostic.related_indices.push(first + 1);
                return Err(error);
            }
        }
    }
    Ok(())
}

/// A proxy chain whose hop names resolved against an assembled collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedChain {
    /// The chain's index in the collection.
    pub index: usize,
    /// The hops' node IDs, entry first.
    pub hops: Vec<uuid::Uuid>,
}

/// Resolve every proxy chain hop by name against an assembled collection:
/// each hop names exactly one proxy node that is not itself a chain, and every
/// hop after the first can run over a tunneled stream.
pub fn resolve_chain_hops(nodes: &[Node]) -> Result<Vec<ResolvedChain>, DetailedConfigError> {
    let mut chains = Vec::new();
    for (node_index, node) in nodes.iter().enumerate() {
        let Some(hops) = node.chain_hops() else {
            continue;
        };
        let mut resolved = Vec::with_capacity(hops.len());
        for (hop_index, hop) in hops.iter().enumerate() {
            let reject = |code, message| {
                let mut error = collection_error(node_index, code, message);
                error.diagnostic.setting = SettingPath::new("nodes")
                    .index(node_index + 1)
                    .field("hops")
                    .index(hop_index + 1);
                error
            };
            let mut matches = nodes.iter().filter(|candidate| candidate.name == *hop);
            let target = match (matches.next(), matches.next()) {
                (Some(target), None) => target,
                (None, _)
                    if matches!(
                        hop.as_str(),
                        crate::Config::BUILTIN_DIRECT_NODE | crate::Config::BUILTIN_BLOCK_NODE
                    ) =>
                {
                    return Err(reject(
                        "unsupported-chain-hop",
                        "chain hop must be a proxy node, not a builtin",
                    ));
                }
                (None, _) => {
                    return Err(reject(
                        "invalid-chain-hop-reference",
                        "chain hop is not an assembled node",
                    ));
                }
                (Some(_), Some(_)) => {
                    return Err(reject(
                        "ambiguous-chain-hop-reference",
                        "chain hop name matches several assembled nodes",
                    ));
                }
            };
            match target.outbound {
                OutboundConfig::Direct | OutboundConfig::Block => {
                    return Err(reject(
                        "unsupported-chain-hop",
                        "chain hop must be a proxy node, not a builtin",
                    ));
                }
                OutboundConfig::Chain { .. } => {
                    return Err(reject(
                        "unsupported-chain-hop",
                        "chain hop must not be another chain",
                    ));
                }
                _ if hop_index > 0 && !target.supports_tunneled_dial() => {
                    return Err(reject(
                        "unsupported-chain-hop",
                        "chain hop after the first must support tunneled dial",
                    ));
                }
                _ => {}
            }
            resolved.push(target.id);
        }
        chains.push(ResolvedChain {
            index: node_index,
            hops: resolved,
        });
    }
    Ok(chains)
}
