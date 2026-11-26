use std::collections::{HashMap, HashSet};

use honk_config::Config;
use honk_config::node::{MAX_CHAIN_HOPS, Node};
use uuid::Uuid;

use super::{IndexedOutcome, IndexedOutcomeKind, has_unsupported_plugin};

pub(super) enum RawChainEntry {
    Candidate {
        ordinal: usize,
        explicit_tag: Option<String>,
        detour: Option<String>,
        node: Node,
    },
    Group {
        ordinal: usize,
        explicit_tag: Option<String>,
        reason: &'static str,
    },
    Builtin {
        ordinal: usize,
        explicit_tag: Option<String>,
        reason: &'static str,
    },
    Rejected {
        ordinal: usize,
        explicit_tag: Option<String>,
        kind: IndexedOutcomeKind,
    },
}

impl RawChainEntry {
    fn explicit_tag(&self) -> Option<&str> {
        match self {
            Self::Candidate { explicit_tag, .. }
            | Self::Group { explicit_tag, .. }
            | Self::Builtin { explicit_tag, .. }
            | Self::Rejected { explicit_tag, .. } => explicit_tag.as_deref(),
        }
    }

    fn candidate_node(&self) -> Option<&Node> {
        match self {
            Self::Candidate { node, .. } => Some(node),
            _ => None,
        }
    }
}

#[derive(Clone, Copy)]
enum TagTarget {
    Entry(usize),
    ExtraGroup,
    Ambiguous,
}

#[derive(Clone, Copy)]
enum ChainReject {
    Malformed(&'static str),
    Unsupported(&'static str),
}

impl ChainReject {
    fn into_outcome(self, ordinal: usize, path: &'static str) -> IndexedOutcome {
        let kind = match self {
            Self::Malformed(reason) => IndexedOutcomeKind::Malformed((None, reason)),
            Self::Unsupported(reason) => IndexedOutcomeKind::Unsupported((None, reason)),
        };
        IndexedOutcome {
            ordinal,
            line: None,
            path,
            kind,
        }
    }
}

type ResolvedHops = Option<Result<Vec<usize>, ChainReject>>;
type BuiltChain = Option<Result<(Vec<Uuid>, Node), ChainReject>>;

fn is_builtin_detour_target(target: &str) -> bool {
    target.eq_ignore_ascii_case(Config::BUILTIN_DIRECT_NODE)
        || target.eq_ignore_ascii_case(Config::BUILTIN_BLOCK_NODE)
        || target.eq_ignore_ascii_case("dns")
        || target.eq_ignore_ascii_case("reject")
        || target.eq_ignore_ascii_case("reject-drop")
        || target.eq_ignore_ascii_case("pass")
        || target.eq_ignore_ascii_case("compatible")
}

pub(super) fn is_synthesized_chain_hop(node: &Node) -> bool {
    if node.chain_hops().is_some() {
        return false;
    }
    let prefix = format!("chain-hop-{}", node.id);
    node.name == prefix
        || node
            .name
            .strip_prefix(&prefix)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
}

fn resolve_hop_indices(
    start_idx: usize,
    first_detour: &str,
    entries: &[RawChainEntry],
    tags: &HashMap<&str, TagTarget>,
) -> Result<Vec<usize>, ChainReject> {
    let mut chain_indices = vec![start_idx];
    let mut next_target = first_detour;
    loop {
        if matches!(
            next_target,
            Config::BUILTIN_DIRECT_NODE | Config::BUILTIN_BLOCK_NODE
        ) {
            return Err(ChainReject::Unsupported(
                "subscription chain hop must be a concrete proxy node",
            ));
        }
        let parent_idx = match tags.get(next_target).copied() {
            Some(TagTarget::Ambiguous) => {
                return Err(ChainReject::Malformed(
                    "subscription chain hop reference is ambiguous",
                ));
            }
            Some(TagTarget::ExtraGroup) => {
                return Err(ChainReject::Unsupported(
                    "subscription chain cannot detour through a group",
                ));
            }
            None => {
                return if is_builtin_detour_target(next_target) {
                    Err(ChainReject::Unsupported(
                        "subscription chain hop must be a concrete proxy node",
                    ))
                } else {
                    Err(ChainReject::Malformed(
                        "subscription chain hop does not exist",
                    ))
                };
            }
            Some(TagTarget::Entry(idx)) => idx,
        };

        if chain_indices.contains(&parent_idx) {
            return Err(ChainReject::Malformed(
                "subscription chain contains a cycle",
            ));
        }

        match &entries[parent_idx] {
            RawChainEntry::Group { .. } => {
                return Err(ChainReject::Unsupported(
                    "subscription chain cannot detour through a group",
                ));
            }
            RawChainEntry::Builtin { .. } => {
                return Err(ChainReject::Unsupported(
                    "subscription chain hop must be a concrete proxy node",
                ));
            }
            RawChainEntry::Rejected { kind, .. } => {
                return if matches!(kind, IndexedOutcomeKind::Unsupported(_)) {
                    Err(ChainReject::Unsupported(
                        "subscription chain hop uses an unsupported proxy feature",
                    ))
                } else {
                    Err(ChainReject::Malformed("subscription chain hop is invalid"))
                };
            }
            RawChainEntry::Candidate { detour, .. } => {
                chain_indices.push(parent_idx);
                if chain_indices.len() > MAX_CHAIN_HOPS {
                    return Err(ChainReject::Malformed(
                        "subscription chain exceeds maximum hop count",
                    ));
                }
                match detour.as_deref() {
                    Some(further) => next_target = further,
                    None => break,
                }
            }
        }
    }

    chain_indices.reverse();

    let mut seen_hop_ids = [Uuid::nil(); MAX_CHAIN_HOPS];
    for (hop_pos, &hop_idx) in chain_indices.iter().enumerate() {
        let Some(hop_node) = entries[hop_idx].candidate_node() else {
            return Err(ChainReject::Malformed("subscription chain hop is invalid"));
        };
        if seen_hop_ids[..hop_pos].contains(&hop_node.id) {
            return Err(ChainReject::Malformed(
                "subscription chain repeats a physical hop endpoint",
            ));
        }
        seen_hop_ids[hop_pos] = hop_node.id;
        if hop_pos > 0 && !hop_node.supports_tunneled_dial() {
            return Err(ChainReject::Unsupported(
                "subscription chain hop after the entry does not support tunneled dial",
            ));
        }
    }

    Ok(chain_indices)
}

pub(super) fn emit_resolved_entries(
    mut entries: Vec<RawChainEntry>,
    extra_group_tags: &[String],
    path: &'static str,
    subscription_id: Option<Uuid>,
    mut emit: impl FnMut(IndexedOutcome),
) {
    for entry in &mut entries {
        if matches!(entry, RawChainEntry::Candidate { node, .. } if has_unsupported_plugin(node)) {
            let (ordinal, explicit_tag) = match std::mem::replace(
                entry,
                RawChainEntry::Builtin {
                    ordinal: 0,
                    explicit_tag: None,
                    reason: "",
                },
            ) {
                RawChainEntry::Candidate {
                    ordinal,
                    explicit_tag,
                    ..
                } => (ordinal, explicit_tag),
                _ => unreachable!(),
            };
            *entry = RawChainEntry::Rejected {
                ordinal,
                explicit_tag,
                kind: IndexedOutcomeKind::Unsupported((
                    None,
                    "subscription node uses an unsupported proxy plugin; ignored",
                )),
            };
        }
    }

    let mut tags: HashMap<&str, TagTarget> = HashMap::new();
    let mut first_standalone_by_id: HashMap<Uuid, usize> = HashMap::new();
    for (idx, entry) in entries.iter().enumerate() {
        if let Some(tag) = entry.explicit_tag() {
            tags.entry(tag)
                .and_modify(|slot| *slot = TagTarget::Ambiguous)
                .or_insert(TagTarget::Entry(idx));
        }
        if let RawChainEntry::Candidate {
            detour: None, node, ..
        } = entry
        {
            first_standalone_by_id.entry(node.id).or_insert(idx);
        }
    }
    for group_tag in extra_group_tags {
        tags.entry(group_tag.as_str())
            .and_modify(|slot| {
                if !matches!(slot, TagTarget::ExtraGroup) {
                    *slot = TagTarget::Ambiguous;
                }
            })
            .or_insert(TagTarget::ExtraGroup);
    }

    let mut resolved: Vec<ResolvedHops> = Vec::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        match entry {
            RawChainEntry::Candidate {
                detour: Some(detour),
                node,
                ..
            } => {
                let mut result = resolve_hop_indices(idx, detour, &entries, &tags);
                if let Ok(hop_indices) = &result {
                    for &hop_idx in hop_indices {
                        let hop_id = entries[hop_idx].candidate_node().unwrap().id;
                        if let Some(&standalone_idx) = first_standalone_by_id.get(&hop_id) {
                            let standalone_name =
                                &entries[standalone_idx].candidate_node().unwrap().name;
                            if matches!(
                                standalone_name.as_str(),
                                Config::BUILTIN_DIRECT_NODE | Config::BUILTIN_BLOCK_NODE
                            ) {
                                result = Err(ChainReject::Unsupported(
                                    "subscription chain hop must be a concrete proxy node",
                                ));
                                break;
                            }
                            if standalone_name == &node.name {
                                result = Err(ChainReject::Malformed(
                                    "subscription chain hop reference is ambiguous",
                                ));
                                break;
                            }
                        }
                    }
                }
                resolved.push(Some(result));
            }
            _ => resolved.push(None),
        }
    }

    let mut retained_name_counts: HashMap<&str, usize> = HashMap::new();
    for &standalone_idx in first_standalone_by_id.values() {
        let name = entries[standalone_idx]
            .candidate_node()
            .unwrap()
            .name
            .as_str();
        *retained_name_counts.entry(name).or_insert(0) += 1;
    }
    let mut seen_chain_signatures: HashSet<Vec<Uuid>> = HashSet::new();
    for (idx, item) in resolved.iter().enumerate() {
        if let Some(Ok(hop_indices)) = item {
            let signature: Vec<Uuid> = hop_indices
                .iter()
                .map(|&hop_idx| entries[hop_idx].candidate_node().unwrap().id)
                .collect();
            if seen_chain_signatures.insert(signature) {
                let name = entries[idx].candidate_node().unwrap().name.as_str();
                *retained_name_counts.entry(name).or_insert(0) += 1;
            }
        }
    }

    for item in &mut resolved {
        let Some(Ok(hop_indices)) = item else {
            continue;
        };
        let collides = hop_indices.iter().any(|&hop_idx| {
            let hop_id = entries[hop_idx].candidate_node().unwrap().id;
            first_standalone_by_id
                .get(&hop_id)
                .is_some_and(|&standalone_idx| {
                    let name = entries[standalone_idx]
                        .candidate_node()
                        .unwrap()
                        .name
                        .as_str();
                    retained_name_counts.get(name).copied().unwrap_or(0) > 1
                })
        });
        if collides {
            *item = Some(Err(ChainReject::Malformed(
                "subscription chain hop reference is ambiguous",
            )));
        }
    }

    let mut used_names: HashSet<String> = HashSet::from([
        Config::BUILTIN_DIRECT_NODE.to_owned(),
        Config::BUILTIN_BLOCK_NODE.to_owned(),
    ]);
    for (idx, entry) in entries.iter().enumerate() {
        if let RawChainEntry::Candidate { detour, node, .. } = entry
            && (detour.is_none() || matches!(resolved[idx], Some(Ok(_))))
        {
            used_names.insert(node.name.clone());
        }
    }

    let mut backing_hops: HashMap<Uuid, Node> = HashMap::new();
    for item in &resolved {
        let Some(Ok(hop_indices)) = item else {
            continue;
        };
        for &hop_idx in hop_indices {
            let hop_node = entries[hop_idx].candidate_node().unwrap();
            if first_standalone_by_id.contains_key(&hop_node.id)
                || backing_hops.contains_key(&hop_node.id)
            {
                continue;
            }
            let base = format!("chain-hop-{}", hop_node.id);
            let mut chosen = base.clone();
            let mut suffix = 2usize;
            while !used_names.insert(chosen.clone()) {
                chosen = format!("{base}-{suffix}");
                suffix += 1;
            }
            let mut backing = hop_node.clone();
            backing.name = chosen;
            backing.subscription_id = subscription_id;
            backing_hops.insert(hop_node.id, backing);
        }
    }

    let mut chain_outcomes: Vec<BuiltChain> = Vec::with_capacity(entries.len());
    for (idx, item) in resolved.into_iter().enumerate() {
        let Some(outcome) = item else {
            chain_outcomes.push(None);
            continue;
        };
        let mapped = match outcome {
            Err(reject) => Err(reject),
            Ok(hop_indices) => {
                let entry_name = &entries[idx].candidate_node().unwrap().name;
                let mut hop_ids = Vec::with_capacity(hop_indices.len());
                let mut hop_refs = Vec::with_capacity(hop_indices.len());
                for hop_idx in hop_indices {
                    let hop_id = entries[hop_idx].candidate_node().unwrap().id;
                    hop_ids.push(hop_id);
                    let hop_ref = if let Some(&standalone_idx) = first_standalone_by_id.get(&hop_id)
                    {
                        entries[standalone_idx].candidate_node().unwrap()
                    } else {
                        &backing_hops[&hop_id]
                    };
                    hop_refs.push(hop_ref);
                }
                match Node::chain_from_nodes(entry_name, &hop_refs) {
                    Ok(mut chain_node) => {
                        chain_node.subscription_id = subscription_id;
                        Ok((hop_ids, chain_node))
                    }
                    Err(_) => Err(ChainReject::Malformed("subscription chain hop is invalid")),
                }
            }
        };
        chain_outcomes.push(Some(mapped));
    }

    for (idx, entry) in entries.into_iter().enumerate() {
        match entry {
            RawChainEntry::Group {
                ordinal, reason, ..
            }
            | RawChainEntry::Builtin {
                ordinal, reason, ..
            } => {
                emit(IndexedOutcome::profile(ordinal, path, reason));
            }
            RawChainEntry::Rejected { ordinal, kind, .. } => {
                emit(IndexedOutcome {
                    ordinal,
                    line: None,
                    path,
                    kind,
                });
            }
            RawChainEntry::Candidate {
                ordinal,
                detour: None,
                node,
                ..
            } => {
                emit(IndexedOutcome::node(ordinal, path, node));
            }
            RawChainEntry::Candidate {
                ordinal,
                detour: Some(_),
                ..
            } => match chain_outcomes[idx].take().unwrap() {
                Err(reject) => {
                    emit(reject.into_outcome(ordinal, path));
                }
                Ok((hop_ids, chain_node)) => {
                    for hop_id in hop_ids {
                        if let Some(backing) = backing_hops.remove(&hop_id) {
                            emit(IndexedOutcome::node(ordinal, path, backing));
                        }
                    }
                    emit(IndexedOutcome::node(ordinal, path, chain_node));
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_plugin_ambiguous_chain_tag_and_backing_name_disambiguation_hold() {
        let plugin_hop = Node::from_share_link(
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@127.0.0.1:8388/?plugin=obfs-local#plug",
        )
        .unwrap();
        let exit = Node::from_share_link("socks5://127.0.0.1:1080#exit").unwrap();
        let hidden_hop = Node::from_share_link("socks5://127.0.0.1:1081#hidden").unwrap();
        let taken_name = format!("chain-hop-{}", hidden_hop.id);
        let mut collide_standalone =
            Node::from_share_link("socks5://127.0.0.1:1082#taken").unwrap();
        collide_standalone.name = taken_name.clone();
        let valid_exit = Node::from_share_link("socks5://127.0.0.1:1083#via-hidden").unwrap();
        let dup_chain_a = Node::from_share_link("socks5://127.0.0.1:1084#dup-chain").unwrap();
        let dup_chain_b = Node::from_share_link("socks5://127.0.0.1:1085#dup-chain").unwrap();
        let via_dup_chain = Node::from_share_link("socks5://127.0.0.1:1086#via-dup").unwrap();

        let entries = vec![
            RawChainEntry::Candidate {
                ordinal: 1,
                explicit_tag: Some("plug".into()),
                detour: None,
                node: plugin_hop,
            },
            RawChainEntry::Candidate {
                ordinal: 2,
                explicit_tag: Some("via-plug".into()),
                detour: Some("plug".into()),
                node: exit,
            },
            RawChainEntry::Candidate {
                ordinal: 3,
                explicit_tag: Some("taken".into()),
                detour: None,
                node: collide_standalone,
            },
            RawChainEntry::Candidate {
                ordinal: 4,
                explicit_tag: Some("hidden".into()),
                detour: Some("taken".into()),
                node: hidden_hop,
            },
            RawChainEntry::Candidate {
                ordinal: 5,
                explicit_tag: Some("via-hidden".into()),
                detour: Some("hidden".into()),
                node: valid_exit,
            },
            RawChainEntry::Candidate {
                ordinal: 6,
                explicit_tag: Some("dup-chain".into()),
                detour: Some("taken".into()),
                node: dup_chain_a,
            },
            RawChainEntry::Candidate {
                ordinal: 7,
                explicit_tag: Some("dup-chain".into()),
                detour: Some("taken".into()),
                node: dup_chain_b,
            },
            RawChainEntry::Candidate {
                ordinal: 8,
                explicit_tag: Some("via-dup".into()),
                detour: Some("dup-chain".into()),
                node: via_dup_chain,
            },
        ];

        let mut outcomes = Vec::new();
        emit_resolved_entries(entries, &[], "entries", None, |outcome| {
            outcomes.push(outcome);
        });

        assert!(matches!(
            (&outcomes[0].ordinal, &outcomes[0].kind),
            (1, IndexedOutcomeKind::Unsupported(_))
        ));
        assert!(matches!(
            (&outcomes[1].ordinal, &outcomes[1].kind),
            (2, IndexedOutcomeKind::Unsupported(_))
        ));
        assert!(matches!(
            (
                &outcomes.last().unwrap().ordinal,
                &outcomes.last().unwrap().kind
            ),
            (8, IndexedOutcomeKind::Malformed(_))
        ));

        let nodes: Vec<_> = outcomes
            .into_iter()
            .filter_map(|outcome| match outcome.kind {
                IndexedOutcomeKind::Node(node) => Some(node),
                _ => None,
            })
            .collect();
        let expected_disambiguated = format!("{taken_name}-2");
        assert!(nodes.iter().any(|n| n.name == expected_disambiguated));
        let config = Config {
            nodes,
            ..Default::default()
        };
        config.validate_assembled().unwrap();
        let via_hidden = config
            .nodes
            .iter()
            .find(|n| n.name == "via-hidden")
            .unwrap();
        assert_eq!(via_hidden.chain_hops().unwrap()[0], taken_name);
        assert_eq!(via_hidden.chain_hops().unwrap()[1], expected_disambiguated);
    }
}
