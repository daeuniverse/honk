use std::hash::BuildHasher as _;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use super::{
    BinaryLpmTrie, GeoAssets,
    domain::{DomainMatcherDigest, GeositeMatcher, lowercase},
};

/// One canonical condition in a compiled routing rule.
#[derive(Debug, Clone)]
pub struct CompiledCondition {
    pub not: bool,
    pub predicate: CompiledPredicate,
}

/// Canonical routing predicates shared by the userspace evaluator and native compiler.
#[derive(Debug, Clone)]
pub enum CompiledPredicate {
    Domain(u32),
    DestinationIp(std::sync::Arc<IpMatcher>),
    SourceIp(std::sync::Arc<IpMatcher>),
    DestinationPort(Vec<PortRange>),
    SourcePort(Vec<PortRange>),
    Protocol(u8),
    IpVersion(u8),
    Dscp(Vec<u8>),
    ProcessName(Vec<String>),
    Mac(Vec<[u8; 6]>),
}

/// Immutable IP matcher retaining the source nets for compiler lowering and a trie for lookup.
#[derive(Debug, Clone)]
pub struct IpMatcher {
    nets: Vec<IpNet>,
    trie: Arc<BinaryLpmTrie>,
}

impl IpMatcher {
    pub(crate) fn new(nets: Vec<IpNet>) -> Self {
        let trie = Arc::new(BinaryLpmTrie::from_nets(&nets));
        Self { nets, trie }
    }

    pub fn nets(&self) -> &[IpNet] {
        &self.nets
    }

    pub fn matches(&self, ip: &IpAddr) -> bool {
        self.trie.matches(ip)
    }

    pub(crate) fn trie(&self) -> &Arc<BinaryLpmTrie> {
        &self.trie
    }
}

/// Hands out one matcher per exact ordered network list. Equal lists build
/// identical tries, so any holder's matcher is interchangeable.
#[derive(Default)]
pub(crate) struct SharedMatchers {
    hasher: std::hash::RandomState,
    /// Buckets by list hash: the interned lists stay in their matchers.
    ip: std::collections::HashMap<u64, Vec<Arc<IpMatcher>>>,
    /// Keyed by selector name, which pins content only within one build's
    /// assets, so these are never offered across builds.
    geosite: std::collections::HashMap<String, CachedGeosite>,
}

struct CachedGeosite {
    matcher: Arc<GeositeMatcher>,
    empty: bool,
    digest: Option<DomainMatcherDigest>,
}

impl SharedMatchers {
    pub(crate) fn ip(&mut self, nets: Vec<IpNet>) -> Arc<IpMatcher> {
        let known = self
            .ip
            .entry(self.hasher.hash_one(nets.as_slice()))
            .or_default();
        if let Some(matcher) = known.iter().find(|matcher| matcher.nets() == nets) {
            return Arc::clone(matcher);
        }
        let matcher = Arc::new(IpMatcher::new(nets));
        known.push(Arc::clone(&matcher));
        matcher
    }

    pub(crate) fn geosite(&mut self, code: &str, assets: &GeoAssets) -> Arc<GeositeMatcher> {
        self.normalized_geosite(&lowercase(code.trim()), assets)
    }

    pub(super) fn normalized_geosite(
        &mut self,
        code: &str,
        assets: &GeoAssets,
    ) -> Arc<GeositeMatcher> {
        self.with_geosite(code, assets, 1, |cached| Arc::clone(&cached.matcher))
    }

    pub(super) fn single_geosite(
        &mut self,
        codes: &[String],
        assets: &GeoAssets,
    ) -> Option<(DomainMatcherDigest, Arc<GeositeMatcher>)> {
        let (first, rest) = codes.split_first()?;
        let code = lowercase(first.trim());
        if !rest.iter().all(|other| lowercase(other.trim()) == code) {
            return None;
        }
        Some(self.with_geosite(&code, assets, codes.len(), |cached| {
            let digest = *cached
                .digest
                .get_or_insert_with(|| DomainMatcherDigest::geosite(assets.geosite_entries(&code)));
            (digest, Arc::clone(&cached.matcher))
        }))
    }

    fn with_geosite<T>(
        &mut self,
        code: &str,
        assets: &GeoAssets,
        uses: usize,
        visit: impl FnOnce(&mut CachedGeosite) -> T,
    ) -> T {
        let cached = if let Some(hit) = self.geosite.get_mut(code) {
            hit
        } else {
            let mut entries = assets.geosite_entries(code).peekable();
            let empty = entries.peek().is_none();
            self.geosite
                .entry(code.to_owned())
                .or_insert_with(|| CachedGeosite {
                    matcher: Arc::new(GeositeMatcher::build(entries)),
                    empty,
                    digest: None,
                })
        };
        if cached.empty {
            for _ in 0..uses {
                assets.report_empty_geosite(code);
            }
        }
        visit(cached)
    }

    /// DNS answer matching needs only the trie; the nets stay in this build-local registry.
    pub(crate) fn trie(&mut self, nets: Vec<IpNet>) -> Arc<BinaryLpmTrie> {
        Arc::clone(self.ip(nets).trie())
    }

    /// Offers live matchers so a rebuild keeps them for unchanged network lists.
    pub(crate) fn offer<'a>(&mut self, matchers: impl IntoIterator<Item = &'a Arc<IpMatcher>>) {
        for matcher in matchers {
            let known = self
                .ip
                .entry(self.hasher.hash_one(matcher.nets()))
                .or_default();
            if !known.iter().any(|known| known.nets() == matcher.nets()) {
                known.push(Arc::clone(matcher));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}
