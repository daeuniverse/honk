use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use super::{BinaryLpmTrie, GeositeDomain, GeositeMatcher};

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
    ip: Vec<Arc<IpMatcher>>,
    /// Keyed by selector name, which pins content only within one build's
    /// assets, so these are never offered across builds.
    geosite: std::collections::HashMap<String, Arc<GeositeMatcher>>,
}

impl SharedMatchers {
    pub(crate) fn ip(&mut self, nets: Vec<IpNet>) -> Arc<IpMatcher> {
        if let Some(matcher) = self.ip.iter().find(|matcher| matcher.nets() == nets) {
            return Arc::clone(matcher);
        }
        let matcher = Arc::new(IpMatcher::new(nets));
        self.ip.push(Arc::clone(&matcher));
        matcher
    }

    /// One matcher per selector (a category plus its attribute filter).
    pub(crate) fn geosite(&mut self, code: &str, domains: &[GeositeDomain]) -> Arc<GeositeMatcher> {
        let matcher = self.geosite.entry(code.trim().to_lowercase());
        Arc::clone(matcher.or_insert_with(|| Arc::new(GeositeMatcher::build(domains))))
    }

    /// DNS answer matching needs only the trie; the nets stay in this build-local registry.
    pub(crate) fn trie(&mut self, nets: Vec<IpNet>) -> Arc<BinaryLpmTrie> {
        Arc::clone(self.ip(nets).trie())
    }

    /// Offers live matchers so a rebuild keeps them for unchanged network lists.
    pub(crate) fn offer<'a>(&mut self, matchers: impl IntoIterator<Item = &'a Arc<IpMatcher>>) {
        for matcher in matchers {
            if !self.ip.iter().any(|known| known.nets() == matcher.nets()) {
                self.ip.push(Arc::clone(matcher));
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
