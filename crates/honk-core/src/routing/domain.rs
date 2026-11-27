//! Domain predicate matchers, geosite expansion matcher, and their build-local interner.

use super::{GeoAssets, SharedMatchers, bounded_any};
use honk_ebpf_common::ROUTING_FACT_CAPACITY;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) enum GeositeDomain {
    Full(String),
    Domain(String),
    Keyword(String),
    Regex(Regex),
}

/// Fast matcher over a compiled geosite domain list.
///
/// Lookup semantics mirror the historical per-entry `match_geosite_domain`:
/// `Full` is a case-insensitive exact match, `Domain` matches the host itself
/// or any dot-boundary sub-domain (case-insensitive), `Keyword` is a
/// case-sensitive substring match, and `Regex` runs against the original
/// (non-lowercased) domain.
#[derive(Debug, Clone, Default)]
pub(crate) struct GeositeMatcher {
    /// Exact host names, stored lowercased.
    full: std::collections::HashSet<String>,
    /// Dot-boundary suffixes, stored lowercased.
    suffix: std::collections::HashSet<String>,
    /// Case-sensitive substring automaton for keywords.
    keyword_ac: Option<aho_corasick::AhoCorasick>,
    /// Full regular expressions (matched against the original domain).
    regex: Vec<Regex>,
}

impl GeositeMatcher {
    pub(crate) fn build<'a>(domains: impl IntoIterator<Item = &'a GeositeDomain>) -> Self {
        let mut matcher = GeositeMatcher::default();
        let mut keywords: Vec<&str> = Vec::new();
        for d in domains {
            match d {
                GeositeDomain::Full(v) => {
                    matcher.full.insert(v.to_lowercase());
                }
                GeositeDomain::Domain(v) => {
                    matcher.suffix.insert(v.to_lowercase());
                }
                GeositeDomain::Keyword(v) => keywords.push(v.as_str()),
                GeositeDomain::Regex(re) => matcher.regex.push(re.clone()),
            }
        }
        if !keywords.is_empty() {
            matcher.keyword_ac = aho_corasick::AhoCorasick::new(&keywords).ok();
        }
        matcher
    }

    pub(crate) fn matches(&self, domain: &str) -> bool {
        self.matches_bounded::<false>(domain, &lowercase(domain), None)
    }

    fn matches_bounded<const BOUNDED: bool>(
        &self,
        domain: &str,
        lower: &str,
        deadline: Option<std::time::Instant>,
    ) -> bool {
        if self.full.contains(lower) {
            return true;
        }
        // Dot-boundary suffix walk: check the host itself, then each parent.
        if !self.suffix.is_empty() {
            let mut d = lower;
            loop {
                if self.suffix.contains(d) {
                    return true;
                }
                match d.find('.') {
                    Some(i) => d = &d[i + 1..],
                    None => break,
                }
            }
        }
        if let Some(ac) = &self.keyword_ac
            && ac.is_match(domain)
        {
            return true;
        }
        bounded_any::<BOUNDED, _>(&self.regex, deadline, |re| re.is_match(domain))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct DomainMatcherDigest([u8; 32]);

impl DomainMatcherDigest {
    pub(super) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_entries(mut entries: Vec<(u8, Cow<'_, str>)>) -> Self {
        entries.sort_unstable();
        entries.dedup();
        let mut hash = Sha256::new();
        hash.update(b"honk.domain-matcher-key.v1\0");
        hash.update((entries.len() as u64).to_le_bytes());
        for (tag, text) in entries {
            hash.update([tag]);
            hash.update((text.len() as u64).to_le_bytes());
            hash.update(text.as_bytes());
        }
        Self(hash.finalize().into())
    }

    pub(super) fn geosite<'a>(entries: impl Iterator<Item = &'a GeositeDomain>) -> Self {
        Self::from_entries(entries.map(GeositeDomain::alternative).collect())
    }
}

impl GeositeDomain {
    fn alternative(&self) -> (u8, Cow<'_, str>) {
        match self {
            Self::Full(value) => (3, lowercase(value)),
            Self::Domain(value) => (4, lowercase(value)),
            Self::Keyword(value) => (5, Cow::Borrowed(value)),
            Self::Regex(value) => (6, Cow::Borrowed(value.as_str())),
        }
    }
}

/// One `domain(...)` call. Every entry, including expanded geosite codes, is
/// an alternative: dae ORs the arguments of a single call.
#[derive(Debug, Clone, Default)]
pub(super) struct DomainMatcher {
    patterns: Vec<Regex>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    /// One matcher per configured selector, matched as their union.
    pub(super) geosite: Vec<Arc<GeositeMatcher>>,
}

impl DomainMatcher {
    pub(super) fn from_selectors(
        domains: &[String],
        suffixes: &[String],
        keywords: &[String],
        regexes: &[String],
        codes: &[String],
        assets: &GeoAssets,
        shared: &mut SharedMatchers,
    ) -> anyhow::Result<(DomainMatcherDigest, Self)> {
        let mut selectors = Vec::new();
        let mut matchers = Vec::new();
        let mut seen = HashSet::new();
        for code in codes {
            let code = lowercase(code.trim());
            let matcher = shared.normalized_geosite(&code, assets);
            if codes.len() == 1 || seen.insert(Arc::as_ptr(&matcher)) {
                matchers.push(matcher);
                selectors.push(code);
            }
        }
        let entries = selectors
            .iter()
            .flat_map(|code| assets.geosite_entries(code));
        Self::new(domains, suffixes, keywords, regexes, entries, matchers)
    }

    pub(super) fn new<'a>(
        domains: &[String],
        suffixes: &[String],
        keywords: &[String],
        regexes: &[String],
        geosite: impl IntoIterator<Item = &'a GeositeDomain>,
        matchers: Vec<Arc<GeositeMatcher>>,
    ) -> anyhow::Result<(DomainMatcherDigest, Self)> {
        let mut patterns = Vec::with_capacity(regexes.len() + domains.len());
        for pattern in regexes {
            patterns.push(
                Regex::new(pattern)
                    .map_err(|error| anyhow::anyhow!("Invalid regex '{}': {}", pattern, error))?,
            );
        }
        for wildcard in domains {
            patterns.push(
                Regex::new(&glob_to_regex(wildcard)).map_err(|error| {
                    anyhow::anyhow!("Invalid pattern '{}': {}", wildcard, error)
                })?,
            );
        }
        let mut entries = Vec::with_capacity(patterns.len() + suffixes.len() + keywords.len());
        entries.extend(patterns.iter().map(|p| (0, Cow::Borrowed(p.as_str()))));
        entries.extend(suffixes.iter().map(|s| (1, Cow::Borrowed(s.as_str()))));
        entries.extend(keywords.iter().map(|s| (2, Cow::Borrowed(s.as_str()))));
        for domain in geosite {
            entries.push(domain.alternative());
        }
        let key = DomainMatcherDigest::from_entries(entries);
        Ok((
            key,
            Self {
                patterns,
                suffixes: suffixes.to_vec(),
                keywords: keywords.to_vec(),
                geosite: matchers,
            },
        ))
    }

    pub(super) fn matches(&self, domain: &str) -> bool {
        self.matches_bounded::<false>(domain, None)
    }

    pub(super) fn matches_bounded<const BOUNDED: bool>(
        &self,
        domain: &str,
        deadline: Option<std::time::Instant>,
    ) -> bool {
        bounded_any::<BOUNDED, _>(&self.patterns, deadline, |pattern| pattern.is_match(domain))
            || bounded_any::<BOUNDED, _>(&self.suffixes, deadline, |suffix| {
                domain.ends_with(suffix)
            })
            || bounded_any::<BOUNDED, _>(&self.keywords, deadline, |keyword| {
                domain.contains(keyword)
            })
            || (!self.geosite.is_empty() && {
                let lower = lowercase(domain);
                bounded_any::<BOUNDED, _>(&self.geosite, deadline, |matcher| {
                    matcher.matches_bounded::<BOUNDED>(domain, &lower, deadline)
                })
            })
    }
}

/// Geosite sets are stored lowercased; query names almost always already are.
pub(super) fn lowercase(domain: &str) -> std::borrow::Cow<'_, str> {
    if domain
        .bytes()
        .any(|b| b.is_ascii_uppercase() || !b.is_ascii())
    {
        std::borrow::Cow::Owned(domain.to_lowercase())
    } else {
        std::borrow::Cow::Borrowed(domain)
    }
}

/// First-seen order is part of the policy fingerprint and assigns bitmap positions.
#[derive(Debug, Default)]
pub(super) struct DomainRegistry {
    pub(super) keys: Vec<DomainMatcherDigest>,
    by_digest: HashMap<DomainMatcherDigest, u32>,
    pub(super) matchers: Vec<DomainMatcher>,
}

impl DomainRegistry {
    pub(super) fn intern_single(
        &mut self,
        digest: DomainMatcherDigest,
        matcher: Arc<GeositeMatcher>,
    ) -> anyhow::Result<u32> {
        self.insert(digest, || DomainMatcher {
            geosite: vec![matcher],
            ..Default::default()
        })
    }

    pub(super) fn intern(
        &mut self,
        (digest, matcher): (DomainMatcherDigest, DomainMatcher),
    ) -> anyhow::Result<u32> {
        self.insert(digest, || matcher)
    }

    fn insert(
        &mut self,
        key: DomainMatcherDigest,
        build: impl FnOnce() -> DomainMatcher,
    ) -> anyhow::Result<u32> {
        let slot = match self.by_digest.entry(key) {
            std::collections::hash_map::Entry::Occupied(slot) => return Ok(*slot.get()),
            std::collections::hash_map::Entry::Vacant(slot) => slot,
        };
        anyhow::ensure!(
            self.matchers.len() < ROUTING_FACT_CAPACITY,
            "routing policy has more than {ROUTING_FACT_CAPACITY} domain predicates"
        );
        let id = self.matchers.len() as u32;
        self.keys.push(key);
        self.matchers.push(build());
        slot.insert(id);
        Ok(id)
    }
}

pub(super) fn glob_to_regex(pattern: &str) -> String {
    let mut re = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\' => {
                re.push('\\');
                re.push(ch);
            }
            c => re.push(c),
        }
    }
    re.push('$');
    re
}
