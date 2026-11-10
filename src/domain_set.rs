//! A set of domain names, each matching itself, the names below it, or both.
//! A lookup costs at most one hash lookup per label of the name asked for.
//!
//! The standard `HashMap` hashes with a key chosen at random per process, so
//! a list cannot be crafted to make lookups slow.

use std::collections::HashMap;

use crate::name;
use crate::rules::Matching;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Flags {
    /// Matches the name itself.
    exact: bool,
    /// Matches every name below it.
    subdomains: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DomainSet {
    names: HashMap<Box<str>, Flags>,
}

impl DomainSet {
    #[must_use]
    pub fn new() -> DomainSet {
        DomainSet::default()
    }

    /// Adds `name` (normalized). Adding a name again widens what it matches.
    pub fn insert(&mut self, name: &str, matching: Matching) {
        let flags = self.names.entry(name.into()).or_default();
        match matching {
            Matching::DomainAndSubdomains => {
                flags.exact = true;
                flags.subdomains = true;
            }
            Matching::SubdomainsOnly => flags.subdomains = true,
        }
    }

    /// True if `name` (normalized) is in the set, or below a name that
    /// matches its subdomains.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        if self.names.get(name).is_some_and(|flags| flags.exact) {
            return true;
        }
        name::parents(name)
            .any(|parent| self.names.get(parent).is_some_and(|flags| flags.subdomains))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Returns memory the set no longer needs, once it is complete.
    pub fn shrink_to_fit(&mut self) {
        self.names.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_subdomain_matching() {
        let mut set = DomainSet::new();
        set.insert("ads.example.com", Matching::DomainAndSubdomains);
        set.insert("tracker.net", Matching::SubdomainsOnly);

        assert!(set.matches("ads.example.com"));
        assert!(set.matches("x.y.ads.example.com"));
        assert!(!set.matches("example.com"));
        assert!(!set.matches("bads.example.com"));
        assert!(!set.matches("tracker.net"));
        assert!(set.matches("a.tracker.net"));
        assert!(!set.matches(""));

        // Adding the same name again widens what it matches.
        set.insert("tracker.net", Matching::DomainAndSubdomains);
        assert!(set.matches("tracker.net"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn many_names() {
        let mut set = DomainSet::new();
        for i in 0..20_000 {
            set.insert(
                &format!("host{i}.example.org"),
                Matching::DomainAndSubdomains,
            );
        }
        set.shrink_to_fit();
        assert_eq!(set.len(), 20_000);
        assert!((0..20_000).all(|i| set.matches(&format!("www.host{i}.example.org"))));
        assert!(!set.matches("host20000.example.org"));
    }
}
