//! The Policy: decides how a name is answered before any upstream server is
//! asked (steps 2-5 of the query pipeline: local records, blocked names,
//! forwarded zones, private names). It is built from two parts, each
//! immutable once built and swapped whole:
//!
//! - the part built from the Policy settings: local records, inline rules
//!   and response settings, replaced at once by a Reload or a Sync;
//! - the [`Lists`], loaded in the background and replaced by
//!   [`Policy::replace_lists`] under the keep-or-swap rule.
//!
//! Queries read both without taking a lock.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use hickory_proto::rr::RecordType;

use crate::config::{BlockResponse, PolicySettings, PrivateNames, Source};
use crate::domain_set::DomainSet;
use crate::local::LocalZone;
use crate::name;
use crate::rules::{self, Rule};

/// Firefox turns on DNS over HTTPS by itself, bypassing this resolver, unless
/// this name fails to resolve.
const FIREFOX_DOH_CANARY: &str = "use-application-dns.net";

/// How the Policy says a name is answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// A local record: its addresses (both families; the answer takes the
    /// ones the question asks for).
    Local {
        addresses: Arc<[IpAddr]>,
        ttl: u32,
    },
    /// A reverse lookup (PTR) for a local record's address.
    Reverse {
        host: Arc<str>,
        ttl: u32,
    },
    Blocked(Blocked),
    /// A name in a forwarded zone: the cache, then the zone's server.
    Forward {
        server: SocketAddr,
    },
    /// A Private name no local record answers: never sent upstream.
    Private {
        ttl: u32,
    },
    /// Not decided here: the cache, then the upstream servers.
    Upstream,
}

/// How to answer a blocked name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blocked {
    pub response: BlockResponse,
    pub ttl: u32,
}

/// What the Policy in force is made of, for the Metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    /// As configured: names with their addresses, wildcards included.
    pub local_records: usize,
    /// Domains in the lists (not the inline rules).
    pub blocked_domains: usize,
    pub allowed_domains: usize,
}

/// Whether [`Policy::replace_lists`] put the new lists in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    Replaced,
    /// The new lists were partial and the current ones complete, from the same
    /// sources: a failed Refresh must not weaken blocking.
    Kept,
}

#[derive(Debug)]
pub struct Policy {
    settings: ArcSwap<BuiltSettings>,
    lists: ArcSwap<Lists>,
    /// Makes the keep-or-swap check and the swap one step.
    replacing: Mutex<()>,
}

impl Policy {
    /// Starts with no lists; they are loaded separately and handed in with
    /// [`Policy::replace_lists`].
    #[must_use]
    pub fn new(settings: &PolicySettings) -> Policy {
        Policy {
            settings: ArcSwap::from_pointee(BuiltSettings::new(settings)),
            lists: ArcSwap::from_pointee(Lists::empty()),
            replacing: Mutex::new(()),
        }
    }

    /// Puts new Policy settings in force at once (a Reload or a Sync).
    pub fn apply(&self, settings: &PolicySettings) {
        self.settings.store(Arc::new(BuiltSettings::new(settings)));
    }

    /// Puts `lists` in force, unless they are partial, the current ones are
    /// complete, and both come from the same sources. After a source change
    /// the new lists win even if partial: a list that was removed must stop
    /// blocking, even if a newly added one is broken.
    pub fn replace_lists(&self, lists: Lists) -> Replacement {
        let _writer = self
            .replacing
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let current = self.lists.load();
        if !lists.complete && current.complete && lists.sources == current.sources {
            return Replacement::Kept;
        }
        self.lists.store(Arc::new(lists));
        Replacement::Replaced
    }

    /// How `name` (normalized: lowercase, no trailing dot) is answered.
    #[must_use]
    pub fn decide(&self, name: &str, qtype: RecordType) -> Decision {
        debug_assert_eq!(
            name::normalize(name).as_deref().unwrap_or(name),
            name,
            "names must be normalized"
        );
        let settings = self.settings.load();
        if let Some(addresses) = settings.local.lookup(name) {
            return Decision::Local {
                addresses,
                ttl: settings.local_ttl,
            };
        }
        if qtype == RecordType::PTR
            && let Some(host) = settings.local.reverse_lookup(name)
        {
            return Decision::Reverse {
                host,
                ttl: settings.local_ttl,
            };
        }
        if name == FIREFOX_DOH_CANARY {
            return Decision::Blocked(Blocked {
                response: BlockResponse::Nxdomain,
                ttl: settings.blocked.ttl,
            });
        }
        if is_blocked(&settings, &self.lists.load(), name) {
            return Decision::Blocked(settings.blocked);
        }
        if let Some(server) = settings.forward_server(name) {
            return Decision::Forward { server };
        }
        // A single label is a top-level domain as often as a host: its zone
        // records, which validating clients ask for (DS com), go upstream.
        // They say nothing about hosts on the LAN.
        let zone_records = !name.contains('.')
            && matches!(
                qtype,
                RecordType::NS | RecordType::SOA | RecordType::DS | RecordType::DNSKEY
            );
        if !settings.forward_private && !zone_records && settings.local.is_private(name) {
            return Decision::Private {
                ttl: settings.local_ttl,
            };
        }
        Decision::Upstream
    }

    /// How to block an upstream answer for `name` that makes it an alias
    /// (CNAME) of `target`: only if `target` is a blocked name and no allow
    /// rule matches `name`. Trackers hide behind such aliases (CNAME
    /// cloaking). Both names normalized.
    #[must_use]
    pub fn block_alias(&self, name: &str, target: &str) -> Option<Blocked> {
        let settings = self.settings.load();
        let lists = self.lists.load();
        (is_blocked(&settings, &lists, target) && !is_allowed(&settings, &lists, name))
            .then_some(settings.blocked)
    }

    #[must_use]
    pub fn counts(&self) -> Counts {
        let lists = self.lists.load();
        Counts {
            local_records: self.settings.load().local_records,
            blocked_domains: lists.blocked_domains(),
            allowed_domains: lists.allowed_domains(),
        }
    }

    /// The lists in force.
    #[must_use]
    pub fn lists(&self) -> Arc<Lists> {
        self.lists.load_full()
    }
}

/// Blocked unless an allow rule (inline or from a list) matches too. One
/// snapshot of each part, so a swap never mixes old and new rules.
fn is_blocked(settings: &BuiltSettings, lists: &Lists, name: &str) -> bool {
    let blocked = settings.block.matches(name) || lists.block.matches(name);
    blocked && !is_allowed(settings, lists, name)
}

fn is_allowed(settings: &BuiltSettings, lists: &Lists, name: &str) -> bool {
    settings.allow.matches(name) || lists.allow.matches(name)
}

/// The part of the Policy built from the Policy settings. Cheap to build, so a
/// Reload or a Sync applies at once.
#[derive(Debug)]
struct BuiltSettings {
    local: LocalZone,
    local_records: usize,
    local_ttl: u32,
    forward_private: bool,
    /// Forwarded zones and their servers.
    forward: Vec<(String, SocketAddr)>,
    /// Inline rules.
    block: DomainSet,
    allow: DomainSet,
    blocked: Blocked,
}

impl BuiltSettings {
    fn new(settings: &PolicySettings) -> BuiltSettings {
        let mut block = DomainSet::new();
        let mut allow = DomainSet::new();
        // The config check already made sure every inline rule parses.
        for (rules, kind) in [
            (&settings.blocking.block, ListKind::Block),
            (&settings.blocking.allow, ListKind::Allow),
        ] {
            for rule in rules.iter().flat_map(|line| rules::parse_line(line).rules) {
                route(kind, &rule, &mut block, &mut allow);
            }
        }
        BuiltSettings {
            local: LocalZone::new(&settings.local.records),
            local_records: settings.local.records.len(),
            local_ttl: settings.local.ttl,
            forward_private: settings.local.private_names == PrivateNames::Forward,
            forward: settings
                .local
                .forward
                .iter()
                .map(|(zone, server)| (zone.as_str().to_owned(), server.0))
                .collect(),
            block,
            allow,
            blocked: Blocked {
                response: settings.blocking.response,
                ttl: settings.blocking.ttl,
            },
        }
    }

    /// The server of the longest forwarded zone `name` is in.
    fn forward_server(&self, name: &str) -> Option<SocketAddr> {
        self.forward
            .iter()
            .filter(|(zone, _)| name::is_at_or_below(name, zone))
            .max_by_key(|(zone, _)| zone.len())
            .map(|(_, server)| *server)
    }
}

/// Whether a list's rules block or allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListKind {
    /// Its rules block, except Adblock `@@` exceptions, which allow.
    Block,
    /// Every rule allows, whatever its syntax.
    Allow,
}

impl ListKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ListKind::Block => "block",
            ListKind::Allow => "allow",
        }
    }
}

fn route(kind: ListKind, rule: &Rule, block: &mut DomainSet, allow: &mut DomainSet) {
    let target = if kind == ListKind::Allow || rule.exception {
        allow
    } else {
        block
    };
    target.insert(&rule.name, rule.matching);
}

/// The list sources to load, in config order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sources {
    pub blocklists: Vec<Source>,
    pub allowlists: Vec<Source>,
}

impl Sources {
    #[must_use]
    pub fn of(settings: &PolicySettings) -> Sources {
        Sources {
            blocklists: settings.blocking.lists.clone(),
            allowlists: settings.blocking.allowlists.clone(),
        }
    }

    /// Every source with its kind: the blocklists, then the allowlists.
    pub fn iter(&self) -> impl Iterator<Item = (&Source, ListKind)> {
        let blocklists = self
            .blocklists
            .iter()
            .map(|source| (source, ListKind::Block));
        blocklists.chain(
            self.allowlists
                .iter()
                .map(|source| (source, ListKind::Allow)),
        )
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.blocklists.len() + self.allowlists.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The rules of every list, merged into one block set and one allow set.
#[derive(Debug)]
pub struct Lists {
    block: DomainSet,
    allow: DomainSet,
    /// The sources these lists were loaded from.
    sources: Sources,
    /// Whether each source loaded, in [`Sources::iter`] order.
    loaded: Vec<bool>,
    /// True if every source loaded.
    complete: bool,
}

impl Lists {
    /// No rules at all, and not complete, so the first real load replaces
    /// them even if some sources fail.
    #[must_use]
    pub fn empty() -> Lists {
        Lists {
            block: DomainSet::new(),
            allow: DomainSet::new(),
            sources: Sources::default(),
            loaded: Vec::new(),
            complete: false,
        }
    }

    #[must_use]
    pub fn sources(&self) -> &Sources {
        &self.sources
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub fn blocked_domains(&self) -> usize {
        self.block.len()
    }

    #[must_use]
    pub fn allowed_domains(&self) -> usize {
        self.allow.len()
    }

    /// Each source, its kind, and whether it loaded.
    pub fn results(&self) -> impl Iterator<Item = (&Source, ListKind, bool)> {
        self.sources
            .iter()
            .zip(self.loaded.iter().copied())
            .map(|((source, kind), loaded)| (source, kind, loaded))
    }
}

/// Collects the rules of a load, source by source, into new [`Lists`].
#[derive(Debug)]
pub struct ListsBuilder {
    block: DomainSet,
    allow: DomainSet,
    sources: Sources,
    loaded: Vec<bool>,
}

impl ListsBuilder {
    #[must_use]
    pub fn new(sources: Sources) -> ListsBuilder {
        ListsBuilder {
            block: DomainSet::new(),
            allow: DomainSet::new(),
            loaded: Vec::with_capacity(sources.len()),
            sources,
        }
    }

    /// Adds a rule from a list of `kind`.
    pub fn add(&mut self, kind: ListKind, rule: &Rule) {
        route(kind, rule, &mut self.block, &mut self.allow);
    }

    /// Records whether the next source, in [`Sources::iter`] order, loaded.
    /// Rules read from a source that failed halfway are kept.
    pub fn source_done(&mut self, loaded: bool) {
        self.loaded.push(loaded);
    }

    /// The lists, complete if every source loaded.
    #[must_use]
    pub fn finish(mut self) -> Lists {
        self.block.shrink_to_fit();
        self.allow.shrink_to_fit();
        let complete = self.loaded.len() == self.sources.len() && self.loaded.iter().all(|&ok| ok);
        Lists {
            block: self.block,
            allow: self.allow,
            sources: self.sources,
            loaded: self.loaded,
            complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const UPSTREAM: &str = "[upstream]\nservers = [\"9.9.9.9\"]\n";

    fn settings(toml: &str) -> PolicySettings {
        Config::parse(&format!("{UPSTREAM}{toml}"))
            .unwrap_or_else(|e| panic!("{e}"))
            .policy_settings()
    }

    fn policy(toml: &str) -> Policy {
        Policy::new(&settings(toml))
    }

    /// Lists from `blocklist` and `allowlist` text, complete.
    fn lists(sources: Sources, blocklist: &str, allowlist: &str) -> Lists {
        let mut builder = ListsBuilder::new(sources);
        for (text, kind) in [(blocklist, ListKind::Block), (allowlist, ListKind::Allow)] {
            for rule in text.lines().flat_map(|line| rules::parse_line(line).rules) {
                builder.add(kind, &rule);
            }
        }
        for _ in 0..builder.sources.len() {
            builder.source_done(true);
        }
        builder.finish()
    }

    fn sources(blocklists: &[&str]) -> Sources {
        let blocklists = blocklists
            .iter()
            .map(|s| Source::try_from((*s).to_owned()).unwrap())
            .collect();
        Sources {
            blocklists,
            allowlists: Vec::new(),
        }
    }

    #[test]
    fn a_local_record_decides_local_with_its_addresses_and_ttl() {
        let policy = policy(
            "[local]\nttl = 120\n[local.records]\n\"nas.lan\" = [\"192.168.1.10\", \"fd00::10\"]\n",
        );
        let Decision::Local { addresses, ttl } = policy.decide("nas.lan", RecordType::A) else {
            panic!()
        };
        assert_eq!(ttl, 120);
        assert_eq!(addresses.len(), 2);
    }

    #[test]
    fn a_ptr_query_for_a_local_address_decides_reverse() {
        let policy = policy("[local.records]\n\"nas.lan\" = \"192.168.1.10\"\n");
        let reverse = policy.decide("10.1.168.192.in-addr.arpa", RecordType::PTR);
        assert!(
            matches!(&reverse, Decision::Reverse { host, ttl: 300 } if &**host == "nas.lan"),
            "{reverse:?}"
        );
        // Only PTR queries get a reverse answer; others fall through to private.
        assert_eq!(
            policy.decide("10.1.168.192.in-addr.arpa", RecordType::A),
            Decision::Private { ttl: 300 }
        );
    }

    #[test]
    fn block_rules_and_allow_rules() {
        let policy = policy(
            "[blocking]\nttl = 30\nblock = [\"ads.example.com\", \"*.tracker.net\"]\nallow = [\"ok.ads.example.com\"]\n",
        );
        let blocked = Decision::Blocked(Blocked {
            response: BlockResponse::Zero,
            ttl: 30,
        });
        assert_eq!(policy.decide("ads.example.com", RecordType::A), blocked);
        assert_eq!(
            policy.decide("x.ads.example.com", RecordType::HTTPS),
            blocked
        );
        assert_eq!(policy.decide("a.tracker.net", RecordType::A), blocked);
        assert_eq!(
            policy.decide("tracker.net", RecordType::A),
            Decision::Upstream
        );
        assert_eq!(
            policy.decide("ok.ads.example.com", RecordType::A),
            Decision::Upstream
        );
        assert_eq!(
            policy.decide("example.com", RecordType::A),
            Decision::Upstream
        );
    }

    #[test]
    fn rules_from_lists_block_and_allow_like_inline_rules() {
        let policy = policy(
            "[blocking]\nblock = [\"inline-blocked.example\"]\nallow = [\"list-blocked.example\"]\n",
        );
        policy.replace_lists(lists(
            sources(&["/l.txt"]),
            "0.0.0.0 ads.example\n||list-blocked.example^\n@@||good.ads.example^\n",
            "inline-blocked.example\n",
        ));
        assert!(matches!(
            policy.decide("ads.example", RecordType::A),
            Decision::Blocked(_)
        ));
        // Allow rules win, wherever each rule comes from.
        assert_eq!(
            policy.decide("good.ads.example", RecordType::A),
            Decision::Upstream
        );
        assert_eq!(
            policy.decide("list-blocked.example", RecordType::A),
            Decision::Upstream
        );
        assert_eq!(
            policy.decide("inline-blocked.example", RecordType::A),
            Decision::Upstream
        );
    }

    #[test]
    fn the_firefox_canary_is_nxdomain_whatever_the_block_response() {
        let policy = policy("");
        let decision = policy.decide("use-application-dns.net", RecordType::A);
        assert_eq!(
            decision,
            Decision::Blocked(Blocked {
                response: BlockResponse::Nxdomain,
                ttl: 300
            })
        );
    }

    #[test]
    fn the_zone_records_of_a_single_label_go_upstream_its_hosts_stay_private() {
        let p = policy("");
        let private = |decision| matches!(decision, Decision::Private { .. });
        for qtype in [
            RecordType::NS,
            RecordType::SOA,
            RecordType::DS,
            RecordType::DNSKEY,
        ] {
            assert_eq!(p.decide("com", qtype), Decision::Upstream, "{qtype}");
            // A validating client learns from the root that .lan is unsigned.
            assert_eq!(p.decide("lan", qtype), Decision::Upstream, "{qtype}");
            // Zones below are private for every type.
            assert!(private(p.decide("home.arpa", qtype)), "{qtype}");
            assert!(private(p.decide("nas.lan", qtype)), "{qtype}");
        }
        for qtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::TXT,
        ] {
            assert!(private(p.decide("printer", qtype)), "{qtype}");
            assert!(private(p.decide("com", qtype)), "{qtype}");
        }
    }

    #[test]
    fn private_names_decide_private_unless_forwarded() {
        let nxdomain = policy("");
        assert_eq!(
            nxdomain.decide("printer", RecordType::A),
            Decision::Private { ttl: 300 }
        );
        assert_eq!(
            nxdomain.decide("nas.lan", RecordType::A),
            Decision::Private { ttl: 300 }
        );
        let forward = policy("[local]\nprivate_names = \"forward\"\n");
        assert_eq!(forward.decide("nas.lan", RecordType::A), Decision::Upstream);
    }

    #[test]
    fn the_pipeline_order_local_then_blocked_then_forwarded_then_private() {
        let policy = policy(
            "[blocking]\nblock = [\"lan\", \"ads.home.arpa\"]\n[local.records]\n\"nas.lan\" = \"10.0.0.10\"\n\
             [local.forward]\n\"home.arpa\" = \"192.168.1.1\"\n",
        );
        // A local record wins over a block rule.
        assert!(matches!(
            policy.decide("nas.lan", RecordType::A),
            Decision::Local { .. }
        ));
        assert!(matches!(
            policy.decide("tv.lan", RecordType::A),
            Decision::Blocked(_)
        ));
        // A blocked name in a forwarded zone stays blocked; a private one is forwarded.
        assert!(matches!(
            policy.decide("ads.home.arpa", RecordType::A),
            Decision::Blocked(_)
        ));
        assert_eq!(
            policy.decide("tv.home.arpa", RecordType::A),
            Decision::Forward {
                server: "192.168.1.1:53".parse().unwrap()
            }
        );
    }

    #[test]
    fn the_longest_forwarded_zone_wins() {
        let policy = policy(
            "[local.forward]\n\"lan\" = \"192.168.1.1\"\n\"iot.lan\" = \"192.168.2.1:5353\"\n",
        );
        assert_eq!(
            policy.decide("tv.lan", RecordType::A),
            Decision::Forward {
                server: "192.168.1.1:53".parse().unwrap()
            }
        );
        assert_eq!(
            policy.decide("cam.iot.lan", RecordType::A),
            Decision::Forward {
                server: "192.168.2.1:5353".parse().unwrap()
            }
        );
        assert_eq!(
            policy.decide("plan", RecordType::A),
            Decision::Private { ttl: 300 }
        );
    }

    #[test]
    fn an_alias_of_a_blocked_name_is_blocked_unless_the_name_asked_for_is_allowed() {
        let policy = policy("[blocking]\nblock = [\"tracker.net\"]\nallow = [\"shop.example\"]\n");
        assert!(
            policy
                .block_alias("metrics.cdn.example", "x.tracker.net")
                .is_some()
        );
        assert!(
            policy
                .block_alias("metrics.shop.example", "x.tracker.net")
                .is_none()
        );
        assert!(
            policy
                .block_alias("metrics.cdn.example", "cdn.example")
                .is_none()
        );
    }

    #[test]
    fn apply_replaces_local_records_and_inline_rules_at_once() {
        let policy = policy("[local.records]\n\"nas.lan\" = \"10.0.0.10\"\n");
        policy.apply(&settings("[blocking]\nblock = [\"ads.example\"]\n"));
        assert!(!matches!(
            policy.decide("nas.lan", RecordType::A),
            Decision::Local { .. }
        ));
        assert!(matches!(
            policy.decide("ads.example", RecordType::A),
            Decision::Blocked(_)
        ));
    }

    #[test]
    fn partial_lists_replace_complete_ones_only_when_the_sources_changed() {
        let policy = policy("");
        let ab = sources(&["/a.txt", "/b.txt"]);
        assert_eq!(
            policy.replace_lists(lists(ab.clone(), "a.example\nb.example\n", "")),
            Replacement::Replaced
        );

        // The same sources, one failed: the complete lists stay.
        let mut partial = ListsBuilder::new(ab.clone());
        partial.add(ListKind::Block, &rules::parse_line("a.example").rules[0]);
        partial.source_done(true);
        partial.source_done(false);
        assert_eq!(policy.replace_lists(partial.finish()), Replacement::Kept);
        assert!(matches!(
            policy.decide("b.example", RecordType::A),
            Decision::Blocked(_)
        ));

        // Other sources: the new lists win even though partial.
        let mut changed = ListsBuilder::new(sources(&["/a.txt", "/c.txt"]));
        changed.source_done(true);
        changed.source_done(false);
        assert_eq!(
            policy.replace_lists(changed.finish()),
            Replacement::Replaced
        );
        assert_eq!(
            policy.decide("b.example", RecordType::A),
            Decision::Upstream
        );
        let results: Vec<bool> = policy.lists().results().map(|(_, _, ok)| ok).collect();
        assert_eq!(results, [true, false]);
    }

    #[test]
    fn counts_are_those_of_the_records_and_lists_in_force() {
        let policy = policy(
            "[blocking]\nblock = [\"inline.example\"]\n[local.records]\n\"nas.lan\" = \"10.0.0.10\"\n\"*.apps.lan\" = \"10.0.0.11\"\n",
        );
        assert_eq!(
            policy.counts(),
            Counts {
                local_records: 2,
                blocked_domains: 0,
                allowed_domains: 0
            }
        );
        policy.replace_lists(lists(
            sources(&["/l.txt"]),
            "a.example\nb.example\n",
            "c.example\n",
        ));
        assert_eq!(
            policy.counts(),
            Counts {
                local_records: 2,
                blocked_domains: 2,
                allowed_domains: 1
            }
        );
    }

    #[test]
    fn decisions_are_consistent_while_lists_are_swapped_concurrently() {
        let policy = Arc::new(policy(""));
        let swapper = {
            let policy = Arc::clone(&policy);
            std::thread::spawn(move || {
                for i in 0..200 {
                    let text = if i % 2 == 0 {
                        "ads.example\n"
                    } else {
                        "other.example\n"
                    };
                    policy.replace_lists(lists(sources(&[&format!("/{i}.txt")]), text, ""));
                }
            })
        };
        for _ in 0..2000 {
            let decision = policy.decide("ads.example", RecordType::A);
            assert!(matches!(
                decision,
                Decision::Blocked(_) | Decision::Upstream
            ));
        }
        swapper.join().unwrap();
    }
}
