//! A bounded cache of upstream answers, keyed by question and the client's
//! DNSSEC flags. Bounded by memory (`cache.size_mb`): each entry weighs what
//! it takes in memory, estimated. On a hit, record TTLs are lowered by the
//! time spent in the cache. An expired entry is kept `serve_stale` longer,
//! for when no upstream server answers (RFC 8767): [`Cache::lookup_stale`]
//! serves it with TTL 30. Storing an answer again starts that time anew.
//!
//! The current time is passed in, so expiry is tested without waiting.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{LowerName, RData, Record, RecordType};

/// TTL of stale answers, as RFC 8767 recommends: clients ask again soon, when
/// the upstream servers may be back.
pub const STALE_TTL: u32 = 30;

/// What the cache keeps per entry beside the key and the answer: its own
/// bookkeeping (the entry, its place in the access and expiry queues) and
/// the allocations' headers. An estimate, on the generous side.
const BOOKKEEPING: usize = 256;

/// What an answer depends on: the question, whether the client used EDNS,
/// set DO (DNSSEC records wanted) or CD (no validation wanted), and which
/// server it came from.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    pub name: LowerName,
    pub qtype: RecordType,
    pub edns: bool,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
    /// The forwarded zone's server the answer came from; None for the
    /// upstream servers. A Reload or a Sync that changes the zones then
    /// misses the old answers instead of serving them.
    pub zone: Option<SocketAddr>,
}

impl Key {
    /// The key of `query`'s question, if it has one.
    #[must_use]
    pub fn of(query: &Message) -> Option<Key> {
        let question = query.queries.first()?;
        Some(Key {
            name: LowerName::new(question.name()),
            qtype: question.query_type(),
            edns: query.edns.is_some(),
            dnssec_ok: query
                .edns
                .as_ref()
                .is_some_and(|edns| edns.flags().dnssec_ok),
            checking_disabled: query.metadata.checking_disabled,
            zone: None,
        })
    }

    /// The same key for an answer from the forwarded zone's `server`.
    #[must_use]
    pub fn via_zone(self, server: SocketAddr) -> Key {
        Key {
            zone: Some(server),
            ..self
        }
    }
}

#[derive(Debug)]
struct Entry {
    /// TTLs clamped; no question or OPT record.
    answer: Message,
    stored_at: Instant,
    /// Seconds the answer is fresh for.
    ttl: u32,
}

pub struct Cache {
    /// None when `size_mb` is 0.
    entries: Option<moka::sync::Cache<Key, Arc<Entry>>>,
    min_ttl: u32,
    max_ttl: u32,
    serve_stale: Duration,
}

impl std::fmt::Debug for Cache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Cache")
            .field("entries", &self.entry_count())
            .finish_non_exhaustive()
    }
}

/// Removes an entry once it is too old to be served even stale.
struct ExpireAfterStale {
    serve_stale: Duration,
}

impl ExpireAfterStale {
    /// How long `entry` is kept from the moment it is stored.
    fn lifetime(&self, entry: &Entry) -> Duration {
        Duration::from_secs(entry.ttl.into()) + self.serve_stale
    }
}

impl moka::Expiry<Key, Arc<Entry>> for ExpireAfterStale {
    fn expire_after_create(&self, _: &Key, entry: &Arc<Entry>, _: Instant) -> Option<Duration> {
        Some(self.lifetime(entry))
    }

    /// An answer stored again is a new answer: its time starts anew. (The
    /// default keeps the first one's, which would drop an answer fetched a
    /// moment ago, and with it the stale answer for an outage.)
    fn expire_after_update(
        &self,
        _: &Key,
        entry: &Arc<Entry>,
        _: Instant,
        _: Option<Duration>,
    ) -> Option<Duration> {
        Some(self.lifetime(entry))
    }
}

impl Cache {
    #[must_use]
    pub fn new(settings: &crate::config::Cache) -> Cache {
        let serve_stale = Duration::from_secs(u64::from(settings.serve_stale_hours) * 3600);
        let entries = (settings.size_mb > 0).then(|| {
            moka::sync::Cache::builder()
                .max_capacity(u64::from(settings.size_mb) * 1024 * 1024)
                .weigher(|key: &Key, entry: &Arc<Entry>| weight(key, &entry.answer))
                .expire_after(ExpireAfterStale { serve_stale })
                .build()
        });
        Cache {
            entries,
            min_ttl: settings.min_ttl,
            max_ttl: settings.max_ttl,
            serve_stale,
        }
    }

    /// A fresh answer for `key`, with TTLs lowered by its age.
    #[must_use]
    pub fn lookup(&self, key: &Key, now: Instant) -> Option<Message> {
        let entry = self.entries.as_ref()?.get(key)?;
        let age = now.saturating_duration_since(entry.stored_at).as_secs();
        let age = u32::try_from(age).ok().filter(|&age| age < entry.ttl)?;
        let mut answer = entry.answer.clone();
        for_each_ttl(&mut answer, |ttl| *ttl = ttl.saturating_sub(age));
        Some(answer)
    }

    /// Like [`Cache::lookup`], but also an answer that expired less than
    /// `serve_stale` ago, with every TTL [`STALE_TTL`]. Only for when no
    /// upstream server answers.
    #[must_use]
    pub fn lookup_stale(&self, key: &Key, now: Instant) -> Option<Message> {
        if let Some(fresh) = self.lookup(key, now) {
            return Some(fresh);
        }
        let entry = self.entries.as_ref()?.get(key)?;
        let expired_at = entry.stored_at + Duration::from_secs(entry.ttl.into());
        if now.saturating_duration_since(expired_at) >= self.serve_stale {
            return None;
        }
        let mut answer = entry.answer.clone();
        for_each_ttl(&mut answer, |ttl| *ttl = STALE_TTL);
        Some(answer)
    }

    /// Keeps `answer` (an upstream answer to the question of `key`) if it is
    /// cacheable: NOERROR or NXDOMAIN, not truncated, and with a record whose
    /// TTL is above zero once clamped to `min_ttl` and `max_ttl`.
    pub fn store(&self, key: Key, answer: &Message, now: Instant) {
        let Some(entries) = &self.entries else { return };
        let code = answer.metadata.response_code;
        if answer.metadata.truncation
            || !matches!(code, ResponseCode::NoError | ResponseCode::NXDomain)
        {
            return;
        }
        let mut answer = answer.clone();
        answer.queries.clear();
        answer.edns = None;
        answer.signature = None;
        let (lo, hi) = (self.min_ttl, self.max_ttl);
        for_each_ttl(&mut answer, |ttl| *ttl = (*ttl).clamp(lo, hi));
        let Some(ttl) = min_ttl(&answer).filter(|&ttl| ttl > 0) else {
            return;
        };
        entries.insert(
            key,
            Arc::new(Entry {
                answer,
                stored_at: now,
                ttl,
            }),
        );
    }

    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.entries.as_ref().map_or(0, |entries| {
            entries.run_pending_tasks();
            entries.entry_count()
        })
    }
}

/// What an entry takes in memory, the unit of `cache.size_mb`: an estimate.
/// An answer is kept decoded, which is several times its encoded size: the
/// message, each record, and (taken as their encoded size) the names and
/// record data that live outside those.
fn weight(key: &Key, answer: &Message) -> u32 {
    let records = answer.answers.len() + answer.authorities.len() + answer.additionals.len();
    let encoded = answer.to_vec().map_or(usize::MAX, |bytes| bytes.len());
    let bytes = BOOKKEEPING
        .saturating_add(size_of::<Key>())
        .saturating_add(key.name.len())
        .saturating_add(size_of::<Entry>())
        .saturating_add(records.saturating_mul(size_of::<Record>()))
        .saturating_add(encoded);
    u32::try_from(bytes).unwrap_or(u32::MAX)
}

/// Applies `change` to every record's TTL, and to the MINIMUM of an SOA in
/// the authority section, which is a negative answer's TTL too (RFC 2308).
fn for_each_ttl(answer: &mut Message, mut change: impl FnMut(&mut u32)) {
    for record in answer
        .answers
        .iter_mut()
        .chain(answer.additionals.iter_mut())
    {
        change(&mut record.ttl);
    }
    for record in &mut answer.authorities {
        change(&mut record.ttl);
        if let RData::SOA(soa) = &mut record.data {
            change(&mut soa.minimum);
        }
    }
}

/// The smallest TTL of all records, an SOA's MINIMUM included; None if there
/// are no records.
fn min_ttl(answer: &Message) -> Option<u32> {
    let ttls = answer
        .answers
        .iter()
        .chain(&answer.authorities)
        .chain(&answer.additionals)
        .map(|record| record.ttl);
    let soa_minimums = answer
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(soa.minimum),
            _ => None,
        });
    ttls.chain(soa_minimums).min()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answer;
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, Record};
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    fn new_cache(serve_stale_hours: u32) -> Cache {
        Cache::new(&crate::config::Cache {
            size_mb: 1,
            min_ttl: 0,
            max_ttl: 3600,
            serve_stale_hours,
        })
    }

    fn query(name: &str) -> Message {
        let mut query = Message::query();
        query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        query
    }

    /// An upstream answer to `query` with one A record.
    fn upstream_answer(query: &Message, ttl: u32) -> Message {
        let mut answer = answer::response(query, ResponseCode::NoError);
        let owner = query.queries[0].name().clone();
        answer.answers.push(Record::from_rdata(
            owner,
            ttl,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        answer
    }

    #[test]
    fn a_hit_lowers_the_ttls_by_the_age_and_expires() {
        let cache = new_cache(0);
        let query = query("example.com.");
        let key = Key::of(&query).unwrap();
        let now = Instant::now();
        cache.store(key.clone(), &upstream_answer(&query, 100), now);

        let hit = cache.lookup(&key, now + Duration::from_secs(40)).unwrap();
        assert_eq!(hit.answers[0].ttl, 60);
        assert!(hit.queries.is_empty() && hit.edns.is_none());
        assert!(cache.lookup(&key, now + Duration::from_secs(100)).is_none());
    }

    #[test]
    fn the_key_ignores_case_but_not_the_dnssec_flags() {
        let cache = new_cache(0);
        let now = Instant::now();
        let lower = query("example.com.");
        cache.store(Key::of(&lower).unwrap(), &upstream_answer(&lower, 100), now);
        assert!(
            cache
                .lookup(&Key::of(&query("EXAMPLE.com.")).unwrap(), now)
                .is_some()
        );

        let mut with_do = query("example.com.");
        with_do.edns = Some(answer::fresh_edns(true));
        assert!(cache.lookup(&Key::of(&with_do).unwrap(), now).is_none());
    }

    #[test]
    fn ttls_are_clamped_and_uncacheable_answers_are_skipped() {
        let cache = Cache::new(&crate::config::Cache {
            size_mb: 1,
            min_ttl: 60,
            max_ttl: 120,
            serve_stale_hours: 0,
        });
        let now = Instant::now();

        let low = query("low.example.");
        cache.store(Key::of(&low).unwrap(), &upstream_answer(&low, 5), now);
        assert_eq!(
            cache.lookup(&Key::of(&low).unwrap(), now).unwrap().answers[0].ttl,
            60
        );
        let high = query("high.example.");
        cache.store(
            Key::of(&high).unwrap(),
            &upstream_answer(&high, 86_400),
            now,
        );
        assert_eq!(
            cache.lookup(&Key::of(&high).unwrap(), now).unwrap().answers[0].ttl,
            120
        );

        let unclamped = new_cache(0);
        let zero = query("zero.example.");
        unclamped.store(Key::of(&zero).unwrap(), &upstream_answer(&zero, 0), now);
        let failed = query("failed.example.");
        unclamped.store(
            Key::of(&failed).unwrap(),
            &answer::response(&failed, ResponseCode::ServFail),
            now,
        );
        let mut cut = upstream_answer(&query("cut.example."), 100);
        cut.metadata.truncation = true;
        unclamped.store(Key::of(&query("cut.example.")).unwrap(), &cut, now);
        let empty = query("empty.example.");
        unclamped.store(
            Key::of(&empty).unwrap(),
            &answer::response(&empty, ResponseCode::NoError),
            now,
        );
        assert_eq!(unclamped.entry_count(), 0);
    }

    #[test]
    fn a_negative_answer_lives_as_long_as_its_soa_minimum() {
        let cache = new_cache(0);
        let query = query("nothing.example.");
        let key = Key::of(&query).unwrap();
        let now = Instant::now();
        let mut negative = answer::negative(&query, ResponseCode::NXDomain, 300);
        if let RData::SOA(soa) = &mut negative.authorities[0].data {
            soa.minimum = 30;
        }
        cache.store(key.clone(), &negative, now);
        assert!(cache.lookup(&key, now + Duration::from_secs(29)).is_some());
        assert!(cache.lookup(&key, now + Duration::from_secs(30)).is_none());
    }

    #[test]
    fn an_expired_answer_is_served_stale_with_ttl_30_within_the_window() {
        let cache = new_cache(1);
        let query = query("example.com.");
        let key = Key::of(&query).unwrap();
        let now = Instant::now();
        cache.store(key.clone(), &upstream_answer(&query, 10), now);

        let later = now + Duration::from_secs(600);
        assert!(cache.lookup(&key, later).is_none());
        assert_eq!(
            cache.lookup_stale(&key, later).unwrap().answers[0].ttl,
            STALE_TTL
        );
        assert!(
            cache
                .lookup_stale(&key, now + Duration::from_secs(10 + 3600))
                .is_none()
        );

        let never = new_cache(0);
        never.store(key.clone(), &upstream_answer(&query, 10), now);
        assert!(never.lookup_stale(&key, later).is_none());
    }

    #[test]
    fn an_entry_weighs_what_it_takes_in_memory_not_its_encoded_size() {
        let query = query("example.com.");
        let key = Key::of(&query).unwrap();
        let mut one = upstream_answer(&query, 100);
        one.queries.clear();
        let mut two = one.clone();
        two.answers.push(one.answers[0].clone());

        let encoded = one.to_vec().unwrap().len();
        let in_memory = size_of::<Message>() + size_of::<Record>();
        assert!(in_memory > 4 * encoded, "kept decoded: far larger");
        let weigh = |answer: &Message| usize::try_from(weight(&key, answer)).unwrap();
        assert!(weigh(&one) >= in_memory + encoded);
        assert!(weigh(&two) - weigh(&one) >= size_of::<Record>());
    }

    #[test]
    fn the_size_bounds_the_memory_of_the_entries_kept() {
        let cache = new_cache(0);
        let now = Instant::now();
        for i in 0..5000 {
            let query = query(&format!("host{i}.example.com."));
            cache.store(Key::of(&query).unwrap(), &upstream_answer(&query, 100), now);
        }
        let kept = usize::try_from(cache.entry_count()).unwrap();
        assert!(kept > 0);
        let each = size_of::<Message>() + size_of::<Record>();
        assert!(
            kept * each <= 1024 * 1024,
            "{kept} entries of at least {each} bytes in 1 MiB"
        );
    }

    #[test]
    fn an_answer_stored_again_is_kept_as_long_as_a_new_one() {
        let cache = new_cache(0);
        let query = query("example.com.");
        let key = Key::of(&query).unwrap();
        let wait = |millis| std::thread::sleep(Duration::from_millis(millis));

        // The entries' removal runs on the real clock: stored again three
        // quarters into its two seconds, the answer must outlive them.
        cache.store(key.clone(), &upstream_answer(&query, 2), Instant::now());
        wait(1500);
        let again = Instant::now();
        cache.store(key.clone(), &upstream_answer(&query, 2), again);
        wait(1000);
        assert!(
            cache.lookup(&key, again).is_some(),
            "removed when the first answer was due"
        );
    }

    #[test]
    fn size_zero_disables_the_cache() {
        let cache = Cache::new(&crate::config::Cache {
            size_mb: 0,
            min_ttl: 0,
            max_ttl: 3600,
            serve_stale_hours: 24,
        });
        let query = query("example.com.");
        let key = Key::of(&query).unwrap();
        cache.store(key.clone(), &upstream_answer(&query, 100), Instant::now());
        assert!(cache.lookup(&key, Instant::now()).is_none());
    }
}
