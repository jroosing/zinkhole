//! Decides how each query is answered. The query pipeline, in order:
//!
//! ```text
//! 1. client not allowed               → dropped (UDP) or REFUSED (TCP)
//! 2. local record, or PTR for one     → local answer
//! 3. blocked (allow rules win)        → zero addresses or NXDOMAIN
//! 4. forwarded zone                   → as 6–7, with the zone's server
//! 5. private name                     → NXDOMAIN
//! 6. cached answer                    → cached answer
//! 7. upstream servers                 → forwarded answer (then cached), or a
//!                                       stale cached one if none answers
//! ```
//!
//! Steps 2–5 are the Policy's decision; this module turns it into a response.
//! Upstream servers sit behind [`Forwarder`].

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use tokio::sync::Semaphore;

use crate::answer;
use crate::cache::{Cache, Key};
use crate::config::Network;
use crate::metrics::Queries;
use crate::policy::{Decision, Policy};

/// How a single query was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    Local,
    Blocked,
    Private,
    Cached,
    Forwarded,
    Failed,
    /// The upstream answer's DNSSEC signatures do not hold (`upstream.dnssec
    /// = "validate"`): SERVFAIL.
    Bogus,
    Refused,
    Invalid,
}

impl Outcome {
    pub const ALL: [Outcome; 9] = [
        Outcome::Local,
        Outcome::Blocked,
        Outcome::Private,
        Outcome::Cached,
        Outcome::Forwarded,
        Outcome::Failed,
        Outcome::Bogus,
        Outcome::Refused,
        Outcome::Invalid,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Local => "local",
            Outcome::Blocked => "blocked",
            Outcome::Private => "private",
            Outcome::Cached => "cached",
            Outcome::Forwarded => "forwarded",
            Outcome::Failed => "failed",
            Outcome::Bogus => "bogus",
            Outcome::Refused => "refused",
            Outcome::Invalid => "invalid",
        }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the query arrived. Over UDP a client's address is unproven and the
/// answer must fit the client's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// Where a query that zinkhole cannot answer itself goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The upstream servers, with failover.
    Upstream,
    /// A forwarded zone's server (plain DNS), alone.
    Zone(SocketAddr),
}

/// Why there is no answer to forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    #[error("no server answered")]
    NoAnswer,
    /// An answer came, but its DNSSEC signatures do not hold.
    #[error("the answer is bogus: its DNSSEC signatures do not hold")]
    Bogus,
}

/// Asks servers for the answers zinkhole does not have.
pub trait Forwarder: Send + Sync {
    /// The answer of `target` to `query`, which holds the client's question,
    /// its RD and CD flags, and EDNS without options. Implementations make
    /// sure the answer is to exactly this question.
    fn forward(
        &self,
        query: Message,
        target: Target,
    ) -> impl Future<Output = Result<Message, ForwardError>> + Send;
}

/// The response to send, if any, and how the query was answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// None: send nothing.
    pub response: Option<Vec<u8>>,
    pub outcome: Outcome,
}

#[derive(Debug)]
pub struct Resolver<F> {
    policy: Arc<Policy>,
    cache: Cache,
    forwarder: F,
    allow_clients: Vec<Network>,
    /// Upstream exchanges at once; a miss that finds none free is SERVFAIL.
    in_flight: Semaphore,
    queries: Queries,
    /// One log line per query (`log.queries`).
    log_queries: AtomicBool,
}

impl<F: Forwarder> Resolver<F> {
    #[must_use]
    pub fn new(
        policy: Arc<Policy>,
        cache: Cache,
        forwarder: F,
        allow_clients: Vec<Network>,
        max_in_flight: usize,
    ) -> Self {
        Resolver {
            policy,
            cache,
            forwarder,
            allow_clients,
            in_flight: Semaphore::new(max_in_flight),
            queries: Queries::default(),
            log_queries: AtomicBool::new(false),
        }
    }

    /// The queries answered since start, per Outcome.
    #[must_use]
    pub fn queries(&self) -> &Queries {
        &self.queries
    }

    /// Turns the per-query log on or off.
    pub fn log_queries(&self, on: bool) {
        self.log_queries.store(on, Ordering::Relaxed);
    }

    #[must_use]
    pub fn policy(&self) -> &Arc<Policy> {
        &self.policy
    }

    #[must_use]
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    #[must_use]
    pub fn forwarder(&self) -> &F {
        &self.forwarder
    }

    /// True if `client` may query.
    #[must_use]
    pub fn is_allowed(&self, client: IpAddr) -> bool {
        self.allow_clients
            .iter()
            .any(|network| network.contains(client))
    }

    /// Answers one query from `client`, and counts and logs it.
    pub async fn handle(&self, query: &[u8], client: IpAddr, transport: Transport) -> Reply {
        let started = Instant::now();
        let (reply, message) = self.answer(query, client, transport).await;
        self.queries.record(reply.outcome);
        if self.log_queries.load(Ordering::Relaxed) {
            let question = message.as_ref().and_then(|message| message.queries.first());
            tracing::info!(
                target: "zinkhole::query",
                %client,
                name = %question.map_or_else(|| "-".to_owned(), |q| shown_name(q.name())),
                r#type = %question.map_or_else(|| "-".to_owned(), |q| q.query_type().to_string()),
                outcome = %reply.outcome,
                micros = started.elapsed().as_micros(),
            );
        }
        reply
    }

    /// The reply, and the query if it could be read.
    async fn answer(
        &self,
        query: &[u8],
        client: IpAddr,
        transport: Transport,
    ) -> (Reply, Option<Message>) {
        if !self.is_allowed(client) {
            // Over UDP the source is unproven: answering would let anyone aim
            // packets at a third party.
            let response = match transport {
                Transport::Udp => None,
                Transport::Tcp => answer::header_only(query, ResponseCode::Refused),
            };
            let reply = Reply {
                response,
                outcome: Outcome::Refused,
            };
            return (reply, None);
        }
        let Ok(message) = Message::from_vec(query) else {
            let reply = Reply {
                response: answer::header_only(query, ResponseCode::FormErr),
                outcome: Outcome::Invalid,
            };
            return (reply, None);
        };
        let reply = match self.resolve(&message).await {
            Ok((response, outcome)) => Reply {
                response: encode(&message, &response, transport),
                outcome,
            },
            Err(Dropped) => Reply {
                response: None,
                outcome: Outcome::Invalid,
            },
        };
        (reply, Some(message))
    }

    async fn resolve(&self, query: &Message) -> Result<(Message, Outcome), Dropped> {
        if query.metadata.message_type != MessageType::Query {
            return Err(Dropped);
        }
        if query.metadata.op_code != OpCode::Query {
            return Ok((
                answer::response(query, ResponseCode::NotImp),
                Outcome::Invalid,
            ));
        }
        let [question] = query.queries.as_slice() else {
            return Ok((
                answer::response(query, ResponseCode::FormErr),
                Outcome::Invalid,
            ));
        };
        let qtype = question.query_type();
        if question.query_class() != DNSClass::IN
            || matches!(qtype, RecordType::AXFR | RecordType::IXFR)
        {
            return Ok((
                answer::response(query, ResponseCode::Refused),
                Outcome::Refused,
            ));
        }
        let Some(name) = policy_name(question.name()) else {
            return Ok((
                answer::response(query, ResponseCode::Refused),
                Outcome::Invalid,
            ));
        };
        Ok(match self.policy.decide(&name, qtype) {
            Decision::Local { addresses, ttl } => (
                answer::addresses(query, &addresses, ttl, true),
                Outcome::Local,
            ),
            Decision::Reverse { host, ttl } => (answer::reverse(query, &host, ttl), Outcome::Local),
            Decision::Blocked(blocked) => (answer::blocked(query, blocked), Outcome::Blocked),
            Decision::Private { ttl } => (
                answer::negative(query, ResponseCode::NXDomain, ttl),
                Outcome::Private,
            ),
            Decision::Forward { server } => {
                self.resolve_upstream(query, &name, Target::Zone(server))
                    .await
            }
            Decision::Upstream => self.resolve_upstream(query, &name, Target::Upstream).await,
        })
    }

    /// Steps 6 and 7: the cache, then `target`, then a stale cached answer.
    async fn resolve_upstream(
        &self,
        query: &Message,
        name: &str,
        target: Target,
    ) -> (Message, Outcome) {
        let Some(key) = Key::of(query) else {
            return (
                answer::response(query, ResponseCode::FormErr),
                Outcome::Invalid,
            );
        };
        let key = match target {
            Target::Upstream => key,
            Target::Zone(server) => key.via_zone(server),
        };
        if let Some(cached) = self.cache.lookup(&key, Instant::now()) {
            return self.alias_checked(query, name, cached, Outcome::Cached);
        }
        // A full pool fails at once (ADR-0001): local and cached answers never
        // wait behind upstream ones, and an outage cannot grow memory. A pool
        // full of exchanges that time out is an outage: a stale answer helps.
        let Ok(_permit) = self.in_flight.try_acquire() else {
            return self.stale_or_failed(query, name, &key);
        };
        match self.forwarder.forward(upstream_query(query), target).await {
            // The upstream server could not get an answer either (its
            // authoritative servers are down, say): as good as none, so a
            // stale answer helps (RFC 8767), and it counts as failed.
            Ok(fresh) if fresh.metadata.response_code == ResponseCode::ServFail => {
                self.stale_or_failed(query, name, &key)
            }
            Ok(fresh) => {
                // Cached as it came: the aliases are checked again on every
                // hit, so a Reload that changes the rules applies at once.
                self.cache.store(key, &fresh, Instant::now());
                self.alias_checked(query, name, fresh, Outcome::Forwarded)
            }
            Err(ForwardError::NoAnswer) => self.stale_or_failed(query, name, &key),
            // Forged or broken: never cached, and no stale answer stands in
            // for it either (the name may be under attack right now).
            Err(ForwardError::Bogus) => (
                answer::response(query, ResponseCode::ServFail),
                Outcome::Bogus,
            ),
        }
    }

    /// No upstream answer: one that expired less than `serve_stale_hours` ago
    /// (RFC 8767), else SERVFAIL.
    fn stale_or_failed(&self, query: &Message, name: &str, key: &Key) -> (Message, Outcome) {
        match self.cache.lookup_stale(key, Instant::now()) {
            Some(stale) => self.alias_checked(query, name, stale, Outcome::Cached),
            None => (
                answer::response(query, ResponseCode::ServFail),
                Outcome::Failed,
            ),
        }
    }

    /// `answer` for the client, unless a CNAME in it makes `name` an alias of
    /// a blocked name: then the block response (ADR-0001).
    fn alias_checked(
        &self,
        query: &Message,
        name: &str,
        upstream: Message,
        outcome: Outcome,
    ) -> (Message, Outcome) {
        let blocked = upstream
            .answers
            .iter()
            .find_map(|record| match &record.data {
                RData::CNAME(target) => {
                    policy_name(&target.0).and_then(|target| self.policy.block_alias(name, &target))
                }
                _ => None,
            });
        match blocked {
            Some(blocked) => (answer::blocked(query, blocked), Outcome::Blocked),
            None => (answer::for_client(query, upstream), outcome),
        }
    }
}

/// The query was not a query: send nothing.
struct Dropped;

/// `name` as the Policy compares names: lowercase, without the trailing dot.
/// None if a label holds a `.`, which has no unambiguous text form.
fn policy_name(name: &Name) -> Option<String> {
    let mut text = String::with_capacity(name.len());
    for label in name {
        if label.contains(&b'.') {
            return None;
        }
        if !text.is_empty() {
            text.push('.');
        }
        text.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
    }
    Some(text)
}

/// `name` for the query log: as the client wrote it, without the root dot.
fn shown_name(name: &Name) -> String {
    let mut text = name.to_string();
    if text.len() > 1 && text.ends_with('.') {
        text.pop();
    }
    text
}

/// What is sent upstream: the client's question and CD, and a fresh OPT
/// record (if the client sent one) without options, so client cookies and
/// client subnet never leave the network, and answers are safe to share
/// between clients through the cache. Always RD (zinkhole is a forwarder:
/// a client's RD=0 would fetch a referral for everyone) and AD (so the
/// answer says whether the upstream validated it; `answer::for_client`
/// decides per client whether to show that).
fn upstream_query(query: &Message) -> Message {
    let mut upstream = Message::query();
    upstream.metadata.recursion_desired = true;
    upstream.metadata.checking_disabled = query.metadata.checking_disabled;
    upstream.metadata.authentic_data = true;
    upstream.queries.clone_from(&query.queries);
    upstream.edns = query
        .edns
        .as_ref()
        .map(|edns| answer::fresh_edns(edns.flags().dnssec_ok));
    upstream
}

/// The response's bytes, truncated (TC, no records) when too large for a UDP
/// client. If it cannot be encoded at all, SERVFAIL.
fn encode(query: &Message, response: &Message, transport: Transport) -> Option<Vec<u8>> {
    let Ok(bytes) = response.to_vec() else {
        return answer::response(query, ResponseCode::ServFail)
            .to_vec()
            .ok();
    };
    if transport == Transport::Udp && bytes.len() > answer::max_udp_size(query) {
        return answer::truncated(response).to_vec().ok();
    }
    Some(bytes)
}

#[cfg(test)]
mod tests;
