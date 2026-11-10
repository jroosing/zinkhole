//! The query pipeline through [`Resolver::handle`], with an in-memory
//! [`Forwarder`]: no sockets.

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Edns, Query};
use hickory_proto::rr::Record;
use hickory_proto::rr::rdata::{A, CNAME};

use super::*;
use crate::config::Config;

/// What the in-memory upstream does with every query.
#[derive(Debug, Clone, Copy)]
enum Behaviour {
    /// One A record, 1.2.3.4, TTL 300.
    Answer,
    /// A CNAME to `cdn.tracker.net`, then its A record.
    Alias,
    /// No server answers.
    Fail,
    /// The server answers SERVFAIL.
    ServFail,
    /// The answer fails DNSSEC validation.
    Bogus,
    /// Answers after this long.
    Slow(Duration),
}

#[derive(Debug)]
struct TestForwarder {
    behaviour: Mutex<Behaviour>,
    calls: AtomicUsize,
    /// Every query sent, with its target.
    sent: Mutex<Vec<(Message, Target)>>,
}

impl TestForwarder {
    fn new(behaviour: Behaviour) -> TestForwarder {
        TestForwarder {
            behaviour: Mutex::new(behaviour),
            calls: AtomicUsize::new(0),
            sent: Mutex::new(Vec::new()),
        }
    }

    fn set(&self, behaviour: Behaviour) {
        *self.behaviour.lock().unwrap() = behaviour;
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Forwarder for TestForwarder {
    async fn forward(&self, query: Message, target: Target) -> Result<Message, ForwardError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.sent.lock().unwrap().push((query.clone(), target));
        let behaviour = *self.behaviour.lock().unwrap();
        let owner = query.queries[0].name().clone();
        let mut answer = answer::response(&query, ResponseCode::NoError);
        let a = |name: Name| Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
        match behaviour {
            Behaviour::Answer => answer.answers.push(a(owner)),
            Behaviour::Alias => {
                let target = Name::from_str("cdn.tracker.net.").unwrap();
                answer.answers.push(Record::from_rdata(
                    owner,
                    300,
                    RData::CNAME(CNAME(target.clone())),
                ));
                answer.answers.push(a(target));
            }
            Behaviour::Fail => return Err(ForwardError::NoAnswer),
            Behaviour::ServFail => answer.metadata.response_code = ResponseCode::ServFail,
            Behaviour::Bogus => return Err(ForwardError::Bogus),
            Behaviour::Slow(delay) => {
                tokio::time::sleep(delay).await;
                answer.answers.push(a(owner));
            }
        }
        Ok(answer)
    }
}

fn resolver(toml: &str, behaviour: Behaviour) -> Resolver<TestForwarder> {
    let text = format!("[upstream]\nservers = [\"9.9.9.9\"]\nmax_in_flight = 2\n{toml}");
    let config = Config::parse(&text).unwrap_or_else(|e| panic!("{e}"));
    Resolver::new(
        Arc::new(Policy::new(&config.policy_settings())),
        Cache::new(&config.cache),
        TestForwarder::new(behaviour),
        config.server.allow_clients.clone(),
        usize::try_from(config.upstream.max_in_flight).unwrap(),
    )
}

fn query(name: &str, qtype: RecordType) -> Message {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), qtype));
    query
}

const LAN: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));

async fn ask_message<F: Forwarder>(
    r: &Resolver<F>,
    query: &Message,
    transport: Transport,
) -> (Message, Outcome) {
    let reply = r.handle(&query.to_vec().unwrap(), LAN, transport).await;
    let response = Message::from_vec(&reply.response.expect("a response")).unwrap();
    assert_eq!(response.metadata.id, query.metadata.id);
    (response, reply.outcome)
}

async fn ask<F: Forwarder>(r: &Resolver<F>, name: &str, qtype: RecordType) -> (Message, Outcome) {
    ask_message(r, &query(name, qtype), Transport::Udp).await
}

/// Caches an A answer for `name` that expired ten minutes ago, so it can be
/// served stale.
fn store_expired<F: Forwarder>(r: &Resolver<F>, name: &str, ip: Ipv4Addr) {
    let q = query(name, RecordType::A);
    let mut old = answer::response(&q, ResponseCode::NoError);
    old.answers.push(Record::from_rdata(
        q.queries[0].name().clone(),
        60,
        RData::A(A(ip)),
    ));
    let then = Instant::now().checked_sub(Duration::from_mins(11)).unwrap();
    r.cache().store(Key::of(&q).unwrap(), &old, then);
}

fn first_a(response: &Message) -> Option<Ipv4Addr> {
    response
        .answers
        .iter()
        .find_map(|record| match record.data {
            RData::A(A(ip)) => Some(ip),
            _ => None,
        })
}

#[tokio::test]
async fn local_records_are_answered_authoritatively_and_ptr_with_the_hostname() {
    let r = resolver(
        "[local.records]\n\"nas.lan\" = \"192.168.1.10\"\n",
        Behaviour::Fail,
    );
    let (a, outcome) = ask(&r, "NAS.lan.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Local);
    assert!(a.metadata.authoritative);
    assert_eq!(first_a(&a), Some(Ipv4Addr::new(192, 168, 1, 10)));
    assert_eq!(
        a.queries[0].name().to_string(),
        "NAS.lan.",
        "the client's spelling is echoed"
    );

    let (ptr, outcome) = ask(&r, "10.1.168.192.in-addr.arpa.", RecordType::PTR).await;
    assert_eq!(outcome, Outcome::Local);
    assert!(matches!(&ptr.answers[0].data, RData::PTR(host) if host.0.to_string() == "nas.lan."));
    assert_eq!(r.forwarder().calls(), 0);
}

#[tokio::test]
async fn blocked_names_and_private_names_are_answered_here() {
    let r = resolver(
        "[blocking]\nblock = [\"ads.example.com\"]\n",
        Behaviour::Answer,
    );
    let (blocked, outcome) = ask(&r, "x.ads.example.com.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Blocked);
    assert_eq!(first_a(&blocked), Some(Ipv4Addr::UNSPECIFIED));

    for name in ["printer.", "nas.lan.", "use-application-dns.net."] {
        let (response, _) = ask(&r, name, RecordType::A).await;
        assert_eq!(
            response.metadata.response_code,
            ResponseCode::NXDomain,
            "{name}"
        );
        assert!(
            matches!(response.authorities[0].data, RData::SOA(_)),
            "{name}: an SOA for the negative TTL"
        );
    }
    assert_eq!(r.forwarder().calls(), 0);
}

#[tokio::test]
async fn a_miss_is_forwarded_then_answered_from_the_cache() {
    let r = resolver("", Behaviour::Answer);
    let (first, outcome) = ask(&r, "example.com.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Forwarded);
    assert_eq!(first_a(&first), Some(Ipv4Addr::new(1, 2, 3, 4)));
    let (second, outcome) = ask(&r, "EXAMPLE.com.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Cached);
    assert_eq!(first_a(&second), Some(Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(r.forwarder().calls(), 1);
}

#[tokio::test]
async fn client_edns_options_never_reach_upstream() {
    let r = resolver("", Behaviour::Answer);
    let mut with_edns = query("example.com.", RecordType::A);
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(true);
    edns.options_mut()
        .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(
            10,
            vec![1, 2, 3, 4, 5, 6, 7, 8],
        ));
    with_edns.edns = Some(edns);
    let (response, _) = ask_message(&r, &with_edns, Transport::Udp).await;
    assert_eq!(
        response.edns.as_ref().map(Edns::max_payload),
        Some(answer::EDNS_PAYLOAD)
    );

    let sent = r.forwarder().sent.lock().unwrap();
    let (upstream, target) = &sent[0];
    assert_eq!(*target, Target::Upstream);
    let upstream_edns = upstream.edns.as_ref().expect("EDNS, as the client used it");
    assert!(
        upstream_edns.options().as_ref().is_empty(),
        "no client cookie"
    );
    assert!(upstream_edns.flags().dnssec_ok, "but the DO bit");
    assert_eq!(upstream_edns.max_payload(), answer::EDNS_PAYLOAD);
    assert!(upstream.metadata.recursion_desired);
}

#[tokio::test]
async fn a_clients_rd_and_ad_flags_never_change_what_is_asked_upstream() {
    // One client's `dig +norec` must not fetch a referral that the cache
    // then hands to everyone; nor may its AD=0 hide validation from others.
    let r = resolver("", Behaviour::Answer);
    let mut plain = query("example.com.", RecordType::A);
    plain.metadata.recursion_desired = false;
    plain.metadata.authentic_data = false;
    ask_message(&r, &plain, Transport::Udp).await;

    let sent = r.forwarder().sent.lock().unwrap();
    let (upstream, _) = &sent[0];
    assert!(upstream.metadata.recursion_desired, "RD");
    assert!(upstream.metadata.authentic_data, "AD");
}

#[tokio::test]
async fn a_name_in_a_forwarded_zone_goes_to_the_zones_server() {
    let r = resolver(
        "[local.forward]\n\"lan\" = \"192.168.1.1\"\n",
        Behaviour::Answer,
    );
    let (_, outcome) = ask(&r, "printer.lan.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Forwarded);
    let (_, outcome) = ask(&r, "printer.lan.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Cached);
    let sent = r.forwarder().sent.lock().unwrap();
    assert_eq!(sent[0].1, Target::Zone("192.168.1.1:53".parse().unwrap()));
}

#[tokio::test]
async fn a_reload_that_adds_a_forwarded_zone_stops_serving_the_upstream_answers_cached_for_it() {
    let r = resolver("", Behaviour::Answer);
    assert_eq!(
        ask(&r, "nas.home.example.", RecordType::A).await.1,
        Outcome::Forwarded
    );
    assert_eq!(
        ask(&r, "nas.home.example.", RecordType::A).await.1,
        Outcome::Cached
    );

    let with_zone = Config::parse(
        "[upstream]\nservers = [\"9.9.9.9\"]\n[local.forward]\n\"home.example\" = \"192.168.1.1\"\n",
    )
    .unwrap();
    r.policy().apply(&with_zone.policy_settings());
    assert_eq!(
        ask(&r, "nas.home.example.", RecordType::A).await.1,
        Outcome::Forwarded
    );
    let sent = r.forwarder().sent.lock().unwrap();
    assert_eq!(
        sent.last().unwrap().1,
        Target::Zone("192.168.1.1:53".parse().unwrap())
    );
}

#[tokio::test]
async fn an_answer_whose_cname_points_at_a_blocked_name_is_blocked_also_from_the_cache() {
    let r = resolver(
        "[blocking]\nttl = 30\nblock = [\"tracker.net\"]\n",
        Behaviour::Alias,
    );
    for expected in [Outcome::Blocked, Outcome::Blocked] {
        let (response, outcome) = ask(&r, "metrics.shop.example.", RecordType::A).await;
        assert_eq!(outcome, expected);
        assert_eq!(first_a(&response), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(response.answers[0].ttl, 30);
    }
    assert_eq!(r.forwarder().calls(), 1, "the second from the cache");

    let allowed = resolver(
        "[blocking]\nblock = [\"tracker.net\"]\nallow = [\"metrics.shop.example\"]\n",
        Behaviour::Alias,
    );
    let (response, outcome) = ask(&allowed, "metrics.shop.example.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Forwarded);
    assert_eq!(response.answers.len(), 2);
}

#[tokio::test]
async fn when_no_server_answers_an_expired_answer_is_served_stale_else_servfail() {
    let r = resolver("", Behaviour::Fail);
    let (response, outcome) = ask(&r, "example.com.", RecordType::A).await;
    assert_eq!(
        (response.metadata.response_code, outcome),
        (ResponseCode::ServFail, Outcome::Failed)
    );

    // An answer that expired ten minutes ago, within the 24 hours.
    let q = query("example.com.", RecordType::A);
    let mut old = answer::response(&q, ResponseCode::NoError);
    old.answers.push(Record::from_rdata(
        q.queries[0].name().clone(),
        60,
        RData::A(A(Ipv4Addr::new(5, 6, 7, 8))),
    ));
    let then = Instant::now().checked_sub(Duration::from_mins(11)).unwrap();
    r.cache().store(Key::of(&q).unwrap(), &old, then);
    let (stale, outcome) = ask(&r, "example.com.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Cached);
    assert_eq!(first_a(&stale), Some(Ipv4Addr::new(5, 6, 7, 8)));
    assert_eq!(stale.answers[0].ttl, crate::cache::STALE_TTL);
}

#[tokio::test]
async fn an_upstream_servfail_counts_as_failed_and_is_replaced_by_a_stale_answer() {
    let r = resolver("", Behaviour::ServFail);
    let (response, outcome) = ask(&r, "example.com.", RecordType::A).await;
    assert_eq!(
        (response.metadata.response_code, outcome),
        (ResponseCode::ServFail, Outcome::Failed)
    );
    store_expired(&r, "example.com.", Ipv4Addr::new(5, 6, 7, 8));
    let (stale, outcome) = ask(&r, "example.com.", RecordType::A).await;
    assert_eq!(
        (outcome, first_a(&stale)),
        (Outcome::Cached, Some(Ipv4Addr::new(5, 6, 7, 8)))
    );
}

#[tokio::test]
async fn a_bogus_answer_is_servfail_never_cached_and_never_replaced_by_a_stale_one() {
    let r = resolver("", Behaviour::Bogus);
    // An expired answer that would be served stale if no server answered.
    let q = query("example.com.", RecordType::A);
    let mut old = answer::response(&q, ResponseCode::NoError);
    old.answers.push(Record::from_rdata(
        q.queries[0].name().clone(),
        60,
        RData::A(A(Ipv4Addr::new(5, 6, 7, 8))),
    ));
    let then = Instant::now().checked_sub(Duration::from_mins(11)).unwrap();
    r.cache().store(Key::of(&q).unwrap(), &old, then);

    let (response, outcome) = ask(&r, "example.com.", RecordType::A).await;
    assert_eq!(
        (response.metadata.response_code, outcome),
        (ResponseCode::ServFail, Outcome::Bogus)
    );
    assert_eq!(response.answers.len(), 0);
    assert_eq!(r.queries().count(Outcome::Bogus), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_every_slot_busy_a_miss_fails_at_once_and_local_answers_stay_instant() {
    let r = Arc::new(resolver(
        "[local.records]\n\"nas.lan\" = \"10.0.0.10\"\n",
        Behaviour::Slow(Duration::from_millis(500)),
    ));
    // max_in_flight = 2: two slow misses take both permits.
    let slow: Vec<_> = (0..2)
        .map(|i| {
            let r = Arc::clone(&r);
            tokio::spawn(
                async move { ask(&r, &format!("slow{i}.example."), RecordType::A).await.1 },
            )
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = Instant::now();
    let (_, outcome) = ask(&r, "third.example.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Failed);
    // A name with an answer that expired a little while ago gets that.
    store_expired(&r, "stale.example.", Ipv4Addr::new(5, 6, 7, 8));
    let (stale, outcome) = ask(&r, "stale.example.", RecordType::A).await;
    assert_eq!(
        (outcome, first_a(&stale)),
        (Outcome::Cached, Some(Ipv4Addr::new(5, 6, 7, 8)))
    );
    let (_, outcome) = ask(&r, "nas.lan.", RecordType::A).await;
    assert_eq!(outcome, Outcome::Local);
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "neither waited for a slot"
    );

    for task in slow {
        assert_eq!(task.await.unwrap(), Outcome::Forwarded);
    }
    // The permits are free again.
    r.forwarder().set(Behaviour::Answer);
    assert_eq!(
        ask(&r, "fourth.example.", RecordType::A).await.1,
        Outcome::Forwarded
    );
}

#[tokio::test]
async fn disallowed_clients_are_dropped_over_udp_and_refused_over_tcp() {
    let r = resolver(
        "[local.records]\n\"nas.lan\" = \"10.0.0.10\"\n",
        Behaviour::Answer,
    );
    let bytes = query("nas.lan.", RecordType::A).to_vec().unwrap();
    let outsider = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

    let udp = r.handle(&bytes, outsider, Transport::Udp).await;
    assert_eq!(
        udp,
        Reply {
            response: None,
            outcome: Outcome::Refused
        }
    );
    let tcp = r.handle(&bytes, outsider, Transport::Tcp).await;
    assert_eq!(tcp.outcome, Outcome::Refused);
    let refused = Message::from_vec(&tcp.response.unwrap()).unwrap();
    assert_eq!(refused.metadata.response_code, ResponseCode::Refused);
    assert_eq!(refused.answers.len(), 0);
    // Malformed UDP from outsiders is dropped too.
    assert_eq!(
        r.handle(&bytes[..5], outsider, Transport::Udp)
            .await
            .response,
        None
    );
}

#[tokio::test]
async fn zone_transfers_other_classes_and_malformed_queries() {
    let r = resolver("", Behaviour::Answer);
    let (axfr, outcome) = ask(&r, "lan.", RecordType::AXFR).await;
    assert_eq!(
        (axfr.metadata.response_code, outcome),
        (ResponseCode::Refused, Outcome::Refused)
    );

    let mut chaos = query("version.bind.", RecordType::TXT);
    chaos.queries[0].set_query_class(DNSClass::CH);
    let (response, _) = ask_message(&r, &chaos, Transport::Udp).await;
    assert_eq!(response.metadata.response_code, ResponseCode::Refused);

    let mut bytes = query("example.com.", RecordType::A).to_vec().unwrap();
    bytes.truncate(bytes.len() - 2);
    let reply = r.handle(&bytes, LAN, Transport::Udp).await;
    assert_eq!(reply.outcome, Outcome::Invalid);
    let formerr = Message::from_vec(&reply.response.unwrap()).unwrap();
    assert_eq!(formerr.metadata.response_code, ResponseCode::FormErr);

    // A response is never answered.
    let mut response = query("example.com.", RecordType::A);
    response.metadata.message_type = MessageType::Response;
    let reply = r
        .handle(&response.to_vec().unwrap(), LAN, Transport::Udp)
        .await;
    assert_eq!(
        reply,
        Reply {
            response: None,
            outcome: Outcome::Invalid
        }
    );
    assert_eq!(r.forwarder().calls(), 0);
}

#[tokio::test]
async fn an_answer_too_large_for_udp_is_truncated_and_complete_over_tcp() {
    // A long name with 16 IPv6 addresses: about 660 bytes, over the 512 a
    // client without EDNS accepts.
    let name = format!(
        "{}.{}.{}.lan",
        "a".repeat(60),
        "b".repeat(60),
        "c".repeat(60)
    );
    let addresses: Vec<String> = (1..=16).map(|i| format!("\"fd00::{i:x}\"")).collect();
    let r = resolver(
        &format!("[local.records]\n\"{name}\" = [{}]\n", addresses.join(", ")),
        Behaviour::Fail,
    );
    let q = query(&format!("{name}."), RecordType::AAAA);

    let reply = r.handle(&q.to_vec().unwrap(), LAN, Transport::Udp).await;
    let bytes = reply.response.unwrap();
    assert!(bytes.len() <= 512);
    let udp = Message::from_vec(&bytes).unwrap();
    assert!(udp.metadata.truncation && udp.answers.is_empty());

    let (tcp, _) = ask_message(&r, &q, Transport::Tcp).await;
    assert!(!tcp.metadata.truncation);
    assert_eq!(tcp.answers.len(), 16);
}

#[test]
fn policy_names_are_lowercase_without_the_root_dot() {
    assert_eq!(
        policy_name(&Name::from_str("NAS.Lan.").unwrap()).as_deref(),
        Some("nas.lan")
    );
    assert_eq!(policy_name(&Name::root()).as_deref(), Some(""));
    let dotted = Name::from_labels(vec![b"a.b".as_slice(), b"lan".as_slice()]).unwrap();
    assert_eq!(policy_name(&dotted), None);
}
