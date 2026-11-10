//! The upstream servers against stub servers on loopback: plain DNS and DNS
//! over HTTPS, offline.

use std::str::FromStr;
use std::time::Duration;

use hickory_proto::op::Query;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};

use super::*;
use crate::answer;
use crate::stub::{Behaviour, DohStub, DoqStub, PlainStub};

fn settings(servers: &[String], timeout_ms: u32) -> config::Upstream {
    toml::from_str(&format!(
        "servers = [{}]\ntimeout_ms = {timeout_ms}\n",
        servers.join(", ")
    ))
    .unwrap()
}

fn plain(stub: &PlainStub) -> String {
    format!("\"{}\"", stub.address)
}

fn query(name: &str) -> Message {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    query
}

fn first_a(answer: &Message) -> Option<std::net::Ipv4Addr> {
    answer.answers.iter().find_map(|record| match record.data {
        RData::A(A(ip)) => Some(ip),
        _ => None,
    })
}

#[tokio::test]
async fn a_plain_server_answers() {
    let stub = PlainStub::start(Behaviour::Answer).await;
    let upstream = Upstream::new(&settings(&[plain(&stub)], 1000));
    let answer = upstream
        .forward(query("example.com."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(first_a(&answer), Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));
    let stats = upstream.stats();
    assert_eq!((stats[0].answer_times.count(), stats[0].failures), (1, 0));
}

#[tokio::test]
async fn a_spoofed_answer_with_the_wrong_id_is_ignored() {
    let stub = PlainStub::start(Behaviour::SpoofFirst).await;
    let upstream = Upstream::new(&settings(&[plain(&stub)], 1000));
    let answer = upstream
        .forward(query("example.com."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(
        first_a(&answer),
        Some(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        "not 6.6.6.6"
    );
}

#[tokio::test]
async fn a_truncated_answer_is_fetched_again_over_tcp() {
    let stub = PlainStub::start(Behaviour::Truncate).await;
    let upstream = Upstream::new(&settings(&[plain(&stub)], 1000));
    let answer = upstream
        .forward(query("example.com."), Target::Upstream)
        .await
        .unwrap();
    assert!(!answer.metadata.truncation);
    assert_eq!(first_a(&answer), Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(stub.received(), 2, "once over UDP, once over TCP");
}

#[tokio::test]
async fn an_answer_to_another_question_is_a_failure() {
    let stub = PlainStub::start(Behaviour::WrongQuestion).await;
    let upstream = Upstream::new(&settings(&[plain(&stub)], 300));
    assert_eq!(
        upstream
            .forward(query("example.com."), Target::Upstream)
            .await,
        Err(ForwardError::NoAnswer)
    );
}

#[tokio::test]
async fn refused_and_silent_servers_fail_over_to_the_next_which_is_then_preferred() {
    let refusing = PlainStub::start(Behaviour::Refuse).await;
    let silent = PlainStub::start(Behaviour::Silent).await;
    let good = PlainStub::start(Behaviour::Answer).await;
    let upstream = Upstream::new(&settings(
        &[plain(&refusing), plain(&silent), plain(&good)],
        300,
    ));

    let started = Instant::now();
    upstream
        .forward(query("a.example."), Target::Upstream)
        .await
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "the silent server gets one timeout, no more"
    );
    assert_eq!(upstream.preferred(), 2);
    let stats = upstream.stats();
    assert_eq!(
        stats.iter().map(|s| s.failures).collect::<Vec<_>>(),
        [1, 1, 0]
    );

    // The server that answered last is asked first.
    upstream
        .forward(query("b.example."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!((refusing.received(), good.received()), (1, 2));
}

#[tokio::test]
async fn after_a_failover_the_first_server_is_tried_again_once_a_minute_and_takes_over() {
    let first = PlainStub::start(Behaviour::Silent).await;
    let second = PlainStub::start(Behaviour::Answer).await;
    let upstream = Upstream::new(&settings(&[plain(&first), plain(&second)], 200));
    upstream
        .forward(query("a.example."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(upstream.preferred(), 1);

    // Within the minute the first server is left alone.
    upstream
        .forward(query("b.example."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(first.received(), 1);

    // The minute is over (moved forward instead of waited for); it answers now.
    first.set(Behaviour::Answer);
    upstream.failover.retry_first_at.store(0, Ordering::Relaxed);
    upstream
        .forward(query("c.example."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(first.received(), 2);
    assert_eq!(upstream.preferred(), 0);
}

#[tokio::test]
async fn the_retry_of_the_first_server_goes_straight_back_to_the_preferred_one() {
    let first = PlainStub::start(Behaviour::Silent).await;
    let second = PlainStub::start(Behaviour::Silent).await;
    let third = PlainStub::start(Behaviour::Answer).await;
    let upstream = Upstream::new(&settings(
        &[plain(&first), plain(&second), plain(&third)],
        200,
    ));
    upstream
        .forward(query("a.example."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(upstream.preferred(), 2);

    // The minute is over: the first server is asked again, still silent,
    // and then the preferred one; the second is not asked a second time.
    upstream.failover.retry_first_at.store(0, Ordering::Relaxed);
    let started = Instant::now();
    upstream
        .forward(query("b.example."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!((first.received(), second.received()), (2, 1));
    assert!(
        started.elapsed() < Duration::from_millis(390),
        "one timeout, not two"
    );
}

#[tokio::test]
async fn when_every_server_fails_the_answer_is_all_servers_failed() {
    let silent = PlainStub::start(Behaviour::Silent).await;
    let refusing = PlainStub::start(Behaviour::Refuse).await;
    let upstream = Upstream::new(&settings(&[plain(&silent), plain(&refusing)], 200));
    assert_eq!(
        upstream
            .forward(query("example.com."), Target::Upstream)
            .await,
        Err(ForwardError::NoAnswer)
    );
}

#[tokio::test]
async fn a_forwarded_zone_server_is_asked_alone_and_not_counted() {
    let zone = PlainStub::start(Behaviour::Answer).await;
    let upstream_stub = PlainStub::start(Behaviour::Answer).await;
    let upstream = Upstream::new(&settings(&[plain(&upstream_stub)], 500));
    upstream
        .forward(query("printer.lan."), Target::Zone(zone.address))
        .await
        .unwrap();
    assert_eq!((zone.received(), upstream_stub.received()), (1, 0));
    assert_eq!(upstream.stats()[0].answer_times.count(), 0);

    zone.set(Behaviour::Refuse);
    assert_eq!(
        upstream
            .forward(query("printer.lan."), Target::Zone(zone.address))
            .await,
        Err(ForwardError::NoAnswer)
    );
    assert_eq!(
        upstream_stub.received(),
        0,
        "no failover to the upstream servers"
    );
}

#[tokio::test]
async fn dns_over_https_answers_and_shares_one_connection() {
    let doh = DohStub::start(Behaviour::Answer, false).await;
    let upstream = Arc::new(Upstream::with_roots(
        &settings(&[doh.config()], 2000),
        doh.roots.clone(),
    ));
    let answer = upstream
        .forward(query("example.com."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(first_a(&answer), Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));

    // Many queries at once go over the same HTTP/2 connection.
    let queries: Vec<_> = (0..20)
        .map(|i| {
            let upstream = Arc::clone(&upstream);
            tokio::spawn(async move {
                upstream
                    .forward(query(&format!("n{i}.example.")), Target::Upstream)
                    .await
            })
        })
        .collect();
    for task in queries {
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(doh.received(), 21);
    assert_eq!(doh.connections(), 1);
}

#[tokio::test]
async fn a_closed_dns_over_https_connection_is_replaced_and_the_query_retried() {
    let doh = DohStub::start(Behaviour::Answer, true).await;
    let upstream = Upstream::with_roots(&settings(&[doh.config()], 2000), doh.roots.clone());
    upstream
        .forward(query("a.example."), Target::Upstream)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await; // the server has closed it by now
    let answer = upstream
        .forward(query("b.example."), Target::Upstream)
        .await;
    assert!(answer.is_ok(), "{answer:?}");
    assert_eq!(doh.connections(), 2);
    assert_eq!(
        upstream.stats()[0].failures,
        0,
        "a stale connection is not a failure of the server"
    );
}

#[tokio::test]
async fn a_dns_over_https_connection_that_stalls_is_not_used_again() {
    // The server accepts the connection and then never answers: no error,
    // only timeouts. Each timed-out query leaves the connection behind.
    let doh = DohStub::start(Behaviour::Silent, false).await;
    let upstream = Upstream::with_roots(&settings(&[doh.config()], 300), doh.roots.clone());
    for name in ["a.example.", "b.example.", "c.example."] {
        assert_eq!(
            upstream.forward(query(name), Target::Upstream).await,
            Err(ForwardError::NoAnswer)
        );
    }
    assert_eq!(doh.connections(), 3, "a new connection for every query");
}

#[tokio::test]
async fn an_http_error_from_a_dns_over_https_server_fails_over() {
    let doh = DohStub::start(Behaviour::HttpError, false).await;
    let fallback = PlainStub::start(Behaviour::Answer).await;
    let upstream = Upstream::with_roots(
        &settings(&[doh.config(), plain(&fallback)], 1000),
        doh.roots.clone(),
    );
    let started = Instant::now();
    upstream
        .forward(query("example.com."), Target::Upstream)
        .await
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "at once, not after the timeout"
    );
    assert_eq!(upstream.preferred(), 1);
    assert_eq!(upstream.stats()[0].failures, 1);
}

#[tokio::test]
async fn dns_over_https_fails_on_a_certificate_nobody_vouches_for() {
    let doh = DohStub::start(Behaviour::Answer, false).await;
    // Only the public roots: the stub's own certificate is not among them.
    let upstream = Upstream::new(&settings(&[doh.config()], 1000));
    assert_eq!(
        upstream
            .forward(query("example.com."), Target::Upstream)
            .await,
        Err(ForwardError::NoAnswer)
    );
    assert_eq!(
        doh.received(),
        0,
        "no query was sent over the unverified connection"
    );
}

#[tokio::test]
async fn dns_over_https_and_plain_dns_fail_over_to_each_other() {
    let doh = DohStub::start(Behaviour::Refuse, false).await;
    let fallback = PlainStub::start(Behaviour::Answer).await;
    let upstream = Upstream::with_roots(
        &settings(&[doh.config(), plain(&fallback)], 1000),
        doh.roots.clone(),
    );
    upstream
        .forward(query("example.com."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(upstream.preferred(), 1);
    let names: Vec<String> = upstream.stats().into_iter().map(|s| s.name).collect();
    assert!(
        names[0].starts_with("https://doh.test:") && names[0].ends_with("(127.0.0.1)"),
        "{names:?}"
    );
}

#[test]
fn checked_rejects_answers_that_are_not_responses_to_the_question() {
    let q = query("example.com.");
    assert!(checked(&q, answer::response(&q, ResponseCode::NoError)).is_ok());
    let mut not_a_response = answer::response(&q, ResponseCode::NoError);
    not_a_response.metadata.message_type = MessageType::Query;
    assert!(checked(&q, not_a_response).is_err());
    let mut other = answer::response(&q, ResponseCode::NoError);
    other.queries[0].set_query_type(RecordType::AAAA);
    assert!(checked(&q, other).is_err());
}

#[tokio::test]
async fn dns_over_quic_answers_and_shares_one_connection() {
    let doq = DoqStub::start(Behaviour::Answer, false).await;
    let upstream = Arc::new(Upstream::with_roots(
        &settings(&[doq.config()], 2000),
        doq.roots.clone(),
    ));
    let answer = upstream
        .forward(query("example.com."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(first_a(&answer), Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));

    // Many queries at once, each on its own stream of one connection.
    let queries: Vec<_> = (0..20)
        .map(|i| {
            let upstream = Arc::clone(&upstream);
            tokio::spawn(async move {
                upstream
                    .forward(query(&format!("n{i}.example.")), Target::Upstream)
                    .await
            })
        })
        .collect();
    for task in queries {
        assert!(task.await.unwrap().is_ok());
    }
    assert_eq!(doq.received(), 21);
    assert_eq!(doq.connections(), 1);
    let stats = upstream.stats();
    assert_eq!(stats[0].answer_times.count(), 21);
    assert!(
        stats[0].name.starts_with("quic://doq.test:") && stats[0].name.ends_with("(127.0.0.1)"),
        "{}",
        stats[0].name
    );
}

#[tokio::test]
async fn a_closed_dns_over_quic_connection_is_replaced_and_the_query_retried() {
    let doq = DoqStub::start(Behaviour::Answer, true).await;
    let upstream = Upstream::with_roots(&settings(&[doq.config()], 2000), doq.roots.clone());
    upstream
        .forward(query("a.example."), Target::Upstream)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await; // the server has closed it by now
    let answer = upstream
        .forward(query("b.example."), Target::Upstream)
        .await;
    assert!(answer.is_ok(), "{answer:?}");
    assert_eq!(doq.connections(), 2);
    assert_eq!(
        upstream.stats()[0].failures,
        0,
        "a stale connection is not a failure of the server"
    );
}

#[tokio::test]
async fn dns_over_quic_fails_on_a_certificate_nobody_vouches_for_and_fails_over() {
    let doq = DoqStub::start(Behaviour::Answer, false).await;
    let fallback = PlainStub::start(Behaviour::Answer).await;
    // Only the public roots: the stub's own certificate is not among them.
    let upstream = Upstream::new(&settings(&[doq.config(), plain(&fallback)], 1000));
    upstream
        .forward(query("example.com."), Target::Upstream)
        .await
        .unwrap();
    assert_eq!(
        doq.received(),
        0,
        "no query was sent over the unverified connection"
    );
    assert_eq!(upstream.preferred(), 1);
}

#[tokio::test]
async fn a_refusing_dns_over_quic_server_is_a_failure() {
    let doq = DoqStub::start(Behaviour::Refuse, false).await;
    let upstream = Upstream::with_roots(&settings(&[doq.config()], 1000), doq.roots.clone());
    assert_eq!(
        upstream
            .forward(query("example.com."), Target::Upstream)
            .await,
        Err(ForwardError::NoAnswer)
    );
    assert_eq!(upstream.stats()[0].failures, 1);
}

// ---------------------------------------------------------------------------
// DNSSEC: a root zone signed with a key of the test's own, trusted instead of
// the real root's.

mod dnssec {
    use hickory_proto::dnssec::crypto::EcdsaSigningKey;
    use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, NSEC, RRSIG};
    use hickory_proto::dnssec::{Algorithm, DnssecSigner, SigningKey, TrustAnchors};
    use hickory_proto::rr::rdata::SOA;
    use hickory_proto::rr::{DNSClass, Record, RecordSet};

    use super::*;

    /// The trust anchor, and the zone: its DNSKEY, `secure.` signed as it
    /// should be, and `forged.`, whose signature is over 1.2.3.4 but which
    /// says 6.6.6.6, as a man in the middle would make it.
    fn signed_root() -> (TrustAnchors, Vec<Record>) {
        let (anchors, zone, _) = signed_root_with_denial();
        (anchors, zone)
    }

    /// The same, and the denial records for names not in it: the zone's SOA
    /// and the NSEC chain `.` → `forged.` → `secure.` → `.`, signed.
    fn signed_root_with_denial() -> (TrustAnchors, Vec<Record>, Vec<Record>) {
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(Algorithm::ECDSAP256SHA256).unwrap();
        let key = EcdsaSigningKey::from_pkcs8(&pkcs8, Algorithm::ECDSAP256SHA256).unwrap();
        let public = key.to_public_key().unwrap();
        let mut anchors = TrustAnchors::empty();
        anchors.insert(&public);
        let dnskey = DNSKEY::from_key(&public);
        let signer = DnssecSigner::new(
            dnskey.clone(),
            Box::new(key),
            Name::root(),
            Duration::from_hours(1),
        );
        let sign = |record: Record| {
            let inception = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
            let rrsig = RRSIG::from_rrset(
                &RecordSet::from(record.clone()),
                DNSClass::IN,
                inception,
                &signer,
            )
            .unwrap();
            let signature = Record::from_rdata(
                record.name.clone(),
                record.ttl,
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
            );
            [record, signature]
        };
        let a = |name: &str, ip: [u8; 4]| {
            Record::from_rdata(Name::from_ascii(name).unwrap(), 300, RData::A(A(ip.into())))
        };
        let mut zone = Vec::new();
        zone.extend(sign(Record::from_rdata(
            Name::root(),
            300,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)),
        )));
        zone.extend(sign(a("secure.", [1, 2, 3, 4])));
        let [mut forged, signature] = sign(a("forged.", [1, 2, 3, 4]));
        forged.data = RData::A(A([6, 6, 6, 6].into()));
        zone.extend([forged, signature]);
        let nsec = |name: &str, next: &str, types: &[RecordType]| {
            let rdata = NSEC::new(Name::from_ascii(next).unwrap(), types.iter().copied());
            Record::from_rdata(
                Name::from_ascii(name).unwrap(),
                300,
                RData::DNSSEC(DNSSECRData::NSEC(rdata)),
            )
        };
        let soa = SOA::new(
            Name::root(),
            Name::from_ascii("admin.").unwrap(),
            1,
            3600,
            600,
            86400,
            300,
        );
        let mut denial = Vec::new();
        denial.extend(sign(Record::from_rdata(Name::root(), 300, RData::SOA(soa))));
        let apex = [
            RecordType::SOA,
            RecordType::DNSKEY,
            RecordType::NSEC,
            RecordType::RRSIG,
        ];
        let host = [RecordType::A, RecordType::NSEC, RecordType::RRSIG];
        denial.extend(sign(nsec(".", "forged.", &apex)));
        denial.extend(sign(nsec("forged.", "secure.", &host)));
        denial.extend(sign(nsec("secure.", ".", &host)));
        (anchors, zone, denial)
    }

    async fn upstream(dnssec: config::Dnssec) -> (Upstream, PlainStub) {
        let (anchors, zone) = signed_root();
        let stub = PlainStub::serving(zone).await;
        let mut config = settings(&[plain(&stub)], 2000);
        config.dnssec = dnssec;
        (
            Upstream::with_anchors(&config, rustls::RootCertStore::empty(), anchors),
            stub,
        )
    }

    #[tokio::test]
    async fn a_correctly_signed_answer_is_authenticated() {
        let (upstream, _stub) = upstream(config::Dnssec::Validate).await;
        let answer = upstream
            .forward(query("secure."), Target::Upstream)
            .await
            .unwrap();
        assert_eq!(first_a(&answer), Some(std::net::Ipv4Addr::new(1, 2, 3, 4)));
        assert!(answer.metadata.authentic_data, "AD");
    }

    #[tokio::test]
    async fn a_forged_answer_is_bogus() {
        let (upstream, _stub) = upstream(config::Dnssec::Validate).await;
        assert_eq!(
            upstream.forward(query("forged."), Target::Upstream).await,
            Err(ForwardError::Bogus)
        );
    }

    #[tokio::test]
    async fn checking_disabled_or_validation_off_passes_the_answer_on_unchecked() {
        let (validating, _stub) = upstream(config::Dnssec::Validate).await;
        let mut unchecked = query("forged.");
        unchecked.metadata.checking_disabled = true;
        let answer = validating
            .forward(unchecked, Target::Upstream)
            .await
            .unwrap();
        assert_eq!(first_a(&answer), Some(std::net::Ipv4Addr::new(6, 6, 6, 6)));
        assert!(!answer.metadata.authentic_data);

        let (passing, _stub) = upstream(config::Dnssec::Upstream).await;
        let answer = passing
            .forward(query("forged."), Target::Upstream)
            .await
            .unwrap();
        assert_eq!(first_a(&answer), Some(std::net::Ipv4Addr::new(6, 6, 6, 6)));
    }

    #[tokio::test]
    async fn a_servfail_from_upstream_stays_a_servfail_not_bogus() {
        let stub = PlainStub::start(Behaviour::ServFail).await;
        let mut config = settings(&[plain(&stub)], 2000);
        config.dnssec = config::Dnssec::Validate;
        let upstream =
            Upstream::with_anchors(&config, rustls::RootCertStore::empty(), signed_root().0);
        let answer = upstream
            .forward(query("secure."), Target::Upstream)
            .await
            .unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::ServFail);
        assert!(!answer.metadata.authentic_data);
    }

    #[tokio::test]
    async fn a_chain_lookup_without_an_answer_is_no_answer_not_bogus() {
        // The answer comes, but the DNSKEY needed to check it never does.
        let (anchors, zone) = signed_root();
        let stub = PlainStub::serving_but_silent_for(zone, RecordType::DNSKEY).await;
        let mut config = settings(&[plain(&stub)], 300);
        config.dnssec = config::Dnssec::Validate;
        let upstream = Upstream::with_anchors(&config, rustls::RootCertStore::empty(), anchors);
        assert_eq!(
            upstream.forward(query("secure."), Target::Upstream).await,
            Err(ForwardError::NoAnswer)
        );
    }

    #[tokio::test]
    async fn validation_ends_within_one_full_failover() {
        // Each answer takes 200 ms, within the 300 ms timeout, but the
        // answer and its DNSKEY one after the other take 400 ms: longer than
        // one full failover (one server, 300 ms) may take.
        let (anchors, zone) = signed_root();
        let stub = PlainStub::serving(zone).await;
        stub.delay(Duration::from_millis(200));
        let mut config = settings(&[plain(&stub)], 300);
        config.dnssec = config::Dnssec::Validate;
        let upstream = Upstream::with_anchors(&config, rustls::RootCertStore::empty(), anchors);
        let started = Instant::now();
        let answer = upstream.forward(query("secure."), Target::Upstream).await;
        assert_eq!(answer, Err(ForwardError::NoAnswer));
        assert!(
            started.elapsed() < Duration::from_millis(390),
            "{:?}",
            started.elapsed()
        );
    }

    fn validating_upstream(stub: &PlainStub, anchors: TrustAnchors) -> Upstream {
        let mut config = settings(&[plain(stub)], 2000);
        config.dnssec = config::Dnssec::Validate;
        Upstream::with_anchors(&config, rustls::RootCertStore::empty(), anchors)
    }

    #[tokio::test]
    async fn a_proven_nxdomain_is_authenticated() {
        let (anchors, zone, denial) = signed_root_with_denial();
        let stub = PlainStub::serving_with_denial(zone, denial).await;
        let upstream = validating_upstream(&stub, anchors);
        let answer = upstream
            .forward(query("missing."), Target::Upstream)
            .await
            .unwrap();
        assert_eq!(answer.metadata.response_code, ResponseCode::NXDomain);
        assert!(answer.metadata.authentic_data, "AD");
    }

    #[tokio::test]
    async fn a_denial_without_proof_in_a_signed_zone_is_bogus() {
        // The name does not exist, and nothing proves it: as forged.
        let (anchors, zone) = signed_root();
        let stub = PlainStub::serving(zone).await;
        let upstream = validating_upstream(&stub, anchors);
        assert_eq!(
            upstream.forward(query("missing."), Target::Upstream).await,
            Err(ForwardError::Bogus)
        );
    }

    #[tokio::test]
    async fn forwarded_zones_are_not_validated() {
        let (upstream, stub) = upstream(config::Dnssec::Validate).await;
        let answer = upstream
            .forward(query("forged."), Target::Zone(stub.address))
            .await
            .unwrap();
        assert_eq!(first_a(&answer), Some(std::net::Ipv4Addr::new(6, 6, 6, 6)));
    }
}
