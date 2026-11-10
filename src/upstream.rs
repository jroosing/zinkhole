//! The upstream servers: DNS over HTTPS, DNS over QUIC and plain DNS, with
//! failover, as the [`Forwarder`] behind the Resolver.
//!
//! - Plain DNS: a fresh socket with a random source port per exchange, and only
//!   an answer from the server's address with the query's ID and question is
//!   accepted (hickory's UDP client); TCP when the answer is truncated.
//! - DNS over HTTPS and DNS over QUIC: one connection per server (HTTP/2 or
//!   QUIC), shared by every query in flight, so queries never queue behind
//!   each other. A reused connection that fails is replaced and the query
//!   retried once.
//! - One timeout covers everything a server does for one query, TCP fallback
//!   and reconnect included.
//! - Servers are tried in the configured order, starting with the one that
//!   answered last; after a failover, one query a minute tries the first
//!   server again, which takes over once it answers. REFUSED counts as a
//!   failure.

use std::cell::Cell;
use std::fmt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use futures_util::{Stream, StreamExt};
use hickory_net::dnssec::DnssecDnsHandle;
use hickory_net::h2::HttpsClientStream;
use hickory_net::quic::QuicClientStream;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::{DnsExchange, FirstAnswer};
use hickory_net::{DnsError, DnsHandle, NetError};
use hickory_proto::dnssec::{Proof, TrustAnchors};
use hickory_proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Message, MessageType, ResponseCode,
};
use hickory_proto::rr::RecordType;
use rustls::ClientConfig;

use crate::config::{self, UpstreamServer};
use crate::metrics::{Histogram, ServerMetrics};
use crate::resolver::{ForwardError, Forwarder, Target};

/// After a failover, the first server is tried again this often.
const RETRY_FIRST_EVERY: Duration = Duration::from_secs(60);

/// Why one server did not answer.
#[derive(Debug, thiserror::Error)]
enum ExchangeError {
    #[error("{0}")]
    Net(#[from] NetError),
    #[error("timed out")]
    Timeout,
    #[error("no answer")]
    NoAnswer,
    #[error("an answer to another question")]
    WrongAnswer,
    #[error("refused")]
    Refused,
}

#[derive(Debug, Default)]
struct Counters {
    failures: AtomicU64,
    answer_times: Histogram,
}

/// The upstream servers, as the Resolver's [`Forwarder`].
pub struct Upstream {
    failover: Arc<Failover>,
    /// With `upstream.dnssec = "validate"`: checks answers from the
    /// failover, and asks it for the DNSKEY and DS records it needs.
    validator: Option<DnssecDnsHandle<FailoverHandle>>,
}

/// The servers, asked in failover order.
struct Failover {
    servers: Vec<Server>,
    timeout: Duration,
    /// Index of the server asked first: the one that answered last.
    preferred: AtomicUsize,
    /// While another server is preferred: when the first one is tried again,
    /// in milliseconds since `started`.
    retry_first_at: AtomicU64,
    started: Instant,
    provider: TokioRuntimeProvider,
}

impl fmt::Debug for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upstream")
            .field("servers", &self.failover.servers)
            .field("preferred", &self.preferred())
            .field("validating", &self.validator.is_some())
            .finish_non_exhaustive()
    }
}

impl Upstream {
    /// The configured servers, with TLS checked against the Mozilla roots
    /// (compiled in, so the binary needs no CA bundle).
    #[must_use]
    pub fn new(settings: &config::Upstream) -> Upstream {
        Upstream::with_roots(settings, crate::tls::public_roots())
    }

    /// The same, trusting `roots` (tests trust their own certificate).
    #[must_use]
    pub fn with_roots(settings: &config::Upstream, roots: rustls::RootCertStore) -> Upstream {
        Upstream::with_anchors(settings, roots, TrustAnchors::default())
    }

    /// The same, validating DNSSEC (if configured) from `anchors` instead of
    /// the root zone's keys (tests sign their own zone).
    #[must_use]
    pub fn with_anchors(
        settings: &config::Upstream,
        roots: rustls::RootCertStore,
        anchors: TrustAnchors,
    ) -> Upstream {
        let failover = Arc::new(Failover::new(settings, roots));
        let validator = (settings.dnssec == config::Dnssec::Validate).then(|| {
            DnssecDnsHandle::with_trust_anchor(
                FailoverHandle(Arc::clone(&failover)),
                Arc::new(anchors),
            )
        });
        Upstream {
            failover,
            validator,
        }
    }

    /// The index of the server asked first.
    #[must_use]
    pub fn preferred(&self) -> usize {
        self.failover.preferred()
    }

    /// What each server did, in config order.
    #[must_use]
    pub fn stats(&self) -> Vec<ServerMetrics> {
        self.failover.stats()
    }
}

impl Failover {
    fn new(settings: &config::Upstream, roots: rustls::RootCertStore) -> Failover {
        let tls = Arc::new(crate::tls::client_config(roots));
        Failover {
            servers: settings
                .servers
                .iter()
                .map(|server| Server::new(server, &tls))
                .collect(),
            timeout: Duration::from_millis(settings.timeout_ms.into()),
            preferred: AtomicUsize::new(0),
            retry_first_at: AtomicU64::new(0),
            started: Instant::now(),
            provider: TokioRuntimeProvider::new(),
        }
    }

    fn preferred(&self) -> usize {
        self.preferred.load(Ordering::Relaxed)
    }

    fn stats(&self) -> Vec<ServerMetrics> {
        let preferred = self.preferred();
        self.servers
            .iter()
            .enumerate()
            .map(|(index, server)| ServerMetrics {
                name: server.name.clone(),
                preferred: index == preferred,
                failures: server.counters.failures.load(Ordering::Relaxed),
                answer_times: server.counters.answer_times.snapshot(),
            })
            .collect()
    }

    /// The upstream servers, in failover order.
    async fn forward(&self, query: &Message) -> Result<Message, ForwardError> {
        let count = self.servers.len();
        let preferred = self.preferred().min(count.saturating_sub(1));
        // Usually from the preferred server on. Once a minute after a
        // failover: the first server, then straight back to the preferred
        // one, not through the servers in between, which failed before.
        let order: Vec<usize> = if preferred != 0 && self.claim_retry() {
            [0, preferred]
                .into_iter()
                .chain((1..count).filter(|&index| index != preferred))
                .collect()
        } else {
            (0..count).map(|i| (preferred + i) % count).collect()
        };
        for index in order {
            let Some(server) = self.servers.get(index) else {
                continue;
            };
            let started = Instant::now();
            match self.ask(server, query).await {
                Ok(answer) => {
                    server.counters.answer_times.record(started.elapsed());
                    if index != preferred {
                        self.prefer(index);
                    }
                    return Ok(answer);
                }
                Err(error) => {
                    server.counters.failures.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(server = %server.name, %error, "upstream server failed");
                }
            }
        }
        Err(ForwardError::NoAnswer)
    }

    /// One server, within the timeout; REFUSED is a failure (misconfigured
    /// or rate limiting: the next server may answer).
    async fn ask(&self, server: &Server, query: &Message) -> Result<Message, ExchangeError> {
        answered(
            self.timeout,
            server.exchange(query, self.timeout, &self.provider),
        )
        .await
    }

    fn prefer(&self, index: usize) {
        self.preferred.store(index, Ordering::Relaxed);
        if index != 0 {
            self.retry_first_at.store(
                self.millis_since_start() + millis(RETRY_FIRST_EVERY),
                Ordering::Relaxed,
            );
        }
    }

    /// True for one query a minute while another server than the first is
    /// preferred: that query tries the first server again.
    fn claim_retry(&self) -> bool {
        let now = self.millis_since_start();
        let due = self.retry_first_at.load(Ordering::Relaxed);
        now >= due
            && self
                .retry_first_at
                .compare_exchange(
                    due,
                    now + millis(RETRY_FIRST_EVERY),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
    }

    fn millis_since_start(&self) -> u64 {
        millis(self.started.elapsed())
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

impl Forwarder for Upstream {
    async fn forward(&self, query: Message, target: Target) -> Result<Message, ForwardError> {
        match target {
            // A client that set CD checks signatures itself: it gets the
            // answer unchecked, as the upstream servers give it.
            Target::Upstream => match &self.validator {
                Some(validator) if !query.metadata.checking_disabled => {
                    // The answer and the DNSKEY and DS lookups behind it run
                    // one after another: together no longer than one full
                    // failover may take, so a permit is not held for long
                    // after the client has given up.
                    let deadline = self.failover.timeout.saturating_mul(
                        u32::try_from(self.failover.servers.len()).unwrap_or(u32::MAX),
                    );
                    tokio::time::timeout(deadline, validated(validator, query))
                        .await
                        .unwrap_or(Err(ForwardError::NoAnswer))
                }
                _ => self.failover.forward(&query).await,
            },
            // A forwarded zone's server alone: no failover, no preference, and
            // not counted, as the Metrics list the configured servers. Not
            // validated: LAN zones are unsigned.
            Target::Zone(address) => {
                let failover = &self.failover;
                let exchange =
                    plain_exchange(address, &query, failover.timeout, &failover.provider);
                answered(failover.timeout, exchange).await.map_err(|error| {
                    tracing::debug!(%address, %error, "forwarded zone server failed");
                    ForwardError::NoAnswer
                })
            }
        }
    }
}

tokio::task_local! {
    /// While validating: set when a lookup the validator made got no answer.
    static LOOKUP_FAILED: Cell<bool>;
}

/// The failover as a hickory [`DnsHandle`], for the DNSSEC validator.
#[derive(Clone)]
struct FailoverHandle(Arc<Failover>);

impl DnsHandle for FailoverHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, NetError>> + Send>>;
    type Runtime = TokioRuntimeProvider;

    fn send(&self, request: DnsRequest) -> Self::Response {
        let failover = Arc::clone(&self.0);
        let (mut query, _) = request.into_parts();
        // Checking disabled: the upstream server hands over what it has,
        // signatures included, and zinkhole checks it (RFC 6840, section
        // 5.9). Otherwise a validating upstream answers bogus data with a
        // plain SERVFAIL, and nothing is learned.
        query.metadata.checking_disabled = true;
        // Signatures make answers larger: room for them over UDP.
        if let Some(edns) = query.edns.as_mut() {
            edns.set_max_payload(crate::answer::EDNS_PAYLOAD);
        }
        Box::pin(futures_util::stream::once(async move {
            let answer = failover.forward(&query).await.map_err(|error| {
                // Polled in the validating task, so the flag is in scope.
                let _ = LOOKUP_FAILED.try_with(|failed| failed.set(true));
                NetError::from(error.to_string())
            })?;
            DnsResponse::from_message(answer).map_err(NetError::from)
        }))
    }
}

/// The answer to `query`, checked: SERVFAIL-worthy if its signatures do not
/// hold; with AD set if every record in it is proven secure.
async fn validated(
    validator: &DnssecDnsHandle<FailoverHandle>,
    query: Message,
) -> Result<Message, ForwardError> {
    let request = DnsRequest::new(query, DnsRequestOptions::default());
    let (result, lookup_failed) = LOOKUP_FAILED
        .scope(Cell::new(false), async {
            let result = validator.send(request).first_answer().await;
            (result, LOOKUP_FAILED.with(Cell::get))
        })
        .await;
    let verdict = verdict(result);
    // hickory calls a chain whose DS or DNSKEY lookup got no answer bogus:
    // that is an outage, not a forgery, and serve-stale should help.
    if lookup_failed && verdict == Err(ForwardError::Bogus) {
        tracing::debug!("a DNSSEC lookup got no answer: no answer, not bogus");
        return Err(ForwardError::NoAnswer);
    }
    verdict
}

/// What the validator's `result` means for the client.
fn verdict(result: Result<DnsResponse, NetError>) -> Result<Message, ForwardError> {
    match result {
        Ok(response) => judged(response.into_message()),
        // A negative answer whose denial of existence is not proven secure:
        // bogus, or (as in an unsigned zone) simply not signed. A SERVFAIL
        // from upstream proves nothing either way: it stays a SERVFAIL, as
        // without validation.
        Err(NetError::Dns(DnsError::Nsec {
            response, proof, ..
        })) => {
            if proof == Proof::Bogus && response.metadata.response_code != ResponseCode::ServFail {
                return Err(ForwardError::Bogus);
            }
            let mut answer = response.into_message();
            answer.metadata.authentic_data = false;
            Ok(answer)
        }
        Err(NetError::Dns(DnsError::DnssecBogus)) => Err(ForwardError::Bogus),
        Err(error) => {
            tracing::debug!(%error, "no validated answer");
            Err(ForwardError::NoAnswer)
        }
    }
}

/// `answer` as the validator marked it: bogus if any of its records is,
/// authenticated (AD) if all of them are secure.
fn judged(mut answer: Message) -> Result<Message, ForwardError> {
    let signed = || {
        answer
            .answers
            .iter()
            .chain(&answer.authorities)
            .filter(|record| record.record_type() != RecordType::RRSIG)
    };
    if signed().any(|record| record.proof == Proof::Bogus) {
        return Err(ForwardError::Bogus);
    }
    let secure = signed().next().is_some() && signed().all(|record| record.proof == Proof::Secure);
    answer.metadata.authentic_data = secure;
    Ok(answer)
}

/// The answer `exchange` gives within `timeout`. REFUSED is no answer: the
/// server will not resolve for us, another one may.
async fn answered(
    timeout: Duration,
    exchange: impl Future<Output = Result<Message, ExchangeError>>,
) -> Result<Message, ExchangeError> {
    let answer = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| ExchangeError::Timeout)??;
    if answer.metadata.response_code == ResponseCode::Refused {
        return Err(ExchangeError::Refused);
    }
    Ok(answer)
}

struct Server {
    name: String,
    transport: Transport,
    counters: Counters,
}

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

enum Transport {
    Plain(SocketAddr),
    Encrypted(Encrypted),
}

/// Which protocol an encrypted connection speaks.
enum Protocol {
    /// DNS over HTTPS, at this path.
    Https { path: Arc<str> },
    /// DNS over QUIC (RFC 9250).
    Quic,
}

/// A DNS-over-HTTPS or DNS-over-QUIC server.
struct Encrypted {
    protocol: Protocol,
    address: SocketAddr,
    tls_name: Arc<str>,
    tls: Arc<ClientConfig>,
    /// The connection queries share, with its generation; None until the
    /// first query, and after a failure.
    connection: std::sync::Mutex<Option<(u64, DnsExchange<TokioRuntimeProvider>)>>,
    /// Held while a connection is opened, so queries share one attempt.
    opening: tokio::sync::Mutex<()>,
    /// Numbers the connections, so a failure closes only the one it hit.
    generations: AtomicU64,
}

impl Server {
    fn new(server: &UpstreamServer, tls: &Arc<ClientConfig>) -> Server {
        let (name, transport) = match server {
            UpstreamServer::Plain(address) => (address.0.to_string(), Transport::Plain(address.0)),
            UpstreamServer::Https(server) => {
                let path = server.url.path().into();
                Server::encrypted(server, Protocol::Https { path }, tls)
            }
            UpstreamServer::Quic(server) => Server::encrypted(server, Protocol::Quic, tls),
        };
        Server {
            name,
            transport,
            counters: Counters::default(),
        }
    }

    fn encrypted(
        server: &config::EncryptedServer,
        protocol: Protocol,
        tls: &Arc<ClientConfig>,
    ) -> (String, Transport) {
        let name = format!("{} ({})", server.url, server.address.ip());
        let transport = Transport::Encrypted(Encrypted {
            protocol,
            address: server.address,
            tls_name: server.tls_name.as_str().into(),
            tls: Arc::clone(tls),
            connection: std::sync::Mutex::new(None),
            opening: tokio::sync::Mutex::new(()),
            generations: AtomicU64::new(0),
        });
        (name, transport)
    }

    async fn exchange(
        &self,
        query: &Message,
        timeout: Duration,
        provider: &TokioRuntimeProvider,
    ) -> Result<Message, ExchangeError> {
        match &self.transport {
            Transport::Plain(address) => plain_exchange(*address, query, timeout, provider).await,
            Transport::Encrypted(encrypted) => encrypted.exchange(query, timeout, provider).await,
        }
    }
}

impl Encrypted {
    async fn exchange(
        &self,
        query: &Message,
        timeout: Duration,
        provider: &TokioRuntimeProvider,
    ) -> Result<Message, ExchangeError> {
        for attempt in 0..2 {
            let (generation, connection, reused) = self.connection(timeout, provider).await?;
            // Until the answer is in, the connection is suspect: an error, or
            // the server's timeout passing while the query waits (a stalled
            // connection returns no error, it just never answers), and it is
            // not used again.
            let mut unanswered = Unanswered {
                encrypted: self,
                generation,
                answered: false,
            };
            match send(&connection, query).await {
                Ok(answer) => {
                    unanswered.answered = true;
                    return checked(query, answer);
                }
                Err(error) => {
                    drop(unanswered);
                    // Most likely the server closed an idle connection: once
                    // more on a new one.
                    if !(reused && attempt == 0) {
                        return Err(error);
                    }
                }
            }
        }
        Err(ExchangeError::NoAnswer)
    }

    /// The shared connection of `generation` is not used again (unless
    /// another query already replaced it).
    fn forget(&self, generation: u64) {
        let mut shared = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if shared
            .as_ref()
            .is_some_and(|(current, _)| *current == generation)
        {
            *shared = None;
        }
    }

    /// The shared connection, if there is one.
    fn shared(&self) -> Option<(u64, DnsExchange<TokioRuntimeProvider>)> {
        self.connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// The shared connection and its generation, opened if there is none;
    /// true if it existed already.
    async fn connection(
        &self,
        timeout: Duration,
        provider: &TokioRuntimeProvider,
    ) -> Result<(u64, DnsExchange<TokioRuntimeProvider>, bool), ExchangeError> {
        if let Some((generation, connection)) = self.shared() {
            return Ok((generation, connection, true));
        }
        let _opening = self.opening.lock().await;
        // Another query may have opened one while this one waited.
        if let Some((generation, connection)) = self.shared() {
            return Ok((generation, connection, true));
        }
        let connection = match &self.protocol {
            Protocol::Https { path } => {
                let mut builder =
                    HttpsClientStream::builder(Arc::clone(&self.tls), provider.clone());
                builder.request_timeout(timeout);
                builder
                    .exchange(self.address, Arc::clone(&self.tls_name), Arc::clone(path))
                    .await?
            }
            Protocol::Quic => {
                // hickory offers the "doq" ALPN when the config has none.
                let stream = QuicClientStream::builder()
                    .crypto_config((*self.tls).clone())
                    .request_timeout(timeout)
                    .build(self.address, Arc::clone(&self.tls_name))
                    .await?;
                let (connection, background) = DnsExchange::from_stream(stream);
                tokio::spawn(background);
                connection
            }
        };
        let generation = self.generations.fetch_add(1, Ordering::Relaxed);
        *self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((generation, connection.clone()));
        Ok((generation, connection, false))
    }
}

/// Forgets the shared connection when dropped before the answer came: on an
/// error, and also when the exchange is abandoned at its timeout.
struct Unanswered<'a> {
    encrypted: &'a Encrypted,
    generation: u64,
    answered: bool,
}

impl Drop for Unanswered<'_> {
    fn drop(&mut self) {
        if !self.answered {
            self.encrypted.forget(self.generation);
        }
    }
}

/// Plain DNS: UDP, then TCP if the answer was truncated.
async fn plain_exchange(
    address: SocketAddr,
    query: &Message,
    timeout: Duration,
    provider: &TokioRuntimeProvider,
) -> Result<Message, ExchangeError> {
    let udp = UdpClientStream::builder(address, provider.clone())
        .with_timeout(Some(timeout))
        .exchange();
    let answer = checked(query, send(&udp, query).await?)?;
    if !answer.metadata.truncation {
        return Ok(answer);
    }
    let tcp = TcpClientStream::exchange(address, None, timeout, Some(1), provider.clone()).await?;
    checked(query, send(&tcp, query).await?)
}

/// Sends `query` as it is: its EDNS was already set by the Resolver.
async fn send(
    exchange: &DnsExchange<TokioRuntimeProvider>,
    query: &Message,
) -> Result<Message, ExchangeError> {
    let mut options = DnsRequestOptions::default();
    options.use_edns = query.edns.is_some();
    options.recursion_desired = query.metadata.recursion_desired;
    if let Some(edns) = &query.edns {
        options.edns_payload_len = edns.max_payload();
        options.edns_set_dnssec_ok = edns.flags().dnssec_ok;
    }
    let mut responses = exchange.send(DnsRequest::new(query.clone(), options));
    let response = responses.next().await.ok_or(ExchangeError::NoAnswer)??;
    Ok(response.into_message())
}

/// `answer` if it is a response to exactly `query`'s question.
fn checked(query: &Message, answer: Message) -> Result<Message, ExchangeError> {
    let same_question = answer.queries.len() == query.queries.len()
        && answer.queries.iter().zip(&query.queries).all(|(a, q)| {
            a.name() == q.name()
                && a.query_type() == q.query_type()
                && a.query_class() == q.query_class()
        });
    if answer.metadata.message_type != MessageType::Response || !same_question {
        return Err(ExchangeError::WrongAnswer);
    }
    Ok(answer)
}

#[cfg(test)]
mod tests;
