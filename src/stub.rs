//! Servers for tests, on loopback ports: plain DNS (UDP and TCP) with
//! scripted behaviour, DNS over HTTPS, and an HTTP(S) server for lists. TLS
//! uses a certificate made at test time and trusted only by the test.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;

/// What a stub does with each query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Behaviour {
    /// One A record, 1.2.3.4, TTL 300.
    Answer,
    /// Never answers.
    Silent,
    Refuse,
    /// SERVFAIL, as when the server cannot reach the authoritative ones.
    ServFail,
    /// DNS over HTTPS: HTTP 503 instead of an answer (plain DNS: silence).
    HttpError,
    /// First an answer with the wrong ID, then the right one.
    SpoofFirst,
    /// Over UDP an empty answer with TC set; over TCP the whole answer.
    Truncate,
    /// An answer to another question.
    WrongQuestion,
}

#[derive(Debug)]
struct State {
    behaviour: Mutex<Behaviour>,
    received: AtomicUsize,
    connections: AtomicUsize,
    /// If not empty, queries are answered from these records instead.
    zone: Vec<Record>,
    /// With a zone: queries of this type get no answer.
    silent_for: Option<RecordType>,
    /// With a zone: the authority records (SOA, NSEC and their signatures)
    /// sent with NXDOMAIN for a name it does not hold; without them such a
    /// name gets an empty answer.
    denial: Vec<Record>,
    /// Plain DNS: how long each answer takes.
    delay: Mutex<std::time::Duration>,
}

impl State {
    fn new(behaviour: Behaviour) -> Arc<State> {
        State::with_zone(behaviour, Vec::new(), None, Vec::new())
    }

    fn with_zone(
        behaviour: Behaviour,
        zone: Vec<Record>,
        silent_for: Option<RecordType>,
        denial: Vec<Record>,
    ) -> Arc<State> {
        Arc::new(State {
            behaviour: Mutex::new(behaviour),
            received: AtomicUsize::new(0),
            connections: AtomicUsize::new(0),
            zone,
            silent_for,
            denial,
            delay: Mutex::new(std::time::Duration::ZERO),
        })
    }

    fn behaviour(&self) -> Behaviour {
        *self.behaviour.lock().unwrap()
    }

    /// The answer to `query`: from the zone, if there is one, else as the
    /// behaviour says.
    fn respond(&self, query: &Message, over_tcp: bool) -> Option<Message> {
        if self.zone.is_empty() {
            return answer(query, self.behaviour(), over_tcp);
        }
        let mut response = answer(query, Behaviour::Refuse, over_tcp)?;
        response.metadata.response_code = ResponseCode::NoError;
        let question = query.queries.first()?;
        if Some(question.query_type()) == self.silent_for {
            return None;
        }
        response.answers = self
            .zone
            .iter()
            .filter(|record| {
                let kind = match &record.data {
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => rrsig.input().type_covered,
                    _ => record.record_type(),
                };
                record.name.eq_case(question.name()) && kind == question.query_type()
            })
            .cloned()
            .collect();
        let known = self
            .zone
            .iter()
            .any(|record| record.name.eq_case(question.name()));
        if !known && !self.denial.is_empty() {
            response.metadata.response_code = ResponseCode::NXDomain;
            response.authorities.clone_from(&self.denial);
        }
        Some(response)
    }
}

/// The answer `behaviour` gives to `query`; None for silence.
fn answer(query: &Message, behaviour: Behaviour, over_tcp: bool) -> Option<Message> {
    let mut answer = Message::response(query.metadata.id, query.metadata.op_code);
    answer.metadata.message_type = MessageType::Response;
    answer.metadata.recursion_desired = query.metadata.recursion_desired;
    answer.metadata.recursion_available = true;
    answer.queries.clone_from(&query.queries);
    let owner = query.queries.first()?.name().clone();
    let a = |name: Name| Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(1, 2, 3, 4))));
    match behaviour {
        Behaviour::Answer | Behaviour::SpoofFirst => answer.answers.push(a(owner)),
        Behaviour::Silent | Behaviour::HttpError => return None,
        Behaviour::Refuse => answer.metadata.response_code = ResponseCode::Refused,
        Behaviour::ServFail => answer.metadata.response_code = ResponseCode::ServFail,
        Behaviour::Truncate if over_tcp => answer.answers.push(a(owner)),
        Behaviour::Truncate => answer.metadata.truncation = true,
        Behaviour::WrongQuestion => {
            let other = Name::from_str("other.example.").ok()?;
            answer.queries[0].set_name(other.clone());
            answer.answers.push(a(other));
        }
    }
    Some(answer)
}

/// A plain DNS server on one loopback port, UDP and TCP.
#[derive(Debug)]
pub(crate) struct PlainStub {
    pub(crate) address: SocketAddr,
    state: Arc<State>,
    tasks: Vec<JoinHandle<()>>,
}

impl PlainStub {
    pub(crate) async fn start(behaviour: Behaviour) -> PlainStub {
        PlainStub::start_with(State::new(behaviour)).await
    }

    /// A server that answers from `zone` (records and their signatures).
    pub(crate) async fn serving(zone: Vec<Record>) -> PlainStub {
        PlainStub::start_with(State::with_zone(Behaviour::Answer, zone, None, Vec::new())).await
    }

    /// A server for `zone` that denies names it does not hold with NXDOMAIN
    /// and the `denial` authority records.
    pub(crate) async fn serving_with_denial(zone: Vec<Record>, denial: Vec<Record>) -> PlainStub {
        PlainStub::start_with(State::with_zone(Behaviour::Answer, zone, None, denial)).await
    }

    /// The same, but never answering queries of type `silent`.
    pub(crate) async fn serving_but_silent_for(zone: Vec<Record>, silent: RecordType) -> PlainStub {
        PlainStub::start_with(State::with_zone(
            Behaviour::Answer,
            zone,
            Some(silent),
            Vec::new(),
        ))
        .await
    }

    async fn start_with(state: Arc<State>) -> PlainStub {
        // UDP first, then TCP on the same port; try again if TCP's is taken.
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
                break (udp, tcp);
            }
        };
        let address = udp.local_addr().unwrap();
        let tasks = vec![
            tokio::spawn(serve_udp(udp, Arc::clone(&state))),
            tokio::spawn(serve_tcp(tcp, Arc::clone(&state))),
        ];
        PlainStub {
            address,
            state,
            tasks,
        }
    }

    pub(crate) fn received(&self) -> usize {
        self.state.received.load(Ordering::SeqCst)
    }

    /// Every answer from now on takes `delay`.
    pub(crate) fn delay(&self, delay: std::time::Duration) {
        *self.state.delay.lock().unwrap() = delay;
    }

    pub(crate) fn set(&self, behaviour: Behaviour) {
        *self.state.behaviour.lock().unwrap() = behaviour;
    }
}

impl Drop for PlainStub {
    fn drop(&mut self) {
        self.tasks.iter().for_each(JoinHandle::abort);
    }
}

async fn serve_udp(socket: UdpSocket, state: Arc<State>) {
    let mut buffer = [0u8; 4096];
    while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
        state.received.fetch_add(1, Ordering::SeqCst);
        let Ok(query) = Message::from_vec(&buffer[..len]) else {
            continue;
        };
        let behaviour = state.behaviour();
        let Some(response) = state.respond(&query, false) else {
            continue;
        };
        let delay = *state.delay.lock().unwrap();
        tokio::time::sleep(delay).await;
        if behaviour == Behaviour::SpoofFirst {
            let mut spoofed = response.clone();
            spoofed.metadata.id = spoofed.metadata.id.wrapping_add(1);
            spoofed.answers[0].data = RData::A(A(Ipv4Addr::new(6, 6, 6, 6)));
            let _ = socket.send_to(&spoofed.to_vec().unwrap(), from).await;
        }
        let _ = socket.send_to(&response.to_vec().unwrap(), from).await;
    }
}

async fn serve_tcp(listener: TcpListener, state: Arc<State>) {
    while let Ok((mut stream, _)) = listener.accept().await {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok(len) = stream.read_u16().await {
                let mut query = vec![0u8; len.into()];
                if stream.read_exact(&mut query).await.is_err() {
                    return;
                }
                state.received.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = Message::from_vec(&query) else {
                    return;
                };
                let Some(response) = state.respond(&query, true) else {
                    continue;
                };
                let bytes = response.to_vec().unwrap();
                let _ = stream.write_u16(u16::try_from(bytes.len()).unwrap()).await;
                let _ = stream.write_all(&bytes).await;
            }
        });
    }
}

/// A TLS acceptor with a fresh certificate for `name`, offering `alpn`, and
/// the roots that trust it.
fn tls(name: &str, alpn: &[u8]) -> (tokio_rustls::TlsAcceptor, rustls::RootCertStore) {
    let (certificate, key, roots) = certificate(name);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    (tokio_rustls::TlsAcceptor::from(Arc::new(config)), roots)
}

/// A fresh self-signed certificate for `name`, its key, and the roots that
/// trust it.
fn certificate(
    name: &str,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
    rustls::RootCertStore,
) {
    let certified = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.signing_key.serialize_der().into());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    (certificate, key, roots)
}

/// A DNS-over-HTTPS server for `doh.test` on a loopback port.
#[derive(Debug)]
pub(crate) struct DohStub {
    pub(crate) address: SocketAddr,
    /// Trusts this stub's certificate, and nothing else.
    pub(crate) roots: rustls::RootCertStore,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl DohStub {
    /// With `one_answer_per_connection`, every connection closes after one
    /// answer, as an idle connection a server closed does.
    pub(crate) async fn start(behaviour: Behaviour, one_answer_per_connection: bool) -> DohStub {
        let (acceptor, roots) = tls("doh.test", b"h2");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = State::new(behaviour);
        let task = tokio::spawn(serve_doh(
            listener,
            acceptor,
            Arc::clone(&state),
            one_answer_per_connection,
        ));
        DohStub {
            address,
            roots,
            state,
            task,
        }
    }

    pub(crate) fn received(&self) -> usize {
        self.state.received.load(Ordering::SeqCst)
    }

    pub(crate) fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// The config line for this server.
    pub(crate) fn config(&self) -> String {
        format!(
            "{{ url = \"https://doh.test:{}/dns-query\", address = \"127.0.0.1\" }}",
            self.address.port()
        )
    }
}

impl Drop for DohStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_doh(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    state: Arc<State>,
    one_answer: bool,
) {
    while let Ok((tcp, _)) = listener.accept().await {
        state.connections.fetch_add(1, Ordering::SeqCst);
        let (acceptor, state) = (acceptor.clone(), Arc::clone(&state));
        tokio::spawn(async move {
            let Ok(tls) = acceptor.accept(tcp).await else {
                return;
            };
            let Ok(mut connection) = h2::server::handshake(tls).await else {
                return;
            };
            // Requests left unanswered stay open, as on a stalled server.
            let mut unanswered = Vec::new();
            while let Some(Ok((request, mut respond))) = connection.accept().await {
                let mut body = request.into_body();
                let mut query = Vec::new();
                while let Some(Ok(chunk)) = body.data().await {
                    let _ = body.flow_control().release_capacity(chunk.len());
                    query.extend_from_slice(&chunk);
                }
                state.received.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = Message::from_vec(&query) else {
                    continue;
                };
                if state.behaviour() == Behaviour::HttpError {
                    let head = http::Response::builder().status(503).body(()).unwrap();
                    let _ = respond.send_response(head, true);
                    continue;
                }
                let Some(response) = state.respond(&query, true) else {
                    unanswered.push(respond);
                    continue;
                };
                let head = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/dns-message")
                    .body(())
                    .unwrap();
                if let Ok(mut stream) = respond.send_response(head, false) {
                    let _ = stream.send_data(Bytes::from(response.to_vec().unwrap()), true);
                }
                if one_answer {
                    // Keep driving the connection until the answer is out,
                    // then drop it without a GOAWAY, as a server that went
                    // away does.
                    let flush = async { while connection.accept().await.is_some() {} };
                    let _ = tokio::time::timeout(std::time::Duration::from_millis(50), flush).await;
                    return;
                }
            }
        });
    }
}

/// What the HTTP stub answers for a path.
#[derive(Debug, Clone)]
pub(crate) enum Reply {
    Body(String),
    /// The body, gzip-compressed, with `Content-Encoding: gzip`.
    Gzip(String),
    Status(u16),
    /// 302 to this URL.
    Redirect(String),
    /// Headers and one line of the body, then nothing, forever.
    Stall,
}

type Routes = Arc<Mutex<Vec<(String, Reply)>>>;

/// An HTTP server for lists, on a loopback port; with TLS, for `localhost`.
#[derive(Debug)]
pub(crate) struct HttpStub {
    pub(crate) address: SocketAddr,
    /// With TLS: trusts this stub's certificate, and nothing else.
    pub(crate) roots: Option<rustls::RootCertStore>,
    routes: Routes,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl HttpStub {
    pub(crate) async fn start(with_tls: bool) -> HttpStub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (acceptor, roots) = if with_tls {
            let (acceptor, roots) = tls("localhost", b"http/1.1");
            (Some(acceptor), Some(roots))
        } else {
            (None, None)
        };
        let routes = Routes::default();
        let requests = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve_http(
            listener,
            acceptor,
            Arc::clone(&routes),
            Arc::clone(&requests),
        ));
        HttpStub {
            address,
            roots,
            routes,
            requests,
            task,
        }
    }

    /// Answers `path` with `reply` from now on.
    pub(crate) fn route(&self, path: &str, reply: Reply) -> &Self {
        let mut routes = self.routes.lock().unwrap();
        routes.retain(|(p, _)| p != path);
        routes.push((path.to_owned(), reply));
        self
    }

    pub(crate) fn url(&self, path: &str) -> String {
        match self.roots {
            Some(_) => format!("https://localhost:{}{path}", self.address.port()),
            None => format!("http://{}{path}", self.address),
        }
    }

    pub(crate) fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for HttpStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_http(
    listener: TcpListener,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    routes: Routes,
    requests: Arc<AtomicUsize>,
) {
    while let Ok((tcp, _)) = listener.accept().await {
        let (acceptor, routes, requests) =
            (acceptor.clone(), Arc::clone(&routes), Arc::clone(&requests));
        tokio::spawn(async move {
            match acceptor {
                Some(acceptor) => {
                    if let Ok(stream) = acceptor.accept(tcp).await {
                        respond(stream, &routes, &requests).await;
                    }
                }
                None => respond(tcp, &routes, &requests).await,
            }
        });
    }
}

/// Answers one request, then closes the connection.
async fn respond<S>(stream: S, routes: &Mutex<Vec<(String, Reply)>>, requests: &AtomicUsize)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncBufReadExt;
    let mut stream = tokio::io::BufReader::new(stream);
    let mut request_line = String::new();
    if stream.read_line(&mut request_line).await.is_err() {
        return;
    }
    loop {
        let mut header = String::new();
        match stream.read_line(&mut header).await {
            Ok(0) | Err(_) => return,
            Ok(_) if header == "\r\n" => break,
            Ok(_) => {}
        }
    }
    requests.fetch_add(1, Ordering::SeqCst);
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    let reply = routes
        .lock()
        .unwrap()
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, reply)| reply.clone());
    let (head, body) = match reply.unwrap_or(Reply::Status(404)) {
        Reply::Body(text) => (
            format!("200 OK\r\nContent-Length: {}", text.len()),
            text.into_bytes(),
        ),
        Reply::Gzip(text) => {
            use std::io::Write as _;
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(text.as_bytes()).unwrap();
            let body = encoder.finish().unwrap();
            (
                format!(
                    "200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}",
                    body.len()
                ),
                body,
            )
        }
        Reply::Status(code) => (format!("{code} Status\r\nContent-Length: 0"), Vec::new()),
        Reply::Redirect(to) => (
            format!("302 Found\r\nLocation: {to}\r\nContent-Length: 0"),
            Vec::new(),
        ),
        Reply::Stall => {
            let start = "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\nads.example\n";
            let _ = stream.write_all(start.as_bytes()).await;
            let _ = stream.flush().await;
            std::future::pending::<()>().await;
            return;
        }
    };
    let head = format!("HTTP/1.1 {head}\r\nConnection: close\r\n\r\n");
    let _ = stream.write_all(head.as_bytes()).await;
    let _ = stream.write_all(&body).await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

/// A DNS-over-QUIC server for `doq.test` on a loopback port (hickory's
/// server side), answering each query on its own stream.
#[derive(Debug)]
pub(crate) struct DoqStub {
    pub(crate) address: SocketAddr,
    /// Trusts this stub's certificate, and nothing else.
    pub(crate) roots: rustls::RootCertStore,
    state: Arc<State>,
    task: JoinHandle<()>,
}

impl DoqStub {
    /// With `one_answer_per_connection`, every connection closes after one
    /// answer, as an idle connection a server closed does.
    pub(crate) async fn start(behaviour: Behaviour, one_answer_per_connection: bool) -> DoqStub {
        let (certificate, key, roots) = certificate("doq.test");
        let provider = rustls::crypto::ring::default_provider();
        let certified =
            rustls::sign::CertifiedKey::from_der(vec![certificate], key, &provider).unwrap();
        let resolver = Arc::new(rustls::sign::SingleCertAndKey::from(certified));
        let mut server =
            hickory_net::quic::QuicServer::new("127.0.0.1:0".parse().unwrap(), resolver)
                .await
                .unwrap();
        let address = server.local_addr().unwrap();
        let state = State::new(behaviour);
        let shared = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok(Some((mut streams, _))) = server.next().await {
                shared.connections.fetch_add(1, Ordering::SeqCst);
                let state = Arc::clone(&shared);
                tokio::spawn(async move {
                    while let Some(Ok(mut stream)) = streams.next().await {
                        let Ok(bytes) = stream.receive_bytes().await else {
                            continue;
                        };
                        state.received.fetch_add(1, Ordering::SeqCst);
                        let Ok(query) = Message::from_vec(&bytes) else {
                            continue;
                        };
                        if let Some(response) = state.respond(&query, true) {
                            let _ = stream.send(response).await;
                            let _ = stream.finish().await;
                        }
                        if one_answer_per_connection {
                            // Dropping the last handle closes the connection.
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            return;
                        }
                    }
                });
            }
        });
        DoqStub {
            address,
            roots,
            state,
            task,
        }
    }

    pub(crate) fn received(&self) -> usize {
        self.state.received.load(Ordering::SeqCst)
    }

    pub(crate) fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// The config line for this server.
    pub(crate) fn config(&self) -> String {
        format!(
            "{{ url = \"quic://doq.test:{}\", address = \"127.0.0.1\" }}",
            self.address.port()
        )
    }
}

impl Drop for DoqStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}
