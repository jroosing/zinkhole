//! The listeners over loopback sockets, with a stub upstream server behind
//! the Resolver.

use std::net::{Ipv4Addr, UdpSocket as StdUdpSocket};
use std::str::FromStr;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use tokio::task::JoinHandle;

use super::*;
use crate::config::Config;
use crate::resolver::Outcome;
use crate::serve;
use crate::stub::{Behaviour, PlainStub};
use crate::upstream::Upstream;

struct Running {
    address: SocketAddr,
    resolver: Arc<Resolver<Upstream>>,
    shutdown: CancellationToken,
    task: JoinHandle<io::Result<()>>,
    _upstream: PlainStub,
}

impl Running {
    async fn stop(self) {
        self.shutdown.cancel();
        let stopped = tokio::time::timeout(Duration::from_secs(2), self.task).await;
        assert!(matches!(stopped, Ok(Ok(Ok(())))), "{stopped:?}");
    }
}

/// A server on `addresses` with a local record `nas.lan` and an upstream
/// stub that answers 1.2.3.4; `toml` adds to the config.
async fn start_on(addresses: &[SocketAddr], toml: &str) -> Running {
    let upstream = PlainStub::start(Behaviour::Answer).await;
    let text = format!(
        "{toml}\n[upstream]\nservers = [\"{}\"]\ntimeout_ms = 500\n[local.records]\n\"nas.lan\" = \"192.168.1.10\"\n",
        upstream.address
    );
    let config = Config::parse(&text).unwrap_or_else(|e| panic!("{e}"));
    let resolver = Arc::new(serve::resolver(&config, Upstream::new(&config.upstream)));
    let listeners = Listeners::bind(addresses).unwrap();
    let address = listeners.addresses()[0];
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(serve(listeners, Arc::clone(&resolver), shutdown.clone()));
    Running {
        address,
        resolver,
        shutdown,
        task,
        _upstream: upstream,
    }
}

async fn start(toml: &str) -> Running {
    start_on(&[SocketAddr::from((Ipv4Addr::LOCALHOST, 0))], toml).await
}

fn query(name: &str) -> Message {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    query
}

fn first_a(answer: &Message) -> Option<Ipv4Addr> {
    answer.answers.iter().find_map(|record| match record.data {
        RData::A(A(ip)) => Some(ip),
        _ => None,
    })
}

/// The answer over UDP to `bytes`, or None within 300 ms.
async fn udp_exchange(server: SocketAddr, bytes: &[u8]) -> Option<Message> {
    let local: SocketAddr = if server.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    }
    .parse()
    .unwrap();
    let socket = UdpSocket::bind(local).await.unwrap();
    socket.send_to(bytes, server).await.unwrap();
    let mut buffer = vec![0u8; 65535];
    let (len, _) = tokio::time::timeout(Duration::from_millis(300), socket.recv_from(&mut buffer))
        .await
        .ok()?
        .unwrap();
    Some(Message::from_vec(&buffer[..len]).unwrap())
}

async fn udp_ask(server: SocketAddr, name: &str) -> Option<Message> {
    udp_exchange(server, &query(name).to_vec().unwrap()).await
}

async fn tcp_send(stream: &mut TcpStream, query: &Message) {
    let bytes = query.to_vec().unwrap();
    stream
        .write_u16(u16::try_from(bytes.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(&bytes).await.unwrap();
}

async fn tcp_receive(stream: &mut TcpStream) -> Message {
    let len = stream.read_u16().await.unwrap();
    let mut bytes = vec![0u8; len.into()];
    stream.read_exact(&mut bytes).await.unwrap();
    Message::from_vec(&bytes).unwrap()
}

/// True if the server closes `stream` without sending anything.
async fn closed(stream: &mut TcpStream) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

#[tokio::test]
async fn udp_answers_local_and_forwarded_queries() {
    let server = start("").await;
    let local = udp_ask(server.address, "nas.lan.").await.unwrap();
    assert_eq!(first_a(&local), Some(Ipv4Addr::new(192, 168, 1, 10)));
    let forwarded = udp_ask(server.address, "example.com.").await.unwrap();
    assert_eq!(first_a(&forwarded), Some(Ipv4Addr::new(1, 2, 3, 4)));
    server.stop().await;
}

#[tokio::test]
async fn tcp_answers_several_queries_on_one_connection_in_order() {
    let server = start("").await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    let (first, second) = (query("example.com."), query("nas.lan."));
    tcp_send(&mut stream, &first).await;
    tcp_send(&mut stream, &second).await;
    let (a, b) = (
        tcp_receive(&mut stream).await,
        tcp_receive(&mut stream).await,
    );
    assert_eq!(
        (a.metadata.id, first_a(&a)),
        (first.metadata.id, Some(Ipv4Addr::new(1, 2, 3, 4)))
    );
    assert_eq!(
        (b.metadata.id, first_a(&b)),
        (second.metadata.id, Some(Ipv4Addr::new(192, 168, 1, 10)))
    );
    server.stop().await;
}

#[tokio::test]
async fn clients_that_may_not_query_get_nothing_over_udp_and_a_closed_connection_over_tcp() {
    let server = start("[server]\nallow_clients = [\"10.0.0.0/8\"]").await;
    assert!(udp_ask(server.address, "nas.lan.").await.is_none());
    assert_eq!(
        server.resolver.queries().count(Outcome::Refused),
        1,
        "dropped unread, and counted all the same"
    );
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    assert!(closed(&mut stream).await);
    server.stop().await;
}

#[tokio::test]
async fn udp_queries_larger_than_4096_bytes_are_dropped() {
    let server = start("").await;
    let mut bytes = query("nas.lan.").to_vec().unwrap();
    bytes.resize(MAX_QUERY_LEN, 0);
    let answer = udp_exchange(server.address, &bytes).await;
    assert!(
        answer.is_some(),
        "4096 bytes is answered (FORMERR for the trailing bytes is fine)"
    );
    bytes.push(0);
    assert!(udp_exchange(server.address, &bytes).await.is_none());
    server.stop().await;
}

#[tokio::test]
async fn tcp_queries_larger_than_4096_bytes_close_the_connection() {
    let server = start("").await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    stream.write_u16(4097).await.unwrap();
    assert!(closed(&mut stream).await);
    server.stop().await;
}

#[tokio::test]
async fn one_client_holds_at_most_four_tcp_connections() {
    let server = start("").await;
    let mut held = Vec::new();
    for _ in 0..TCP_PER_CLIENT {
        let mut stream = TcpStream::connect(server.address).await.unwrap();
        tcp_send(&mut stream, &query("nas.lan.")).await;
        tcp_receive(&mut stream).await;
        held.push(stream);
    }
    let mut fifth = TcpStream::connect(server.address).await.unwrap();
    assert!(closed(&mut fifth).await);

    // Once one closes, there is room again.
    drop(held.pop());
    let mut answered = false;
    for _ in 0..50 {
        let mut stream = TcpStream::connect(server.address).await.unwrap();
        tcp_send(&mut stream, &query("nas.lan.")).await;
        let mut len = [0u8; 2];
        if tokio::time::timeout(Duration::from_millis(200), stream.read_exact(&mut len))
            .await
            .is_ok_and(|r| r.is_ok())
        {
            answered = true;
            break;
        }
    }
    assert!(answered);
    server.stop().await;
}

#[tokio::test(start_paused = true)]
async fn an_idle_tcp_connection_is_closed_after_five_seconds() {
    let server = start("").await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    tcp_send(&mut stream, &query("nas.lan.")).await;
    tcp_receive(&mut stream).await;
    let started = tokio::time::Instant::now();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(60), stream.read(&mut byte)).await;
    assert!(matches!(read, Ok(Ok(0))), "{read:?}");
    assert!(started.elapsed() >= TCP_IDLE);
    server.stop().await;
}

#[tokio::test]
async fn shutdown_closes_open_connections_and_returns() {
    let server = start("").await;
    let mut stream = TcpStream::connect(server.address).await.unwrap();
    tcp_send(&mut stream, &query("nas.lan.")).await;
    tcp_receive(&mut stream).await;
    let address = server.address;
    server.stop().await;
    assert!(closed(&mut stream).await);
    assert!(udp_ask(address, "nas.lan.").await.is_none());
}

/// A port free for UDP and TCP on IPv4 and IPv6 a moment ago.
fn free_port() -> u16 {
    loop {
        let port = StdUdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let all = [format!("0.0.0.0:{port}"), format!("[::]:{port}")];
        if all
            .iter()
            .all(|a| std::net::TcpListener::bind(a).is_ok() && StdUdpSocket::bind(a).is_ok())
        {
            return port;
        }
    }
}

/// Linux refuses a dual-stack `[::]` next to `0.0.0.0` on the same port
/// (macOS allows it), so there this shows the IPv6 socket is IPv6-only.
#[tokio::test]
async fn ipv4_and_ipv6_listen_on_the_same_port() {
    let port = free_port();
    let any4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    let any6 = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
    let server = start_on(&[any4, any6], "").await;
    for address in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
    ] {
        assert!(udp_ask(address, "nas.lan.").await.is_some(), "{address}");
        let mut stream = TcpStream::connect(address).await.unwrap();
        tcp_send(&mut stream, &query("nas.lan.")).await;
        assert_eq!(
            tcp_receive(&mut stream).await.metadata.response_code,
            ResponseCode::NoError
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn ipv4_clients_of_an_ipv6_socket_are_allowed_by_their_ipv4_address() {
    // Only 127.0.0.0/8: as ::ffff:127.0.0.1 the client would not match.
    let server = start_on(
        &[SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0))],
        "[server]\nallow_clients = [\"127.0.0.0/8\"]",
    )
    .await;
    let ipv4 = SocketAddr::from((Ipv4Addr::LOCALHOST, server.address.port()));
    assert!(udp_ask(ipv4, "nas.lan.").await.is_some());
    server.stop().await;
}
