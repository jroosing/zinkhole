//! The HTTP port over loopback, with a raw HTTP/1.1 client.

use std::net::Ipv4Addr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use super::*;
use crate::config::Config;
use crate::resolver::Transport;
use crate::serve;

struct Running {
    address: SocketAddr,
    resolver: Arc<Resolver<Upstream>>,
    shutdown: CancellationToken,
    task: JoinHandle<io::Result<()>>,
}

fn start(allow_clients: &str) -> Running {
    let config = Config::parse(&format!(
        "[server]\nallow_clients = [{allow_clients}]\n[upstream]\nservers = [\"127.0.0.1:9\"]\n[local.records]\n\"nas.lan\" = \"192.168.1.10\"\n"
    ))
    .unwrap();
    let resolver = Arc::new(serve::resolver(&config, Upstream::new(&config.upstream)));
    let listeners = HttpListeners::bind(&[SocketAddr::from((Ipv4Addr::LOCALHOST, 0))]).unwrap();
    let address = listeners.addresses()[0];
    let router = metrics_router(MetricsSource {
        resolver: Arc::clone(&resolver),
        state: Arc::new(metrics::State::default()),
    });
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(serve(
        listeners,
        router,
        config.server.allow_clients.clone(),
        shutdown.clone(),
    ));
    Running {
        address,
        resolver,
        shutdown,
        task,
    }
}

/// The whole response to `request`, or what arrived before the server
/// closed the connection.
async fn exchange(address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    String::from_utf8_lossy(&response).into_owned()
}

fn request(method: &str, path: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: zinkhole\r\n\r\n")
}

#[tokio::test]
async fn get_metrics_shows_the_counters_in_prometheus_format() {
    let running = start("\"127.0.0.0/8\"");
    let mut query = hickory_proto::op::Message::query();
    query.add_query(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_ascii("nas.lan.").unwrap(),
        hickory_proto::rr::RecordType::A,
    ));
    let bytes = query.to_vec().unwrap();
    running
        .resolver
        .handle(&bytes, Ipv4Addr::LOCALHOST.into(), Transport::Udp)
        .await;

    let response = exchange(running.address, &request("GET", "/metrics")).await;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(
        response.contains("content-type: text/plain; version=0.0.4; charset=utf-8\r\n"),
        "{response}"
    );
    assert!(
        response.contains("\nzinkhole_queries_total{outcome=\"local\"} 1\n"),
        "{response}"
    );
    assert!(
        response.contains("\nzinkhole_local_records 1\n"),
        "{response}"
    );
    assert!(
        response.contains("zinkhole_upstream_failures_total{server=\"127.0.0.1:9\"} 0"),
        "{response}"
    );
    running.shutdown.cancel();
    running.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn unknown_paths_are_404_and_other_methods_405() {
    let running = start("\"127.0.0.0/8\"");
    let response = exchange(running.address, &request("GET", "/nothing")).await;
    assert!(response.starts_with("HTTP/1.1 404 "), "{response}");
    let response = exchange(running.address, &request("POST", "/metrics")).await;
    assert!(response.starts_with("HTTP/1.1 405 "), "{response}");
    let response = exchange(running.address, &request("HEAD", "/metrics")).await;
    assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    running.shutdown.cancel();
}

#[tokio::test]
async fn clients_that_may_not_query_get_a_closed_connection() {
    let running = start("\"10.0.0.0/8\"");
    let response = exchange(running.address, &request("GET", "/metrics")).await;
    assert_eq!(response, "");
    running.shutdown.cancel();
}

/// How long until the server closes `stream`, and what it sent.
async fn closed_after(mut stream: TcpStream) -> (Duration, String) {
    let started = std::time::Instant::now();
    let mut response = Vec::new();
    let read =
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response)).await;
    assert!(read.is_ok(), "the server closed the connection");
    (
        started.elapsed(),
        String::from_utf8_lossy(&response).into_owned(),
    )
}

#[tokio::test]
async fn a_request_head_must_arrive_within_two_seconds_of_connecting() {
    let running = start("\"127.0.0.0/8\"");
    let mut slow = TcpStream::connect(running.address).await.unwrap();
    slow.write_all(b"GET /metrics HTTP/1.1\r\nHost: zinkh")
        .await
        .unwrap();
    let silent = TcpStream::connect(running.address).await.unwrap();
    let (slow, silent) = tokio::join!(closed_after(slow), closed_after(silent));
    for (waited, response) in [slow, silent] {
        assert!(
            waited >= Duration::from_millis(1900) && waited < Duration::from_secs(4),
            "{waited:?}"
        );
        assert!(!response.contains(" 200 "), "{response}");
    }
    running.shutdown.cancel();
}

#[tokio::test]
async fn shutdown_returns_with_a_connection_open() {
    let running = start("\"127.0.0.0/8\"");
    let _idle = TcpStream::connect(running.address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    running.shutdown.cancel();
    let stopped = tokio::time::timeout(Duration::from_secs(1), running.task).await;
    assert!(matches!(stopped, Ok(Ok(Ok(())))), "{stopped:?}");
}
