//! The HTTP port (ADR-0001): `GET /metrics`, and `GET /sync` on an origin.
//!
//! Only clients in `server.allow_clients` are served; others have their
//! connection closed on arrival, as on the DNS port. A request head must
//! arrive within 2 seconds of connecting, a connection serves one request
//! and lasts at most 10 seconds, and at most 16 are served at once. Unknown paths are
//! 404, other methods 405.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Extension, Router};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::Network;
use crate::metrics::{self, Snapshot};
use crate::resolver::Resolver;
use crate::server::{self, BindError, Unavailable};
use crate::upstream::Upstream;

/// For the request head, from the connection's start.
const HEAD_TIMEOUT: Duration = Duration::from_secs(2);
/// For the whole connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections served at once, over all listeners.
const CONNECTIONS: usize = 16;
const BACKOFF: Duration = Duration::from_millis(10);

/// The client of a request, as allowed: an extension on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Client(pub IpAddr);

/// What `GET /metrics` shows.
#[derive(Debug, Clone)]
pub struct MetricsSource {
    pub resolver: Arc<Resolver<Upstream>>,
    pub state: Arc<metrics::State>,
}

impl MetricsSource {
    #[must_use]
    pub fn render(&self) -> String {
        let policy = self.resolver.policy();
        metrics::render(&Snapshot {
            queries: self.resolver.queries(),
            upstream: self.resolver.forwarder().stats(),
            counts: policy.counts(),
            cache_entries: self.resolver.cache().entry_count(),
            lists: policy.lists(),
            state: &self.state,
        })
    }
}

/// `GET /metrics`.
pub fn metrics_router(source: MetricsSource) -> Router {
    Router::new()
        .route("/metrics", get(get_metrics))
        .with_state(source)
}

async fn get_metrics(State(source): State<MetricsSource>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        source.render(),
    )
}

/// Bound listeners, not yet served.
#[derive(Debug)]
pub struct HttpListeners {
    listeners: Vec<std::net::TcpListener>,
}

impl HttpListeners {
    /// A listener on each address, skipping IPv6 addresses where IPv6 is
    /// unavailable.
    ///
    /// # Errors
    ///
    /// An address cannot be bound, or none is left.
    pub fn bind(addresses: &[SocketAddr]) -> Result<HttpListeners, BindError> {
        let mut listeners = Vec::with_capacity(addresses.len());
        for &address in addresses {
            match server::bind_tcp(address, server::ipv6_only(address, addresses)) {
                Ok(listener) => listeners.push(listener),
                Err(Unavailable::Ipv6(error)) => {
                    tracing::warn!(%address, %error, "IPv6 is unavailable, not listening here");
                }
                Err(Unavailable::Other(source)) => {
                    return Err(BindError::Socket {
                        address,
                        protocol: "http",
                        source,
                    });
                }
            }
        }
        if listeners.is_empty() {
            return Err(BindError::Nothing);
        }
        Ok(HttpListeners { listeners })
    }

    #[must_use]
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .collect()
    }
}

/// Serves `router` on `listeners` to `allow_clients` until `shutdown`.
///
/// # Errors
///
/// A listener cannot be handed to the runtime; nothing is served then.
pub async fn serve(
    listeners: HttpListeners,
    router: Router,
    allow_clients: Vec<Network>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    let listeners = listeners
        .listeners
        .into_iter()
        .map(TcpListener::from_std)
        .collect::<io::Result<Vec<_>>>()?;
    let allow_clients: Arc<[Network]> = allow_clients.into();
    let connections = Arc::new(Semaphore::new(CONNECTIONS));
    let tasks = TaskTracker::new();
    for listener in listeners {
        tasks.spawn(accept(
            listener,
            router.clone(),
            Arc::clone(&allow_clients),
            Arc::clone(&connections),
            tasks.clone(),
            shutdown.clone(),
        ));
    }
    tasks.close();
    tasks.wait().await;
    Ok(())
}

async fn accept(
    listener: TcpListener,
    router: Router,
    allow_clients: Arc<[Network]>,
    connections: Arc<Semaphore>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
) {
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, from) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%error, "http accept failed");
                tokio::time::sleep(BACKOFF).await;
                continue;
            }
        };
        let client = from.ip().to_canonical();
        if !allow_clients.iter().any(|network| network.contains(client)) {
            continue;
        }
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            tracing::debug!(%from, "too many http connections, closing");
            continue;
        };
        let service = TowerToHyperService::new(router.clone().layer(Extension(Client(client))));
        let connection = async move {
            let served = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEAD_TIMEOUT)
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            match tokio::time::timeout(CONNECTION_TIMEOUT, served).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::debug!(%from, %error, "http connection failed"),
                Err(_) => tracing::debug!(%from, "http connection took too long, closed"),
            }
            drop(permit);
        };
        tasks.spawn(shutdown.clone().run_until_cancelled_owned(connection));
    }
}

#[cfg(test)]
mod tests;
