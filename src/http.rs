//! The HTTP port (ADR-0001): `GET /metrics`, and `GET /sync` on an origin.
//!
//! Only clients in `server.allow_clients` are served; others have their
//! connection closed on arrival, as on the DNS port. A request head must
//! arrive within 2 seconds of connecting, a connection serves one request
//! and lasts at most 10 seconds, and at most 16 are served at once, 4 of
//! them from one client address. Unknown paths are 404, other methods 405.

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
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::Network;
use crate::listen::{self, Admitted, BindError, Limits, Unbound};
use crate::metrics::{self, Snapshot};
use crate::resolver::Resolver;
use crate::upstream::Upstream;

/// For the request head, from the connection's start.
const HEAD_TIMEOUT: Duration = Duration::from_secs(2);
/// For the whole connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections served at once, over all listeners.
const CONNECTIONS: usize = 16;
/// Of those, the most one client address may hold: one client cannot keep
/// the replicas and the monitoring system out.
const PER_CLIENT: usize = 4;

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
            upstream: self.resolver.forwarder().server_metrics(),
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
        let listeners = listen::bind_each(addresses, |address, ipv6_only| {
            listen::bind_tcp(address, ipv6_only).map_err(|why| Unbound::new(address, "http", why))
        })?;
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
    let limits = Limits::new(CONNECTIONS, PER_CLIENT);
    let tasks = TaskTracker::new();
    for listener in listeners {
        tasks.spawn(accept(
            listener,
            router.clone(),
            Arc::clone(&allow_clients),
            Arc::clone(&limits),
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
    limits: Arc<Limits>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
) {
    let allowed = |client| allow_clients.iter().any(|network| network.contains(client));
    while let Some(admitted) = listen::accept(&listener, "http", allowed, &limits, &shutdown).await
    {
        let Admitted {
            stream,
            from,
            client,
            slot,
        } = admitted;
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
            drop(slot);
        };
        tasks.spawn(shutdown.clone().run_until_cancelled_owned(connection));
    }
}

#[cfg(test)]
mod tests;
