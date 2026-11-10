//! The DNS listeners: UDP and TCP on every `server.listen` address, with a
//! task per query (ADR-0001). Everything about answering is the Resolver's;
//! this module moves bytes and keeps clients from hogging connections:
//!
//! - UDP queries larger than any real query are dropped.
//! - TCP connections from clients that may not query are closed at once, so
//!   they never hold a connection; so is a connection beyond the 16 served at
//!   once, or beyond 4 from one client address.
//! - A TCP connection is closed after 5 seconds without a whole query, after
//!   a write that takes as long, and after 100 queries.
//!
//! An IPv6 address that shares its port with an IPv4 one is IPv6-only, so
//! both can be bound; alone, `[::]` also takes IPv4, and those clients are
//! seen by their IPv4 address. Where IPv6 is unavailable, as in some
//! containers, IPv6 addresses are skipped with a warning.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::resolver::{Forwarder, Resolver, Transport};

/// Larger queries are dropped; real ones are well under 512 bytes.
pub const MAX_QUERY_LEN: usize = 4096;
/// TCP connections served at once, over all listeners.
const TCP_CONNECTIONS: usize = 16;
/// Of those, the most one client address may hold.
const TCP_PER_CLIENT: usize = 4;
/// For a whole query to arrive, or an answer to be written (RFC 7766 asks for
/// seconds, not minutes).
const TCP_IDLE: Duration = Duration::from_secs(5);
/// Queries answered per TCP connection before it is closed.
const TCP_MAX_QUERIES: usize = 100;
/// Pause after a failed receive or accept (such as too many open files), so
/// a broken socket is never spun on.
const BACKOFF: Duration = Duration::from_millis(10);

/// A listen address that could not be bound.
#[derive(Debug, thiserror::Error)]
pub enum BindError {
    #[error("cannot listen on {address} ({protocol}): {source}")]
    Socket {
        address: SocketAddr,
        protocol: &'static str,
        source: io::Error,
    },
    #[error("no address to listen on (IPv6 is unavailable)")]
    Nothing,
}

/// Bound sockets, not yet served.
#[derive(Debug)]
pub struct Listeners {
    udp: Vec<std::net::UdpSocket>,
    tcp: Vec<std::net::TcpListener>,
}

impl Listeners {
    /// A UDP socket and a TCP listener on each address. Port 0 picks a free
    /// port, the same for UDP and TCP.
    ///
    /// # Errors
    ///
    /// An address cannot be bound, or none is left after skipping IPv6
    /// addresses on a system without IPv6.
    pub fn bind(addresses: &[SocketAddr]) -> Result<Listeners, BindError> {
        let mut listeners = Listeners {
            udp: Vec::with_capacity(addresses.len()),
            tcp: Vec::with_capacity(addresses.len()),
        };
        for &address in addresses {
            let ipv6_only = ipv6_only(address, addresses);
            let udp = match bind_udp(address, ipv6_only) {
                Ok(udp) => udp,
                Err(Unavailable::Ipv6(error)) => {
                    tracing::warn!(%address, %error, "IPv6 is unavailable, not listening here");
                    continue;
                }
                Err(Unavailable::Other(source)) => {
                    return Err(BindError::Socket {
                        address,
                        protocol: "udp",
                        source,
                    });
                }
            };
            let bound = udp.local_addr().map_err(|source| BindError::Socket {
                address,
                protocol: "udp",
                source,
            })?;
            let tcp = bind_tcp(bound, ipv6_only).map_err(|unavailable| {
                let (Unavailable::Ipv6(source) | Unavailable::Other(source)) = unavailable;
                BindError::Socket {
                    address: bound,
                    protocol: "tcp",
                    source,
                }
            })?;
            listeners.udp.push(udp);
            listeners.tcp.push(tcp);
        }
        if listeners.udp.is_empty() {
            return Err(BindError::Nothing);
        }
        Ok(listeners)
    }

    /// Where queries are answered, over UDP and TCP alike.
    #[must_use]
    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.udp
            .iter()
            .filter_map(|socket| socket.local_addr().ok())
            .collect()
    }
}

/// Why an address could not be bound.
pub(crate) enum Unavailable {
    /// The system has no IPv6: skip the address.
    Ipv6(io::Error),
    Other(io::Error),
}

/// True if the IPv6 `address` must be IPv6-only: an IPv4 address in `all`
/// shares its port.
pub(crate) fn ipv6_only(address: SocketAddr, all: &[SocketAddr]) -> bool {
    address.is_ipv6()
        && all
            .iter()
            .any(|other| other.is_ipv4() && other.port() == address.port())
}

fn bind_udp(address: SocketAddr, ipv6_only: bool) -> Result<std::net::UdpSocket, Unavailable> {
    bind(address, Type::DGRAM, ipv6_only).map(Into::into)
}

/// A TCP listener on `address`.
pub(crate) fn bind_tcp(
    address: SocketAddr,
    ipv6_only: bool,
) -> Result<std::net::TcpListener, Unavailable> {
    let socket = bind(address, Type::STREAM, ipv6_only)?;
    socket.listen(1024).map_err(Unavailable::Other)?;
    Ok(socket.into())
}

/// A non-blocking socket bound to `address`.
fn bind(address: SocketAddr, kind: Type, ipv6_only: bool) -> Result<Socket, Unavailable> {
    // Creating an IPv6 socket fails only without IPv6; binding fails with
    // AddrNotAvailable when IPv6 exists but has no address to bind.
    let socket =
        Socket::new(Domain::for_address(address), kind, None).map_err(|error| match address {
            SocketAddr::V6(_) => Unavailable::Ipv6(error),
            SocketAddr::V4(_) => Unavailable::Other(error),
        })?;
    let bound = (|| {
        if address.is_ipv6() {
            socket.set_only_v6(ipv6_only)?;
        }
        if kind == Type::STREAM {
            // Quick restarts despite connections in TIME_WAIT. Not
            // SO_REUSEPORT: nobody else gets to listen on the port.
            socket.set_reuse_address(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())
    })();
    match bound {
        Ok(()) => Ok(socket),
        Err(error) if address.is_ipv6() && error.kind() == io::ErrorKind::AddrNotAvailable => {
            Err(Unavailable::Ipv6(error))
        }
        Err(error) => Err(Unavailable::Other(error)),
    }
}

/// Answers queries on `listeners` until `shutdown`, then cancels the queries
/// in flight and returns once every task has stopped.
///
/// # Errors
///
/// A socket cannot be handed to the runtime; nothing is served then.
pub async fn serve<F: Forwarder + 'static>(
    listeners: Listeners,
    resolver: Arc<Resolver<F>>,
    shutdown: CancellationToken,
) -> io::Result<()> {
    // All handed over before any is served, so a failure serves nothing.
    let udp = listeners
        .udp
        .into_iter()
        .map(|socket| UdpSocket::from_std(socket).map(Arc::new))
        .collect::<io::Result<Vec<_>>>()?;
    let tcp = listeners
        .tcp
        .into_iter()
        .map(TcpListener::from_std)
        .collect::<io::Result<Vec<_>>>()?;
    let tasks = TaskTracker::new();
    let limits = Arc::new(TcpLimits::new());
    for socket in udp {
        tasks.spawn(serve_udp(
            socket,
            Arc::clone(&resolver),
            tasks.clone(),
            shutdown.clone(),
        ));
    }
    for listener in tcp {
        tasks.spawn(accept_tcp(
            listener,
            Arc::clone(&resolver),
            Arc::clone(&limits),
            tasks.clone(),
            shutdown.clone(),
        ));
    }
    shutdown.cancelled().await;
    tasks.close();
    tasks.wait().await;
    Ok(())
}

async fn serve_udp<F: Forwarder + 'static>(
    socket: Arc<UdpSocket>,
    resolver: Arc<Resolver<F>>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
) {
    // One byte more than the largest query, to tell a query that fits from
    // one the socket cut short.
    let mut buffer = vec![0u8; MAX_QUERY_LEN + 1];
    loop {
        let received = tokio::select! {
            () = shutdown.cancelled() => return,
            received = socket.recv_from(&mut buffer) => received,
        };
        let (len, from) = match received {
            Ok(received) => received,
            Err(error) => {
                tracing::debug!(%error, "udp receive failed");
                tokio::time::sleep(BACKOFF).await;
                continue;
            }
        };
        let Some(query) = buffer.get(..len).filter(|_| len <= MAX_QUERY_LEN) else {
            continue;
        };
        let query = query.to_vec();
        let (socket, resolver) = (Arc::clone(&socket), Arc::clone(&resolver));
        tasks.spawn(shutdown.clone().run_until_cancelled_owned(async move {
            let reply = resolver.handle(&query, client(from), Transport::Udp).await;
            if let Some(response) = reply.response
                && let Err(error) = socket.send_to(&response, from).await
            {
                tracing::debug!(%from, %error, "udp send failed");
            }
        }));
    }
}

async fn accept_tcp<F: Forwarder + 'static>(
    listener: TcpListener,
    resolver: Arc<Resolver<F>>,
    limits: Arc<TcpLimits>,
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
                tracing::debug!(%error, "tcp accept failed");
                tokio::time::sleep(BACKOFF).await;
                continue;
            }
        };
        let client = client(from);
        // Checked per connection too, not just per query: a client that may
        // not query must not hold a connection.
        if !resolver.is_allowed(client) {
            continue;
        }
        let Some(slot) = limits.admit(client) else {
            tracing::debug!(%from, "too many tcp connections, closing");
            continue;
        };
        let resolver = Arc::clone(&resolver);
        tasks.spawn(shutdown.clone().run_until_cancelled_owned(async move {
            if let Err(error) = serve_connection(stream, client, &resolver).await {
                tracing::debug!(%from, %error, "tcp connection ended");
            }
            drop(slot);
        }));
    }
}

/// Answers the queries on one connection, in order, until the client closes
/// it, goes quiet, or reaches the query limit.
async fn serve_connection<F: Forwarder>(
    mut stream: TcpStream,
    client: IpAddr,
    resolver: &Resolver<F>,
) -> io::Result<()> {
    for _ in 0..TCP_MAX_QUERIES {
        let query = match tokio::time::timeout(TCP_IDLE, read_message(&mut stream)).await {
            Ok(Ok(Some(query))) => query,
            // Closed by the client, or quiet too long: done.
            Ok(Ok(None)) | Err(_) => return Ok(()),
            Ok(Err(error)) => return Err(error),
        };
        let Some(response) = resolver
            .handle(&query, client, Transport::Tcp)
            .await
            .response
        else {
            return Ok(());
        };
        let len = u16::try_from(response.len()).map_err(io::Error::other)?;
        let mut framed = Vec::with_capacity(2 + response.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(&response);
        tokio::time::timeout(TCP_IDLE, stream.write_all(&framed))
            .await
            .map_err(io::Error::other)??;
    }
    Ok(())
}

/// One length-prefixed message; None when the client closed the connection
/// between messages.
async fn read_message(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let len = match stream.read_u16().await {
        Ok(len) => usize::from(len),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    };
    if len > MAX_QUERY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a {len}-byte query"),
        ));
    }
    let mut query = vec![0u8; len];
    stream.read_exact(&mut query).await?;
    Ok(Some(query))
}

/// The client as the Resolver sees it: an IPv4 client of a dual-stack
/// socket by its IPv4 address, so `allow_clients` applies to it.
fn client(from: SocketAddr) -> IpAddr {
    from.ip().to_canonical()
}

/// The TCP connections being served: at most [`TCP_CONNECTIONS`], and at
/// most [`TCP_PER_CLIENT`] of them per client address.
#[derive(Debug)]
struct TcpLimits {
    connections: Arc<Semaphore>,
    per_client: Mutex<HashMap<IpAddr, usize>>,
}

impl TcpLimits {
    fn new() -> TcpLimits {
        TcpLimits {
            connections: Arc::new(Semaphore::new(TCP_CONNECTIONS)),
            per_client: Mutex::new(HashMap::new()),
        }
    }

    /// A place for one more connection from `client`, if there is one; it
    /// is freed when dropped.
    fn admit(self: &Arc<Self>, client: IpAddr) -> Option<TcpSlot> {
        let mut per_client = self
            .per_client
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if per_client
            .get(&client)
            .is_some_and(|&held| held >= TCP_PER_CLIENT)
        {
            return None;
        }
        let permit = Arc::clone(&self.connections).try_acquire_owned().ok()?;
        *per_client.entry(client).or_insert(0) += 1;
        Some(TcpSlot {
            limits: Arc::clone(self),
            client,
            _permit: permit,
        })
    }
}

#[derive(Debug)]
struct TcpSlot {
    limits: Arc<TcpLimits>,
    client: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for TcpSlot {
    fn drop(&mut self) {
        let mut per_client = self
            .limits
            .per_client
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(held) = per_client.get_mut(&self.client) {
            *held -= 1;
            if *held == 0 {
                per_client.remove(&self.client);
            }
        }
    }
}

#[cfg(test)]
mod tests;
