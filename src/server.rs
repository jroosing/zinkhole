//! The DNS listeners: UDP and TCP on every `server.listen` address, with a
//! task per query (ADR-0001). Everything about answering is the Resolver's;
//! this module moves bytes and keeps clients from hogging connections:
//!
//! - UDP queries larger than any real query are dropped, and so are those
//!   from clients that may not query, before anything is done for them.
//! - TCP connections from clients that may not query are closed at once, so
//!   they never hold a connection; so is a connection beyond the 16 served at
//!   once, or beyond 4 from one client address.
//! - A TCP connection is closed after 5 seconds without a whole query, after
//!   a write that takes as long, and after 100 queries.
//!
//! Binding the addresses and letting connections in are shared with the
//! HTTP port: see [`crate::listen`].

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::listen::{self, Admitted, BindError, Limits, Unbound};
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
        let bound = listen::bind_each(addresses, |address, ipv6_only| {
            let udp = listen::bind_udp(address, ipv6_only)
                .map_err(|why| Unbound::new(address, "udp", why))?;
            let bound = udp
                .local_addr()
                .map_err(|error| Unbound::failed(address, "udp", error))?;
            // The UDP socket is there, so IPv6 is: no TCP listener beside it
            // is an error, never a reason to skip the address.
            let tcp = listen::bind_tcp(bound, ipv6_only)
                .map_err(|why| Unbound::failed(bound, "tcp", why.into_error()))?;
            Ok((udp, tcp))
        })?;
        let (udp, tcp) = bound.into_iter().unzip();
        Ok(Listeners { udp, tcp })
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
    let limits = Limits::new(TCP_CONNECTIONS, TCP_PER_CLIENT);
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
                tokio::time::sleep(listen::BACKOFF).await;
                continue;
            }
        };
        let Some(query) = buffer.get(..len).filter(|_| len <= MAX_QUERY_LEN) else {
            continue;
        };
        let client = listen::client(from);
        // Before anything is done for it: a flood from clients that may not
        // query costs neither a copy nor a task per packet.
        if !resolver.is_allowed(client) {
            resolver.dropped_unread(client);
            continue;
        }
        let query = query.to_vec();
        let (socket, resolver) = (Arc::clone(&socket), Arc::clone(&resolver));
        tasks.spawn(shutdown.clone().run_until_cancelled_owned(async move {
            let reply = resolver.handle(&query, client, Transport::Udp).await;
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
    limits: Arc<Limits>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
) {
    // Checked per connection too, not just per query: a client that may not
    // query must not hold a connection.
    let allowed = |client| resolver.is_allowed(client);
    while let Some(admitted) = listen::accept(&listener, "tcp", allowed, &limits, &shutdown).await {
        let Admitted {
            stream,
            from,
            client,
            slot,
        } = admitted;
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

#[cfg(test)]
mod tests;
