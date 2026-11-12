//! What the DNS and the HTTP listeners share: binding their addresses, and
//! letting connections in.
//!
//! - An IPv6 address that shares its port with an IPv4 one is IPv6-only, so
//!   both can be bound; alone, `[::]` also takes IPv4, and those clients are
//!   seen by their IPv4 address. Where IPv6 is unavailable, as in some
//!   containers, IPv6 addresses are skipped with a warning.
//! - A connection from a client that is not allowed is closed at once, so
//!   such a client never holds one; so is a connection beyond the
//!   listener's [`Limits`]: so many at once, and so many of those from one
//!   client address.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use socket2::{Domain, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Pause after a failed receive or accept (such as too many open files), so
/// a broken socket is never spun on.
pub(crate) const BACKOFF: Duration = Duration::from_millis(10);

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

/// Why a socket could not be bound.
pub(crate) enum Unavailable {
    /// The system has no IPv6.
    Ipv6(io::Error),
    Other(io::Error),
}

impl Unavailable {
    pub(crate) fn into_error(self) -> io::Error {
        let (Unavailable::Ipv6(error) | Unavailable::Other(error)) = self;
        error
    }
}

/// Why nothing listens on an address.
pub(crate) enum Unbound {
    /// The system has no IPv6: the address is skipped.
    NoIpv6(io::Error),
    Failed(BindError),
}

impl Unbound {
    /// `address` could not be bound for `protocol`, for the reason given.
    pub(crate) fn new(address: SocketAddr, protocol: &'static str, why: Unavailable) -> Unbound {
        match why {
            Unavailable::Ipv6(error) => Unbound::NoIpv6(error),
            Unavailable::Other(source) => Unbound::failed(address, protocol, source),
        }
    }

    /// `address` could not be bound for `protocol`, and that is an error.
    pub(crate) fn failed(
        address: SocketAddr,
        protocol: &'static str,
        source: io::Error,
    ) -> Unbound {
        Unbound::Failed(BindError::Socket {
            address,
            protocol,
            source,
        })
    }
}

/// What `bind` makes of each of `addresses`, skipping IPv6 addresses where
/// IPv6 is unavailable. `bind` is told whether its address must be
/// IPv6-only.
///
/// # Errors
///
/// An address cannot be bound, or none is left.
pub(crate) fn bind_each<T>(
    addresses: &[SocketAddr],
    mut bind: impl FnMut(SocketAddr, bool) -> Result<T, Unbound>,
) -> Result<Vec<T>, BindError> {
    let mut bound = Vec::with_capacity(addresses.len());
    for &address in addresses {
        match bind(address, ipv6_only(address, addresses)) {
            Ok(listener) => bound.push(listener),
            Err(Unbound::NoIpv6(error)) => {
                tracing::warn!(%address, %error, "IPv6 is unavailable, not listening here");
            }
            Err(Unbound::Failed(error)) => return Err(error),
        }
    }
    if bound.is_empty() {
        return Err(BindError::Nothing);
    }
    Ok(bound)
}

/// True if the IPv6 `address` must be IPv6-only: an IPv4 address in `all`
/// shares its port.
fn ipv6_only(address: SocketAddr, all: &[SocketAddr]) -> bool {
    address.is_ipv6()
        && all
            .iter()
            .any(|other| other.is_ipv4() && other.port() == address.port())
}

/// A UDP socket on `address`.
pub(crate) fn bind_udp(
    address: SocketAddr,
    ipv6_only: bool,
) -> Result<std::net::UdpSocket, Unavailable> {
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

/// The client as `allow_clients` sees it: an IPv4 client of a dual-stack
/// socket by its IPv4 address.
pub(crate) fn client(from: SocketAddr) -> IpAddr {
    from.ip().to_canonical()
}

/// The connections a listener serves at once: so many in all, and so many
/// of them per client address.
#[derive(Debug)]
pub(crate) struct Limits {
    connections: Arc<Semaphore>,
    per_client: Mutex<HashMap<IpAddr, usize>>,
    most_per_client: usize,
}

impl Limits {
    pub(crate) fn new(most: usize, most_per_client: usize) -> Arc<Limits> {
        Arc::new(Limits {
            connections: Arc::new(Semaphore::new(most)),
            per_client: Mutex::new(HashMap::new()),
            most_per_client,
        })
    }

    /// A place for one more connection from `client`, if there is one; it
    /// is freed when dropped.
    pub(crate) fn admit(self: &Arc<Self>, client: IpAddr) -> Option<Slot> {
        let mut per_client = self
            .per_client
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if per_client
            .get(&client)
            .is_some_and(|&held| held >= self.most_per_client)
        {
            return None;
        }
        let permit = Arc::clone(&self.connections).try_acquire_owned().ok()?;
        *per_client.entry(client).or_insert(0) += 1;
        Some(Slot {
            limits: Arc::clone(self),
            client,
            _permit: permit,
        })
    }
}

/// A connection's place within the [`Limits`], freed when dropped.
#[derive(Debug)]
pub(crate) struct Slot {
    limits: Arc<Limits>,
    client: IpAddr,
    _permit: OwnedSemaphorePermit,
}

impl Drop for Slot {
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

/// A connection that was let in.
#[derive(Debug)]
pub(crate) struct Admitted {
    pub(crate) stream: TcpStream,
    /// Where it comes from, for the log.
    pub(crate) from: SocketAddr,
    /// Its client, as `allow_clients` sees it.
    pub(crate) client: IpAddr,
    /// Its place within the limits: keep it for as long as the connection.
    pub(crate) slot: Slot,
}

/// The next connection on `listener` to serve; None at `shutdown`.
///
/// A connection from a client that is not `allowed` is closed at once, and
/// so is one beyond `limits`. A failed accept is tried again after a pause.
/// `protocol` names the listener in the log.
pub(crate) async fn accept(
    listener: &TcpListener,
    protocol: &str,
    allowed: impl Fn(IpAddr) -> bool,
    limits: &Arc<Limits>,
    shutdown: &CancellationToken,
) -> Option<Admitted> {
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => return None,
            accepted = listener.accept() => accepted,
        };
        let (stream, from) = match accepted {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::debug!(%error, "{protocol} accept failed");
                tokio::time::sleep(BACKOFF).await;
                continue;
            }
        };
        let client = client(from);
        if !allowed(client) {
            continue;
        }
        let Some(slot) = limits.admit(client) else {
            tracing::debug!(%from, "too many {protocol} connections, closing");
            continue;
        };
        return Some(Admitted {
            stream,
            from,
            client,
            slot,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn limits_count_per_client_and_overall_and_free_on_drop() {
        let limits = Limits::new(16, 4);
        let client = |n: u8| IpAddr::from([10, 0, 0, n]);
        let first: Vec<_> = (0..4).map(|_| limits.admit(client(1)).unwrap()).collect();
        assert!(limits.admit(client(1)).is_none());
        let mut others: Vec<_> = (2..)
            .map(client)
            .take(16 - 4)
            .map(|c| limits.admit(c).unwrap())
            .collect();
        assert!(limits.admit(client(200)).is_none(), "all 16 are taken");
        others.pop();
        assert!(limits.admit(client(200)).is_some());
        drop(first);
        drop(others);
        assert_eq!(
            limits.per_client.lock().unwrap().len(),
            0,
            "nothing left behind"
        );
    }

    #[test]
    fn binding_skips_addresses_without_ipv6_and_fails_on_anything_else() {
        let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 5300));
        let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 5300));
        let other = SocketAddr::from((Ipv6Addr::LOCALHOST, 5301));
        let no_ipv6 = || io::Error::from(io::ErrorKind::AddrNotAvailable);

        // IPv6-only exactly where an IPv4 address shares the port.
        let bound = bind_each(&[v4, v6, other], |address, ipv6_only| {
            Ok((address, ipv6_only))
        });
        assert_eq!(bound.unwrap(), [(v4, false), (v6, true), (other, false)]);

        let skipped = bind_each(&[v4, v6], |address, _| {
            if address.is_ipv6() {
                Err(Unbound::new(address, "udp", Unavailable::Ipv6(no_ipv6())))
            } else {
                Ok(address)
            }
        });
        assert_eq!(skipped.unwrap(), [v4]);

        let nothing = bind_each(&[v6], |address, _| {
            Err::<(), _>(Unbound::new(address, "udp", Unavailable::Ipv6(no_ipv6())))
        });
        assert!(matches!(nothing, Err(BindError::Nothing)));

        let failed = bind_each(&[v4, v6], |address, _| {
            Err::<(), _>(Unbound::new(address, "http", Unavailable::Other(no_ipv6())))
        });
        assert!(
            matches!(failed, Err(BindError::Socket { address, protocol: "http", .. }) if address == v4)
        );
    }
}
