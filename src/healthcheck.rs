//! `zinkhole healthcheck`: asks a running server for `localhost`, which it
//! answers from the built-in local record, so the check does not depend on
//! upstream servers. Lets images without a shell (`FROM scratch`) define a
//! container health check.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

/// How long a healthy server may take to answer.
const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum Unhealthy {
    #[error("cannot ask {server}: {source}")]
    Socket {
        server: SocketAddr,
        source: std::io::Error,
    },
    #[error("no answer from {server} within {} s", TIMEOUT.as_secs())]
    NoAnswer { server: SocketAddr },
    #[error("{server} answered {code} (is this address in server.allow_clients?)")]
    Refused {
        server: SocketAddr,
        code: ResponseCode,
    },
}

/// Where a server running with `config` answers: its first listen address,
/// or loopback on that port if it listens on every address.
#[must_use]
pub fn target(config: &crate::config::Config) -> SocketAddr {
    let Some(listen) = config.server.listen.first() else {
        return SocketAddr::from((Ipv4Addr::LOCALHOST, crate::config::DNS_PORT));
    };
    let address = listen.0;
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::from((Ipv4Addr::LOCALHOST, address.port()))
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::from((Ipv6Addr::LOCALHOST, address.port()))
        }
        _ => address,
    }
}

/// Ok when `server` answers `localhost A` with NOERROR within two seconds.
///
/// # Errors
/// When no answer comes, or it is not NOERROR.
pub fn check(server: SocketAddr) -> Result<(), Unhealthy> {
    let socket_error = |source| Unhealthy::Socket { server, source };
    let any: IpAddr = match server {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let socket = UdpSocket::bind((any, 0)).map_err(socket_error)?;
    let query = localhost_query();
    let id = query.metadata.id;
    let bytes = query
        .to_vec()
        .map_err(|e| socket_error(std::io::Error::other(e)))?;
    socket.send_to(&bytes, server).map_err(socket_error)?;

    let deadline = Instant::now() + TIMEOUT;
    let mut buffer = [0u8; 512];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Unhealthy::NoAnswer { server });
        }
        socket.set_read_timeout(Some(left)).map_err(socket_error)?;
        let Ok((len, from)) = socket.recv_from(&mut buffer) else {
            return Err(Unhealthy::NoAnswer { server });
        };
        // Anything that is not this query's answer, from this server, is ignored.
        let Some(data) = buffer.get(..len) else {
            continue;
        };
        let Ok(answer) = Message::from_vec(data) else {
            continue;
        };
        if from != server
            || answer.metadata.id != id
            || answer.metadata.message_type != MessageType::Response
        {
            continue;
        }
        return match answer.metadata.response_code {
            ResponseCode::NoError => Ok(()),
            code => Err(Unhealthy::Refused { server, code }),
        };
    }
}

fn localhost_query() -> Message {
    let mut query = Message::query();
    query.metadata.op_code = OpCode::Query;
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii("localhost.").unwrap_or_default(),
        RecordType::A,
    ));
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_that_answers_noerror_is_healthy_and_refused_is_not() {
        for (code, healthy) in [
            (ResponseCode::NoError, true),
            (ResponseCode::Refused, false),
        ] {
            let server = UdpSocket::bind("127.0.0.1:0").unwrap();
            let address = server.local_addr().unwrap();
            let answering = std::thread::spawn(move || {
                let mut buffer = [0u8; 512];
                let (len, from) = server.recv_from(&mut buffer).unwrap();
                let query = Message::from_vec(&buffer[..len]).unwrap();
                let mut answer = Message::response(query.metadata.id, OpCode::Query);
                answer.metadata.response_code = code;
                server.send_to(&answer.to_vec().unwrap(), from).unwrap();
            });
            assert_eq!(check(address).is_ok(), healthy);
            answering.join().unwrap();
        }
    }

    #[test]
    fn silence_is_unhealthy() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let started = Instant::now();
        assert!(matches!(
            check(silent.local_addr().unwrap()),
            Err(Unhealthy::NoAnswer { .. })
        ));
        assert!(started.elapsed() < TIMEOUT + Duration::from_secs(1));
    }

    #[test]
    fn the_target_is_where_the_config_listens_with_loopback_for_a_wildcard() {
        let target = |listen: &str| {
            let config = crate::config::Config::parse(&format!(
                "[server]\nlisten = [{listen}]\n[upstream]\nservers = [\"9.9.9.9\"]\n"
            ))
            .unwrap();
            super::target(&config).to_string()
        };
        assert_eq!(target(r#""0.0.0.0:5353", "[::]:5353""#), "127.0.0.1:5353");
        assert_eq!(target(r#""[::]""#), "[::1]:53");
        assert_eq!(target(r#""192.168.1.5""#), "192.168.1.5:53");
    }
}
