//! The configuration file (TOML). `config.example.toml` documents every
//! setting. Parsing checks each value on its own, so the error names the line;
//! [`Config::validate`] then checks what involves several settings, and its
//! errors name the setting.

use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use indexmap::IndexMap;
use ipnet::IpNet;
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use url::Url;

use crate::name;

/// Where `serve` and `check` look unless told otherwise.
pub const DEFAULT_PATH: &str = "/etc/zinkhole/config.toml";
/// A config file larger than this is refused.
pub const MAX_FILE_SIZE: usize = 1024 * 1024;
/// The port DNS uses when an address gives none.
pub const DNS_PORT: u16 = 53;
/// The HTTP port in the docs and the installers (ADR-0001).
pub const HTTP_PORT: u16 = 5380;
/// At most this many addresses per local record.
pub const MAX_ADDRESSES: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{} is larger than {} KiB", path.display(), MAX_FILE_SIZE / 1024)]
    TooLarge { path: PathBuf },
    /// Names the line and column.
    #[error("{0}")]
    Parse(#[from] toml::de::Error),
    #[error("{key}: {message}")]
    Invalid { key: String, message: String },
    /// A parse or validation error in the file at `path`.
    #[error("{}: {source}", path.display())]
    InFile { path: PathBuf, source: Box<Error> },
}

fn invalid(key: impl Into<String>, message: impl Into<String>) -> Error {
    Error::Invalid {
        key: key.into(),
        message: message.into(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    pub upstream: Upstream,
    #[serde(default)]
    pub cache: Cache,
    /// None on a replica, whose Policy settings come from its origin.
    pub blocking: Option<Blocking>,
    /// None on a replica, whose Policy settings come from its origin.
    pub local: Option<Local>,
    #[serde(default)]
    pub log: Log,
    /// None when nothing is served over HTTP: no Metrics, and no origin.
    pub http: Option<Http>,
    /// None when running alone.
    pub sync: Option<Sync>,
}

impl Config {
    /// Reads, parses and validates the file at `path`.
    ///
    /// # Errors
    /// When the file cannot be read, is too large, or is not a valid config.
    pub fn load(path: &Path) -> Result<Config, Error> {
        let read_error = |source| Error::Read {
            path: path.to_path_buf(),
            source,
        };
        let size = std::fs::metadata(path).map_err(read_error)?.len();
        if size > MAX_FILE_SIZE as u64 {
            return Err(Error::TooLarge {
                path: path.to_path_buf(),
            });
        }
        let text = std::fs::read_to_string(path).map_err(read_error)?;
        Config::parse(&text).map_err(|error| Error::InFile {
            path: path.to_path_buf(),
            source: Box::new(error),
        })
    }

    /// Parses and validates config text.
    ///
    /// # Errors
    /// When the text is not valid TOML, has unknown keys or invalid values, or
    /// its settings contradict each other.
    pub fn parse(text: &str) -> Result<Config, Error> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// What this instance is to sync.
    #[must_use]
    pub fn role(&self) -> Role {
        match self.sync {
            None => Role::Alone,
            Some(Sync::Origin { .. }) => Role::Origin,
            Some(Sync::Replica { .. }) => Role::Replica,
        }
    }

    /// The Policy settings: this file's, or the defaults when it has none.
    #[must_use]
    pub fn policy_settings(&self) -> PolicySettings {
        PolicySettings {
            blocking: self.blocking.clone().unwrap_or_default(),
            local: self.local.clone().unwrap_or_default(),
        }
    }

    /// The checks that involve more than one setting.
    fn validate(&self) -> Result<(), Error> {
        if self.server.listen.is_empty() {
            return Err(invalid("server.listen", "needs at least one address"));
        }
        if self.upstream.servers.is_empty() {
            return Err(invalid(
                "upstream.servers",
                "at least one upstream server is required",
            ));
        }
        if let Some(i) = first_repeat(&self.upstream.servers) {
            return Err(invalid(format!("upstream.servers[{i}]"), "is listed twice"));
        }
        for (i, server) in self.upstream.servers.iter().enumerate() {
            if let UpstreamServer::Plain(address) = server
                && self.server.is_this_server(address.0)
            {
                return Err(invalid(
                    format!("upstream.servers[{i}]"),
                    format!(
                        "{} is this server itself (server.listen); every query would come back here",
                        address.0
                    ),
                ));
            }
        }
        if let Some(local) = &self.local {
            self.server.check_forwards(local)?;
        }
        if let Some(blocking) = &self.blocking {
            blocking.validate()?;
        }
        if self.cache.min_ttl > self.cache.max_ttl {
            return Err(invalid(
                "cache.min_ttl",
                "must not be larger than cache.max_ttl",
            ));
        }
        if let Some(http) = &self.http {
            if http.listen.is_empty() {
                return Err(invalid("http.listen", "needs at least one address"));
            }
            for address in &http.listen {
                if let Some(dns) = self
                    .server
                    .listen
                    .iter()
                    .find(|dns| same_listener(address.0, dns.0))
                {
                    return Err(invalid(
                        "http.listen",
                        format!(
                            "{} takes port {} from server.listen ({})",
                            address.0,
                            address.0.port(),
                            dns.0
                        ),
                    ));
                }
            }
        }
        match &self.sync {
            Some(Sync::Origin { .. }) if self.http.is_none() => Err(invalid(
                "sync",
                "an origin serves its settings on http.listen: add an [http] section",
            )),
            Some(Sync::Replica { .. }) if self.blocking.is_some() || self.local.is_some() => {
                Err(invalid(
                    "sync",
                    "a replica takes [blocking] and [local] from its origin: remove them from this file",
                ))
            }
            _ => Ok(()),
        }
    }
}

/// The index of the first item that repeats an earlier one.
fn first_repeat<T: PartialEq>(items: &[T]) -> Option<usize> {
    items
        .iter()
        .enumerate()
        .find(|(i, item)| items.iter().take(*i).any(|earlier| earlier == *item))
        .map(|(i, _)| i)
}

/// Two listeners clash when they take the same port on the same address, or
/// one of them on every address.
fn same_listener(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

/// Everything the Policy is built from: what an origin serves its replicas,
/// and what a Reload or a Sync puts in force.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySettings {
    #[serde(default)]
    pub blocking: Blocking,
    #[serde(default)]
    pub local: Local,
}

impl PolicySettings {
    /// The checks that need nothing but the settings themselves. Whether
    /// they fit an instance is for its [`Server`] to say.
    ///
    /// # Errors
    /// When the settings contradict themselves or hold an invalid rule.
    pub fn validate(&self) -> Result<(), Error> {
        self.blocking.validate()
    }
}

// ---------------------------------------------------------------------------
// Sections

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Server {
    /// Where to answer DNS, over UDP and TCP.
    pub listen: Vec<DnsAddr>,
    /// Only clients in these networks are answered.
    pub allow_clients: Vec<Network>,
}

impl Server {
    /// Policy settings synced from the origin, checked as this instance's
    /// own would be: a replica takes them only if it could have had them in
    /// its own file.
    ///
    /// # Errors
    /// When the text is not valid settings, or they do not fit this
    /// instance (such as a forwarded zone pointing at it).
    pub fn synced_settings(&self, text: &str) -> Result<PolicySettings, Error> {
        let settings: PolicySettings = toml::from_str(text)?;
        self.check_forwards(&settings.local)?;
        settings.validate()?;
        Ok(settings)
    }

    /// No forwarded zone of `local` may send its queries to this server.
    fn check_forwards(&self, local: &Local) -> Result<(), Error> {
        for (zone, server) in &local.forward {
            if self.is_this_server(server.0) {
                return Err(invalid(
                    format!("local.forward.\"{zone}\""),
                    format!(
                        "{} is this server itself (server.listen); every query for '{zone}' would come back here",
                        server.0
                    ),
                ));
            }
        }
        Ok(())
    }

    /// True if queries sent to `target` would reach this server.
    fn is_this_server(&self, target: SocketAddr) -> bool {
        self.listen.iter().any(|listen| {
            let listen = listen.0;
            listen.port() == target.port()
                && (listen.ip() == target.ip()
                    || (listen.ip().is_unspecified()
                        && (target.ip().is_loopback() || target.ip().is_unspecified())))
        })
    }
}

impl Default for Server {
    fn default() -> Self {
        let any4 = DnsAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DNS_PORT));
        let any6 = DnsAddr(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DNS_PORT));
        Server {
            listen: vec![any4, any6],
            allow_clients: default_allow_clients(),
        }
    }
}

/// Loopback, private, link-local and CGNAT ranges: the clients of a home
/// network, and nobody on the internet.
fn default_allow_clients() -> Vec<Network> {
    [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .into_iter()
    .filter_map(|text| IpNet::from_str(text).ok().map(Network))
    .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Tried in order; the one that answered last is tried first.
    pub servers: Vec<UpstreamServer>,
    /// Everything one server gets for one query.
    #[serde(
        default = "default_timeout_ms",
        deserialize_with = "ranged::<_, 100, 30_000>"
    )]
    pub timeout_ms: u32,
    /// Upstream exchanges at once; a cache miss beyond that is SERVFAIL.
    #[serde(
        default = "default_max_in_flight",
        deserialize_with = "ranged::<_, 1, 1024>"
    )]
    pub max_in_flight: u32,
    /// Who checks DNSSEC signatures on upstream answers.
    #[serde(default)]
    pub dnssec: Dnssec,
}

/// Who validates DNSSEC (`upstream.dnssec`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Dnssec {
    /// The upstream servers: DNSSEC flags are passed through, and a
    /// validating upstream (Quad9, Cloudflare) refuses forged data.
    #[default]
    Upstream,
    /// zinkhole itself, from the root trust anchors: answers from upstream
    /// servers whose signatures do not hold are SERVFAIL. Forwarded zones
    /// are not validated.
    Validate,
}

fn default_timeout_ms() -> u32 {
    2000
}

fn default_max_in_flight() -> u32 {
    64
}

/// A server for the queries zinkhole does not answer itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpstreamServer {
    /// `"192.168.1.1"` or `"192.168.1.1:5353"`.
    Plain(DnsAddr),
    /// `{ url = "https://dns.quad9.net/dns-query", address = "9.9.9.9" }`.
    Https(EncryptedServer),
    /// `{ url = "quic://dns.adguard-dns.com", address = "94.140.14.14" }`:
    /// DNS over QUIC (RFC 9250).
    Quic(EncryptedServer),
}

impl<'de> Deserialize<'de> for UpstreamServer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ServerVisitor;

        impl<'de> Visitor<'de> for ServerVisitor {
            type Value = UpstreamServer;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(r#"an IP address (plain DNS) or { url = "https://…" or "quic://…", address = "…" } (DNS over HTTPS or QUIC)"#)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                DnsAddr::from_str(value)
                    .map(UpstreamServer::Plain)
                    .map_err(E::custom)
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                let server =
                    EncryptedServer::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(match server.url.scheme() {
                    "quic" => UpstreamServer::Quic(server),
                    _ => UpstreamServer::Https(server),
                })
            }
        }

        deserializer.deserialize_any(ServerVisitor)
    }
}

/// A DNS-over-HTTPS or DNS-over-QUIC server. `url` gives the name the
/// certificate must carry (and for HTTPS the path); `address` is where to
/// connect, so reaching it needs no name lookup (zinkhole is the resolver).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawEncryptedServer")]
pub struct EncryptedServer {
    pub url: Url,
    /// The URL's host, checked against the server's certificate.
    pub tls_name: String,
    /// The address and the URL's port.
    pub address: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEncryptedServer {
    url: Url,
    address: IpAddr,
}

/// The DNS-over-QUIC port (RFC 9250).
const DOQ_PORT: u16 = 853;

impl TryFrom<RawEncryptedServer> for EncryptedServer {
    type Error = String;

    fn try_from(raw: RawEncryptedServer) -> Result<Self, Self::Error> {
        let url = raw.url;
        let default_port = match url.scheme() {
            "https" => 443,
            "quic" => DOQ_PORT,
            _ => {
                return Err(format!(
                    "'{url}': DNS over HTTPS needs an https:// URL, DNS over QUIC a quic:// one"
                ));
            }
        };
        if url.scheme() == "quic" && (!matches!(url.path(), "" | "/") || url.query().is_some()) {
            return Err(format!("'{url}': DNS over QUIC has no path or query"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(format!("'{url}': no user or password in the URL"));
        }
        let tls_name = url
            .host_str()
            .ok_or_else(|| format!("'{url}' has no host"))?
            .to_owned();
        let port = url.port().unwrap_or(default_port);
        Ok(EncryptedServer {
            address: SocketAddr::new(raw.address, port),
            tls_name,
            url,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Cache {
    /// Memory for cached answers, in MiB; 0 disables the cache.
    #[serde(deserialize_with = "ranged::<_, 0, 1024>")]
    pub size_mb: u32,
    #[serde(deserialize_with = "ranged::<_, 0, 604_800>")]
    pub min_ttl: u32,
    #[serde(deserialize_with = "ranged::<_, 0, 604_800>")]
    pub max_ttl: u32,
    /// How long after expiring an answer may still be served when no
    /// upstream server answers; 0 for never.
    #[serde(deserialize_with = "ranged::<_, 0, 168>")]
    pub serve_stale_hours: u32,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            size_mb: 32,
            min_ttl: 0,
            max_ttl: 86_400,
            serve_stale_hours: 24,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Blocking {
    pub response: BlockResponse,
    #[serde(deserialize_with = "ranged::<_, 0, 86_400>")]
    pub ttl: u32,
    /// 0: only at start, and when a Reload changes the sources.
    #[serde(deserialize_with = "ranged::<_, 0, 8760>")]
    pub refresh_hours: u32,
    pub lists: Vec<Source>,
    pub allowlists: Vec<Source>,
    /// Inline rules, in any list syntax.
    pub block: Vec<String>,
    pub allow: Vec<String>,
}

impl Default for Blocking {
    fn default() -> Self {
        Blocking {
            response: BlockResponse::Zero,
            ttl: 300,
            refresh_hours: 24,
            lists: Vec::new(),
            allowlists: Vec::new(),
            block: Vec::new(),
            allow: Vec::new(),
        }
    }
}

impl Blocking {
    /// No source listed twice, and every inline rule a rule.
    fn validate(&self) -> Result<(), Error> {
        for (key, sources) in [
            ("blocking.lists", &self.lists),
            ("blocking.allowlists", &self.allowlists),
        ] {
            if let Some(i) = first_repeat(sources) {
                return Err(invalid(format!("{key}[{i}]"), "is listed twice"));
            }
        }
        for (key, rules) in [
            ("blocking.block", &self.block),
            ("blocking.allow", &self.allow),
        ] {
            for (i, rule) in rules.iter().enumerate() {
                let parsed = crate::rules::parse_line(rule);
                if parsed.rules.is_empty() || parsed.skipped > 0 {
                    return Err(invalid(
                        format!("{key}[{i}]"),
                        format!(
                            "'{rule}' is not a rule (a domain, *.domain, ||domain^ or a hosts or dnsmasq line)"
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// How blocked names are answered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    /// `0.0.0.0` / `::`, and an empty answer for other types.
    #[default]
    Zero,
    Nxdomain,
}

/// Where a list is loaded from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum Source {
    Url(Url),
    File(PathBuf),
}

impl TryFrom<String> for Source {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.contains("://") {
            let url = Url::parse(&text).map_err(|e| format!("invalid URL '{text}': {e}"))?;
            return match url.scheme() {
                "http" | "https" => Ok(Source::Url(url)),
                other => Err(format!(
                    "'{text}': lists come from http(s):// URLs or files, not {other}://"
                )),
            };
        }
        if text.trim().is_empty() {
            return Err("a list source must not be empty".to_owned());
        }
        Ok(Source::File(PathBuf::from(text)))
    }
}

impl From<Source> for String {
    fn from(source: Source) -> String {
        match source {
            Source::Url(url) => url.into(),
            Source::File(path) => path.to_string_lossy().into_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Local {
    #[serde(deserialize_with = "ranged::<_, 0, 86_400>")]
    pub ttl: u32,
    pub private_names: PrivateNames,
    /// Hostnames for the network's own devices; `*.name` for every name
    /// below. In file order: the first name for an address answers its PTR.
    #[serde(deserialize_with = "unique_names")]
    pub records: IndexMap<RecordName, Addresses>,
    /// Zones whose names go to a server of their own (plain DNS).
    #[serde(deserialize_with = "unique_names")]
    pub forward: IndexMap<ZoneName, DnsAddr>,
}

impl Default for Local {
    fn default() -> Self {
        Local {
            ttl: 300,
            private_names: PrivateNames::Nxdomain,
            records: IndexMap::new(),
            forward: IndexMap::new(),
        }
    }
}

/// What happens to Private names no local record answers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivateNames {
    #[default]
    Nxdomain,
    /// Send them to the upstream servers like any other name.
    Forward,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    pub level: LogLevel,
    pub format: LogFormat,
    /// One line per query: client, name, type, Outcome, duration.
    pub queries: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
    Debug,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http {
    /// `GET /metrics`, and `GET /sync` on an origin (ADR-0001).
    pub listen: Vec<HttpAddr>,
}

/// What an instance is to sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Runs alone: no sync section.
    Alone,
    Origin,
    Replica,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::Alone => "none",
            Role::Origin => "origin",
            Role::Replica => "replica",
        })
    }
}

/// Where the Policy settings come from (ADR-0001).
#[derive(Debug, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase", deny_unknown_fields)]
pub enum Sync {
    /// Serves its Policy settings to replicas.
    Origin { secret: Secret },
    /// Takes its Policy settings from `origin`.
    Replica {
        secret: Secret,
        /// The origin's HTTP port, e.g. `http://192.168.1.5:5380`.
        origin: OriginUrl,
        #[serde(
            default = "default_interval_secs",
            deserialize_with = "ranged::<_, 1, 86_400>"
        )]
        interval_secs: u32,
        #[serde(default = "default_state_dir")]
        state_dir: PathBuf,
    },
}

fn default_interval_secs() -> u32 {
    60
}

fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/lib/zinkhole")
}

// ---------------------------------------------------------------------------
// Values

/// An address with a port, the DNS port when none is given:
/// `"192.168.1.1"`, `"192.168.1.1:5353"`, `"fd00::1"`, `"[fd00::1]:5353"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsAddr(pub SocketAddr);

impl FromStr for DnsAddr {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = SocketAddr::from_str(text) {
            return Ok(DnsAddr(address));
        }
        // An IPv6 address may come bracketed even without a port: "[::1]".
        let bare = text
            .strip_prefix('[')
            .and_then(|t| t.strip_suffix(']'))
            .unwrap_or(text);
        IpAddr::from_str(bare)
            .map(|ip| DnsAddr(SocketAddr::new(ip, DNS_PORT)))
            .map_err(|_| format!("'{text}' is not an IP address with optional port"))
    }
}

impl TryFrom<String> for DnsAddr {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        DnsAddr::from_str(&text)
    }
}

impl From<DnsAddr> for String {
    fn from(address: DnsAddr) -> String {
        address.0.to_string()
    }
}

/// An HTTP listen address, which must give its port: `"0.0.0.0:5380"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct HttpAddr(pub SocketAddr);

impl TryFrom<String> for HttpAddr {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        SocketAddr::from_str(&text).map(HttpAddr).map_err(|_| {
            format!("'{text}' needs to be an IP address with a port, e.g. 0.0.0.0:{HTTP_PORT}")
        })
    }
}

/// A network (`"192.168.0.0/16"`) or a single address (`"192.168.1.10"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Network(pub IpNet);

impl Network {
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        self.0.contains(&address)
    }
}

impl TryFrom<String> for Network {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if let Ok(net) = IpNet::from_str(&text) {
            return Ok(Network(net.trunc()));
        }
        IpAddr::from_str(&text)
            .map(|ip| Network(IpNet::from(ip)))
            .map_err(|_| {
                format!("'{text}' is not a network (e.g. 192.168.0.0/16) or an IP address")
            })
    }
}

/// One address or a list of them, at most [`MAX_ADDRESSES`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct Addresses(pub Vec<IpAddr>);

impl<'de> Deserialize<'de> for Addresses {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AddressesVisitor;

        impl<'de> Visitor<'de> for AddressesVisitor {
            type Value = Addresses;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "an IP address or a list of at most {MAX_ADDRESSES}")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                let ip = IpAddr::from_str(value)
                    .map_err(|_| E::custom(format!("'{value}' is not an IP address")))?;
                Ok(Addresses(vec![ip]))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut addresses = Vec::new();
                while let Some(text) = seq.next_element::<String>()? {
                    let ip = IpAddr::from_str(&text)
                        .map_err(|_| de::Error::custom(format!("'{text}' is not an IP address")))?;
                    if addresses.len() == MAX_ADDRESSES {
                        return Err(de::Error::custom(format!(
                            "more than {MAX_ADDRESSES} addresses"
                        )));
                    }
                    addresses.push(ip);
                }
                if addresses.is_empty() {
                    return Err(de::Error::custom("needs at least one address"));
                }
                Ok(Addresses(addresses))
            }
        }

        deserializer.deserialize_any(AddressesVisitor)
    }
}

/// A name in the config, as its own type: lowercase, without a trailing
/// dot, and valid by `$rule`. `$noun` is what the error calls it; with
/// `wildcard`, `*.name` stands for every name below `name`.
macro_rules! config_name {
    ($(#[$doc:meta])* $type:ident, $noun:literal, wildcard: $wildcard:literal, rule: $rule:path) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
        #[serde(into = "String")]
        pub struct $type(String);

        impl $type {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl FromStr for $type {
            type Err = String;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                checked_name(text, $noun, $wildcard, $rule).map($type)
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<$type> for String {
            fn from(name: $type) -> String {
                name.0
            }
        }
    };
}

config_name!(
    /// A local record's name, a hostname: lowercase, without a trailing
    /// dot, optionally `*.name` for every name below `name`.
    RecordName,
    "hostname",
    wildcard: true,
    rule: name::check_hostname
);

config_name!(
    /// A forwarded zone's name, such as `lan`, `1.168.192.in-addr.arpa` or
    /// `_msdcs.corp.lan`: a zone is any name, not only a hostname.
    ZoneName,
    "zone",
    wildcard: false,
    rule: name::check
);

/// `text` lowercased and without its trailing dot, if `rule` finds it
/// valid, after `*.` if a `wildcard` may stand there.
fn checked_name(
    text: &str,
    noun: &str,
    wildcard: bool,
    rule: fn(&str) -> Result<(), String>,
) -> Result<String, String> {
    let name = name::lowercase(text);
    if name.is_empty() {
        return Err("a name must not be empty".to_owned());
    }
    let checked = if wildcard {
        name.strip_prefix("*.").unwrap_or(&name)
    } else {
        &name
    };
    rule(checked).map_err(|why| format!("'{text}' is not a valid {noun}: {why}"))?;
    Ok(name)
}

/// A sync origin's URL: `http(s)://host:port`, and nothing more. The URL is
/// logged, so it must not hold anything secret.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "Url")]
pub struct OriginUrl(pub Url);

impl TryFrom<Url> for OriginUrl {
    type Error = String;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        // The errors do not repeat the URL: it may hold a password.
        let example = format!("e.g. http://192.168.1.5:{HTTP_PORT}");
        if !matches!(url.scheme(), "http" | "https") || url.host().is_none() {
            return Err(format!(
                "the origin is an http:// URL with a host, {example}"
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(format!(
                "the origin's URL takes no user or password: remove them ({example})"
            ));
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
            return Err(format!(
                "the origin's URL is its host and port only: remove the path, query and fragment ({example})"
            ));
        }
        Ok(OriginUrl(url))
    }
}

/// The shared Sync secret: 256 random bits, written as 64 hex digits
/// (`zinkhole secret` makes one). Never printed.
pub struct Secret(SecretBox<[u8; Secret::LEN]>);

impl Secret {
    pub const LEN: usize = 32;

    #[must_use]
    pub fn expose(&self) -> &[u8; Secret::LEN] {
        self.0.expose_secret()
    }

    /// True if both are the same secret; in constant time, so the
    /// comparison says nothing about where they differ.
    #[must_use]
    pub fn same_as(&self, other: &Secret) -> bool {
        self.expose()
            .iter()
            .zip(other.expose())
            .fold(0u8, |differ, (a, b)| differ | (a ^ b))
            == 0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = secrecy::SecretString::deserialize(deserializer)?;
        let mut bytes = [0u8; Secret::LEN];
        crate::hex::decode_into(text.expose_secret().trim(), &mut bytes).map_err(|_| {
            de::Error::custom(format!(
                "the secret must be {} hex digits (256 bits); make one with `zinkhole secret`",
                Secret::LEN * 2
            ))
        })?;
        Ok(Secret(SecretBox::new(Box::new(bytes))))
    }
}

// ---------------------------------------------------------------------------
// Deserialization helpers

/// An integer between `MIN` and `MAX`, inclusive, checked while parsing so the
/// error names the line.
fn ranged<'de, D: Deserializer<'de>, const MIN: u32, const MAX: u32>(
    deserializer: D,
) -> Result<u32, D::Error> {
    let value = i64::deserialize(deserializer)?;
    u32::try_from(value)
        .ok()
        .filter(|v| (MIN..=MAX).contains(v))
        .ok_or_else(|| de::Error::custom(format!("{value} is not between {MIN} and {MAX}")))
}

/// A table keyed by names that must stay distinct once normalized, so that
/// `"NAS.lan"` and `"nas.lan"` are an error instead of one silently winning.
/// Keeps the file's order.
fn unique_names<'de, D, K, V>(deserializer: D) -> Result<IndexMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: FromStr<Err = String> + std::hash::Hash + Eq + fmt::Display,
    V: Deserialize<'de>,
{
    struct UniqueVisitor<K, V>(PhantomData<(K, V)>);

    impl<'de, K, V> Visitor<'de> for UniqueVisitor<K, V>
    where
        K: FromStr<Err = String> + std::hash::Hash + Eq + fmt::Display,
        V: Deserialize<'de>,
    {
        type Value = IndexMap<K, V>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a table of names")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut entries = IndexMap::new();
            while let Some(text) = map.next_key::<String>()? {
                let key = K::from_str(&text).map_err(de::Error::custom)?;
                let value = map.next_value()?;
                if entries.contains_key(&key) {
                    return Err(de::Error::custom(format!("'{key}' is defined twice")));
                }
                entries.insert(key, value);
            }
            Ok(entries)
        }
    }

    deserializer.deserialize_map(UniqueVisitor(PhantomData))
}

// ---------------------------------------------------------------------------
// Tests

#[cfg(test)]
mod tests {
    use super::*;

    const UPSTREAM: &str = "[upstream]\nservers = [\"9.9.9.9\"]\n";
    const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn parse(text: &str) -> Config {
        Config::parse(text).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The error for `text`, which must contain `fragment`.
    fn expect_error(text: &str, fragment: &str) {
        let error = Config::parse(text)
            .expect_err("the config should be rejected")
            .to_string();
        assert!(
            error.contains(fragment),
            "expected '{fragment}' in:\n{error}"
        );
    }

    #[test]
    fn the_example_config_is_valid() {
        let config = parse(include_str!("../config.example.toml"));
        assert_eq!(config.upstream.servers.len(), 3);
    }

    #[test]
    fn a_minimal_config_takes_the_defaults() {
        let config = parse(UPSTREAM);
        assert_eq!(config.server.listen.len(), 2);
        assert!(
            config
                .server
                .allow_clients
                .iter()
                .any(|n| n.contains("192.168.1.1".parse().unwrap()))
        );
        assert!(
            !config
                .server
                .allow_clients
                .iter()
                .any(|n| n.contains("8.8.8.8".parse().unwrap()))
        );
        assert_eq!(config.upstream.timeout_ms, 2000);
        assert_eq!(config.upstream.max_in_flight, 64);
        assert_eq!(config.cache.size_mb, 32);
        assert_eq!(config.policy_settings(), PolicySettings::default());
        assert!(config.http.is_none() && config.sync.is_none());
    }

    #[test]
    fn upstream_servers_are_plain_dns_dns_over_https_or_quic() {
        let config = parse(
            r#"[upstream]
servers = [
  { url = "https://dns.quad9.net/dns-query", address = "9.9.9.9" },
  "192.168.1.1",
  "[fd00::1]:5353",
]"#,
        );
        let UpstreamServer::Https(doh) = &config.upstream.servers[0] else {
            panic!("DoH expected")
        };
        assert_eq!(doh.tls_name, "dns.quad9.net");
        assert_eq!(doh.address, "9.9.9.9:443".parse().unwrap());
        assert_eq!(doh.url.path(), "/dns-query");
        let quic = parse(
            r#"[upstream]
servers = [
  { url = "quic://dns.adguard-dns.com", address = "94.140.14.14" },
  { url = "quic://doq.example:8853", address = "2001:db8::1" },
]"#,
        );
        let [UpstreamServer::Quic(first), UpstreamServer::Quic(second)] =
            quic.upstream.servers.as_slice()
        else {
            panic!("DoQ expected")
        };
        assert_eq!(first.tls_name, "dns.adguard-dns.com");
        assert_eq!(first.address, "94.140.14.14:853".parse().unwrap());
        assert_eq!(second.address, "[2001:db8::1]:8853".parse().unwrap());
        assert_eq!(
            config.upstream.servers[1],
            UpstreamServer::Plain(DnsAddr("192.168.1.1:53".parse().unwrap()))
        );
        assert_eq!(
            config.upstream.servers[2],
            UpstreamServer::Plain(DnsAddr("[fd00::1]:5353".parse().unwrap()))
        );
    }

    #[test]
    fn upstream_errors() {
        expect_error("[upstream]\nservers = []\n", "at least one upstream server");
        expect_error(
            "[upstream]\nservers = [\"dns.google\"]\n",
            "not an IP address",
        );
        expect_error(
            "[upstream]\nservers = [{ url = \"http://dns.quad9.net/dns-query\", address = \"9.9.9.9\" }]\n",
            "needs an https:// URL",
        );
        expect_error(
            "[upstream]\nservers = [{ url = \"quic://dns.adguard-dns.com/dns-query\", address = \"94.140.14.14\" }]\n",
            "no path",
        );
        expect_error(
            "[upstream]\nservers = [{ url = \"https://dns.quad9.net/dns-query\" }]\n",
            "address",
        );
        expect_error(
            "[upstream]\nservers = [{ url = \"https://x.example/q\", address = \"9.9.9.9\", sni = \"y\" }]\n",
            "unknown field",
        );
        expect_error(
            "[upstream]\nservers = [\"9.9.9.9\"]\ntimeout_ms = 5\n",
            "not between 100 and 30000",
        );
        expect_error(
            "[upstream]\nservers = [\"9.9.9.9\"]\nmax_in_flight = 0\n",
            "not between 1 and 1024",
        );
        expect_error(
            "[upstream]\nservers = [\"127.0.0.1\"]\n",
            "this server itself",
        );
        expect_error(
            "[upstream]\nservers = [\"9.9.9.9\", \"1.1.1.1\", \"9.9.9.9:53\"]\n",
            "upstream.servers[2]: is listed twice",
        );
        expect_error(
            "[upstream]\nservers = [\"9.9.9.9\"]\n[blocking]\nallowlists = [\"/a.txt\", \"/a.txt\"]\n",
            "blocking.allowlists[1]: is listed twice",
        );
    }

    #[test]
    fn errors_from_parsing_name_the_line() {
        let error = Config::parse("[upstream]\nservers = [\"9.9.9.9\"]\n\n[cache]\nmin_ttl = -1\n")
            .expect_err("rejected")
            .to_string();
        assert!(error.contains("line 5"), "{error}");
    }

    #[test]
    fn unknown_keys_and_sections_are_errors() {
        expect_error(
            &format!("{UPSTREAM}[server]\nworkers = 4\n"),
            "unknown field `workers`",
        );
        expect_error(
            &format!("{UPSTREAM}[metrics]\nlisten = [\"0.0.0.0:9153\"]\n"),
            "unknown field `metrics`",
        );
    }

    #[test]
    fn local_records_take_one_address_or_a_list() {
        let config = parse(&format!(
            "{UPSTREAM}[local.records]\n\"NAS.lan.\" = \"192.168.1.10\"\n\"*.apps.lan\" = [\"192.168.1.11\", \"fd00::11\"]\n"
        ));
        let local = config.local.expect("local");
        let names: Vec<&str> = local.records.keys().map(RecordName::as_str).collect();
        assert_eq!(names, ["nas.lan", "*.apps.lan"], "in file order");
        assert_eq!(local.records.values().map(|a| a.0.len()).sum::<usize>(), 3);
    }

    #[test]
    fn local_record_errors() {
        expect_error(
            &format!("{UPSTREAM}[local.records]\n\"nas.lan\" = \"999.1.1.1\"\n"),
            "not an IP address",
        );
        expect_error(
            &format!("{UPSTREAM}[local.records]\n\"bad_host!\" = \"10.0.0.1\"\n"),
            "not a valid hostname",
        );
        expect_error(
            &format!(
                "{UPSTREAM}[local.records]\n\"nas.lan\" = \"10.0.0.1\"\n\"NAS.LAN\" = \"10.0.0.2\"\n"
            ),
            "defined twice",
        );
        let many: Vec<String> = (1..=17).map(|i| format!("\"10.0.0.{i}\"")).collect();
        expect_error(
            &format!(
                "{UPSTREAM}[local.records]\n\"nas.lan\" = [{}]\n",
                many.join(", ")
            ),
            "more than 16",
        );
        expect_error(
            &format!("{UPSTREAM}[local.records]\n\"nas.lan\" = []\n"),
            "at least one address",
        );
    }

    #[test]
    fn forwarded_zones_go_to_a_plain_dns_server() {
        let config = parse(&format!(
            "{UPSTREAM}[local.forward]\n\"lan\" = \"192.168.1.1\"\n\"1.168.192.in-addr.arpa\" = \"192.168.1.1:5353\"\n"
        ));
        let forward = config.local.expect("local").forward;
        assert_eq!(forward.len(), 2);
        // A zone is any name: underscores, which a hostname may not have.
        let config = parse(&format!(
            "{UPSTREAM}[local.forward]\n\"_MSDCS.corp.lan.\" = \"192.168.1.1\"\n"
        ));
        let zones: Vec<String> = config
            .local
            .expect("local")
            .forward
            .keys()
            .map(ToString::to_string)
            .collect();
        assert_eq!(zones, ["_msdcs.corp.lan"]);
        expect_error(
            &format!("{UPSTREAM}[local.forward]\n\"a b.lan\" = \"192.168.1.1\"\n"),
            "is not a valid zone",
        );
        expect_error(
            &format!("{UPSTREAM}[local.records]\n\"_nas.lan\" = \"192.168.1.10\"\n"),
            "is not a valid hostname",
        );
        expect_error(
            &format!("{UPSTREAM}[local.forward]\n\"lan\" = \"[::1]\"\n"),
            "this server itself",
        );
    }

    #[test]
    fn blocking_sources_are_urls_or_files() {
        let config = parse(&format!(
            "{UPSTREAM}[blocking]\nresponse = \"nxdomain\"\nlists = [\"https://example.com/hosts\", \"/etc/zinkhole/mine.txt\"]\n"
        ));
        let blocking = config.blocking.expect("blocking");
        assert_eq!(blocking.response, BlockResponse::Nxdomain);
        assert!(matches!(blocking.lists[0], Source::Url(_)));
        assert!(matches!(blocking.lists[1], Source::File(_)));
        expect_error(
            &format!("{UPSTREAM}[blocking]\nlists = [\"ftp://example.com/x\"]\n"),
            "not ftp://",
        );
        expect_error(
            &format!("{UPSTREAM}[blocking]\nresponse = \"refuse\"\n"),
            "unknown variant",
        );
        expect_error(
            &format!("{UPSTREAM}[blocking]\nblock = [\"ok.example\", \"not a domain\"]\n"),
            "blocking.block[1]",
        );
        expect_error(
            &format!("{UPSTREAM}[blocking]\nallow = [\"||x.example^$third-party\"]\n"),
            "blocking.allow[0]",
        );
        parse(&format!(
            "{UPSTREAM}[blocking]\nblock = [\"*.tracking.example\", \"||ads.example^\"]\n"
        ));
        // A hosts line blocks only with an address that leads nowhere.
        parse(&format!(
            "{UPSTREAM}[blocking]\nblock = [\"0.0.0.0 ads.example\"]\n"
        ));
        expect_error(
            &format!("{UPSTREAM}[blocking]\nblock = [\"93.184.216.34 www.example\"]\n"),
            "blocking.block[0]",
        );
    }

    #[test]
    fn the_http_port_must_not_take_the_dns_port() {
        parse(&format!("{UPSTREAM}[http]\nlisten = [\"0.0.0.0:5380\"]\n"));
        expect_error(
            &format!("{UPSTREAM}[http]\nlisten = [\"10.0.0.1:53\"]\n"),
            "takes port 53",
        );
        expect_error(
            &format!("{UPSTREAM}[http]\nlisten = [\"10.0.0.1\"]\n"),
            "with a port",
        );
        // Different addresses may share a port.
        parse(&format!(
            "[server]\nlisten = [\"10.0.0.1:53\"]\n{UPSTREAM}[http]\nlisten = [\"10.0.0.2:53\"]\n"
        ));
    }

    #[test]
    fn the_http_port_needs_an_address() {
        expect_error(
            &format!("{UPSTREAM}[http]\nlisten = []\n"),
            "http.listen: needs at least one address",
        );
        // An origin's [http] section without one is no section.
        expect_error(
            &format!(
                "{UPSTREAM}[http]\nlisten = []\n[sync]\nrole = \"origin\"\nsecret = \"{SECRET}\"\n"
            ),
            "http.listen: needs at least one address",
        );
    }

    #[test]
    fn sync_role_origin_or_replica() {
        let origin = parse(&format!(
            "{UPSTREAM}[http]\nlisten = [\"0.0.0.0:5380\"]\n[sync]\nrole = \"origin\"\nsecret = \"{SECRET}\"\n"
        ));
        let Some(Sync::Origin { secret }) = origin.sync else {
            panic!("origin expected")
        };
        assert_eq!(secret.expose()[0], 0x01);
        assert_eq!(format!("{secret:?}"), "Secret([redacted])");

        let replica = parse(&format!(
            "{UPSTREAM}[sync]\nrole = \"replica\"\norigin = \"http://192.168.1.5:5380\"\nsecret = \"{SECRET}\"\n"
        ));
        let Some(Sync::Replica {
            interval_secs,
            state_dir,
            ..
        }) = replica.sync
        else {
            panic!("replica expected")
        };
        assert_eq!(interval_secs, 60);
        assert_eq!(state_dir, PathBuf::from("/var/lib/zinkhole"));
    }

    #[test]
    fn sync_errors() {
        let http = "[http]\nlisten = [\"0.0.0.0:5380\"]\n";
        expect_error(
            &format!("{UPSTREAM}[sync]\nrole = \"origin\"\nsecret = \"{SECRET}\"\n"),
            "add an [http] section",
        );
        expect_error(
            &format!("{UPSTREAM}{http}[sync]\nrole = \"origin\"\nsecret = \"short\"\n"),
            "64 hex digits",
        );
        expect_error(
            &format!("{UPSTREAM}{http}[sync]\nrole = \"master\"\nsecret = \"{SECRET}\"\n"),
            "unknown variant",
        );
        expect_error(
            &format!(
                "{UPSTREAM}{http}[sync]\nrole = \"origin\"\nsecret = \"{SECRET}\"\ninterval_secs = 5\n"
            ),
            "unknown field",
        );
        expect_error(
            &format!(
                "{UPSTREAM}[sync]\nrole = \"replica\"\norigin = \"ftp://10.0.0.1\"\nsecret = \"{SECRET}\"\n"
            ),
            "http:// URL",
        );
        expect_error(
            &format!(
                "{UPSTREAM}[blocking]\nblock = [\"ads.example\"]\n[sync]\nrole = \"replica\"\norigin = \"http://10.0.0.1:5380\"\nsecret = \"{SECRET}\"\n"
            ),
            "from its origin",
        );
    }

    #[test]
    fn an_origin_url_is_a_host_and_port_and_nothing_secret() {
        let replica = |origin: &str| {
            format!(
                "{UPSTREAM}[sync]\nrole = \"replica\"\norigin = \"{origin}\"\nsecret = \"{SECRET}\"\n"
            )
        };
        for fine in [
            "http://10.0.0.1:5380",
            "http://10.0.0.1:5380/",
            "https://origin.lan",
        ] {
            parse(&replica(fine));
        }
        for (origin, fragment) in [
            ("http://user:hunter2@10.0.0.1:5380", "no user or password"),
            ("http://user@10.0.0.1:5380", "no user or password"),
            ("http://10.0.0.1:5380/sync", "remove the path"),
            ("http://10.0.0.1:5380/?token=hunter2", "remove the path"),
            ("http://10.0.0.1:5380/#hunter2", "remove the path"),
        ] {
            expect_error(&replica(origin), fragment);
            let error = Config::parse(&replica(origin))
                .expect_err("rejected")
                .to_string();
            assert!(!error.contains("hunter2"), "{error}");
        }
    }

    #[test]
    fn cache_ttls_must_be_in_order() {
        expect_error(
            &format!("{UPSTREAM}[cache]\nmin_ttl = 10\nmax_ttl = 5\n"),
            "cache.min_ttl",
        );
    }

    #[test]
    fn policy_settings_round_trip_through_toml() {
        let config = parse(&format!(
            "{UPSTREAM}[blocking]\nblock = [\"ads.example\"]\nlists = [\"https://example.com/l.txt\"]\n[local.records]\n\"nas.lan\" = \"10.0.0.10\"\n"
        ));
        let settings = config.policy_settings();
        let text = toml::to_string(&settings).expect("serialize");
        let back: PolicySettings = toml::from_str(&text).expect("deserialize");
        assert_eq!(back, settings);
    }
}
