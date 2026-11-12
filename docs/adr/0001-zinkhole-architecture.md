---
status: accepted
---

# zinkhole's architecture

zinkhole is a DNS blocker and local DNS server for a home network: one static binary and one config file, on a Raspberry Pi, in a Proxmox container or in Docker. It parses untrusted packets from the LAN and untrusted lists from the internet, and it is the network's resolver: when it is down, nothing on the network finds anything. The vocabulary is in `CONTEXT.md`.

This record describes the design as the code has it today. It replaces the earlier ADRs 0001 to 0006.

**Decision.** zinkhole is written in Rust on `tokio` and uses libraries wherever one fits. The crates named below are what is in use today, not a limit on what may be used.

## Answering queries

- **Listeners** (`server.rs`, `listen.rs`). A UDP socket and a TCP listener on each `server.listen` address, on `tokio` sockets set up with `socket2`, with a task per query. Binding the addresses and letting connections in (allowed clients, the limits) is one piece of code for the DNS and the HTTP listeners.
  - UDP queries over 4096 bytes are dropped.
  - TCP serves at most 16 connections, 4 per client address; a connection is closed after 5 seconds without a whole query, after a write that takes as long, and after 100 queries.
  - An IPv6 address that shares its port with an IPv4 one is bound IPv6-only; where IPv6 is unavailable, IPv6 addresses are skipped with a warning.
- **Allowed clients.** Only clients in `server.allow_clients` are answered (by default loopback, private, link-local and CGNAT ranges). A UDP query from anyone else is dropped unread and unanswered, because its source is unproven, and counts as `refused`; a TCP connection from anyone else is closed on arrival.
- **Query pipeline** (`resolver.rs`, `policy.rs`). In order: allowed client, local record (and its reverse lookup), blocked name, forwarded zone, private name, cache, upstream server. The first step that applies decides the answer.
  - Messages that are not queries are dropped; other opcodes get NOTIMP; zone transfers and classes other than IN get REFUSED.
  - `use-application-dns.net`, Firefox's DNS-over-HTTPS canary, is answered NXDOMAIN unless a local record has it or an allow rule matches it.
  - A single-label name's NS, SOA, DS and DNSKEY records go upstream; other private names get NXDOMAIN unless `local.private_names = "forward"`.
- **Policy** (`policy.rs`, `local.rs`, `rules.rs`, `domain_set.rs`). Built from the Policy settings and held in `arc-swap`, so a Reload, a Sync or a Refresh replaces it without holding up queries. A plain domain matches itself and its subdomains, a wildcard only the subdomains, and an allow rule wins over a block rule. Lists may be plain domains, wildcards, Adblock (`||domain^`, `@@||domain^`), hosts files or dnsmasq lines; a hosts or dnsmasq line blocks only when its address leads nowhere (unspecified or loopback).
- **Forwarded zones** (`local.forward`). Names at and below a zone go to that zone's server over plain DNS; the longest matching zone wins. A zone is any name (`_msdcs.corp.lan`), where a local record is a hostname. Local records and rules still apply first, and a private name in a forwarded zone is forwarded. There is no failover and no DNSSEC validation for a zone's server.
- **Aliases of blocked names.** Every upstream answer, cache hit and stale answer has its CNAME targets checked: if a target is a blocked name and no allow rule matches the name asked for, the client gets the block response. The upstream answer is cached as it came and checked again on each hit, so a change of rules applies at once.
- **Cache** (`cache.rs`). `moka`, keyed by the question, the client's EDNS, DO and CD, and the forwarded zone's server if there is one. `cache.size_mb` bounds it, each entry weighing an estimate of what it takes in memory (an answer is kept decoded, several times its encoded size). Only NOERROR and NXDOMAIN answers that are not truncated are kept, with TTLs clamped to `cache.min_ttl` and `cache.max_ttl`. An expired entry is kept `cache.serve_stale_hours` longer, counted from when it was last stored, and served with TTL 30 when no upstream server answers (RFC 8767).
- **Upstream servers** (`upstream.rs`). DNS over HTTPS, DNS over QUIC and plain DNS, on `hickory-net`'s client transports with `hickory-proto` for the wire format.
  - An encrypted server is `{ url, address }`: the URL's host is checked against the certificate and the address avoids a bootstrap lookup. One connection per server carries every query in flight.
  - Plain DNS uses a fresh socket and source port per exchange, and TCP when the answer is truncated.
  - Servers are tried in the configured order, starting with the one that answered last; after a failover the first server is tried again once a minute. `upstream.timeout_ms` covers everything one server does for one query. REFUSED counts as a failure.
  - What goes upstream is the question, the client's CD and DO, and a fresh OPT record without options, always with RD and AD set. Client cookies and client subnet stay on the network.
- **DNSSEC.** By default the flags are passed through and a validating upstream server refuses forged data. With `upstream.dnssec = "validate"`, hickory's validator checks upstream answers from the root trust anchors; an answer whose signatures do not hold is SERVFAIL with the Outcome `bogus`, is never cached and is never replaced by a stale answer.
- **Concurrency.** A semaphore with `upstream.max_in_flight` permits (default 64) bounds upstream exchanges. A cache miss that finds none free gets a stale answer or SERVFAIL at once, so local and cached answers never wait behind upstream ones. An upstream SERVFAIL or no answer also falls back to a stale answer.
- **Answer size.** A UDP answer is at most what the client advertises, and never more than 1232 bytes; larger ones are truncated and the client retries over TCP.

## Settings

- **Config** (`config.rs`). One TOML file of at most 1 MiB, parsed into `serde` structs with `deny_unknown_fields`. Values are typed (addresses, networks, names, URLs, ranged integers), so most errors name their line; checks across settings run afterwards. `zinkhole check` runs the same validation.
- **Policy settings.** The `[blocking]` and `[local]` sections. `settings.rs` puts them in force: in the Policy at once, and their list sources and interval for the Refresh.
- **Reload** (SIGHUP, `serve.rs`). The file is read again. Policy settings, the log level and the query log apply at once; changes to `server`, `upstream`, `cache`, `http`, `log.format` and `sync` are reported as needing a restart, and a changed sync role is refused.
- **Lists** (`lists.rs`, `client.rs`). Loaded with `reqwest` on `rustls`, or from files, and streamed through the parser so a list is never held whole. A source fails after 2 minutes, above 64 MiB decompressed, on any status but 200, or when an `https://` source redirects to `http://`; a whole load ends after 10 minutes. A plain `http://` source loads with a warning.
- **Refresh** (`refresh.rs`). Queries are answered from the start with local records and inline rules while the first load runs. Lists load again every `blocking.refresh_hours`; an incomplete load is retried after 60 seconds, doubling each time up to the interval; a Reload or Sync that changes the sources cancels a running load and starts a new one.

## The HTTP port

- `[http] listen` starts one listener per address (`http.rs`), with an `axum` router served by `hyper` over HTTP/1. The port in the docs and installers is 5380.
- It serves `GET /metrics` always, and `GET /sync` on an origin. Other paths are 404, other methods 405.
- Only allowed clients are served; others have their connection closed on arrival. A request head must arrive within 2 seconds, a connection serves one request and lasts at most 10 seconds, and at most 16 connections are served at once, 4 of them from one client address.
- **Metrics** (`metrics.rs`). Prometheus text format, written by zinkhole's own code: queries per Outcome, answer times and failures per upstream server, and the state of the lists, the cache, sync and the instance. An encrypted upstream server is named by its scheme, host and address, without the path of its URL. Kept in memory only.

## Sync

- **Roles.** `sync.role = "origin"` or `"replica"`, with the same `sync.secret` on both: 256 bits from `zinkhole secret`, held in a `secrecy` type and compared in constant time. An origin needs an `[http]` section. A replica's file has no `[blocking]` or `[local]`; it takes `sync.origin` (the origin's scheme, host and port, and nothing else: the URL is logged), `sync.interval_secs` (default 60) and `sync.state_dir` (default `/var/lib/zinkhole`).
- **What is synced.** The origin's Policy settings, as TOML, at most 1 MiB. Lists are not synced, only their sources; each instance loads its own. Everything else stays in each instance's own file.
- **The exchange** (`sync.rs`). A replica polls `GET /sync` every interval, and at once on a Reload, with a fresh random 32-byte nonce in `x-zinkhole-nonce`, the ETag of the settings it has in `If-None-Match`, and in `x-zinkhole-proof` a proof that it has the secret: an HMAC-SHA256 over the nonce and that ETag, under a key derived from the secret. The origin answers only a request whose proof holds; any other gets a 401 and does not count as a replica. Replicas from before this proof are refused too, so replicas are updated before their origin.
- **The answer.** Always a 200. The origin derives a one-time key from the secret and the nonce with HKDF-SHA256 and seals the payload with XChaCha20-Poly1305: either "unchanged" or the settings. The ETag is an HMAC-SHA256 of the settings keyed from the secret, and is the associated data. An answer therefore opens only for the request it was made for, and the settings cannot be read on the way. A replica takes "unchanged" only when the answer's ETag is the one it holds. The crates are `hkdf`, `hmac`, `sha2` and `chacha20poly1305`.
- **Applying.** A replica checks synced settings as it would its own file, including that no forwarded zone points at itself, and then puts them in force like a Reload. Settings it refuses leave the last ones in place, are logged once per version and show in the Metrics. It warns after three failed syncs in a row and keeps answering from the settings it has.
- **State file.** After each accepted change the replica writes `synced-settings` in its state directory: sealed under a key of its own derived from the secret, written atomically, mode 0600. It starts from that file when the origin is down, and checks at start that the directory is writable.
- The origin lists the clients it answered, up to 64, in its Metrics.

## Running it

- **CLI** (`main.rs`). `clap` subcommands: `serve`, `check [--lists]`, `healthcheck [ADDR]` and `secret`. The config comes from `-c/--config`, `ZINKHOLE_CONFIG` or `/etc/zinkhole/config.toml`.
- **Signals.** SIGTERM and SIGINT stop the server and cancel queries in flight; SIGHUP reloads; SIGUSR1 logs the queries per Outcome and the cache entries.
- **Background tasks.** The list Refresh, the Sync loop and the HTTP port run beside the DNS listeners. If one of them ends on its own (a panic), the server stops with an error, so that systemd, OpenRC or Docker starts all of it again. An HTTP port whose listeners cannot be served at all is logged, and DNS goes on without it.
- **Logging.** `tracing` to stderr, as text or JSON, with an optional line per query.
- **TLS.** `rustls` with the `ring` provider and the Mozilla roots compiled in (`webpki-roots`), so no system certificate store is needed.

## Build, release and install

- **Code settings.** `Cargo.toml` forbids `unsafe` in zinkhole's own code and denies `unwrap`, `expect`, `panic!`, indexing and `todo!` outside tests, with `clippy::pedantic` as warnings. Release builds keep overflow checks and unwind on panic, so a panic ends one query's task and not the server.
- **Toolchain.** The latest stable Rust (`rust-toolchain.toml`), edition 2024. `Cargo.lock` is committed, `cargo-deny` checks advisories, licenses and sources, and Dependabot keeps crates current.
- **CI** (`.github/workflows/ci.yml`, `deploy/ci/release.sh`). Every push runs formatting, clippy with `-D warnings`, the tests, `cargo-deny` and `shellcheck`, and builds static musl binaries for x86_64 and aarch64 on runners of each architecture. A tag `v<version>` that matches `Cargo.toml` publishes a GitHub release with the binaries, `update.sh`, the deploy bundle and `SHA256SUMS`, and pushes a multi-arch image to GHCR.
- **Installer** (`deploy/install.sh`). Checks the config with the new binary, installs the service (a sandboxed systemd unit with `DynamicUser`, or OpenRC as the user `zinkhole`), starts it, and puts the previous binary back if the new one does not answer within 15 seconds. The config file is installed mode 644 so the unprivileged service can read it.
- **Docker.** The default image is `FROM scratch` with the binary and the example config, running as uid 65532 with `zinkhole healthcheck` as its health check; an `alpine` target adds a shell.
- **Proxmox** (`deploy/proxmox/`). `ct/zinkhole.sh` runs on the node on the Proxmox VE community scripts' engine (`community-scripts/core`), which creates the container. `install/zinkhole-install.sh` runs inside it: it downloads the latest release, checks it against `SHA256SUMS`, asks for the sync role and writes the config. An origin's secret is not printed; the script says where to read it. `update` in the container runs the latest release's `update.sh`, which checks the new binary against the current config before installing it.
