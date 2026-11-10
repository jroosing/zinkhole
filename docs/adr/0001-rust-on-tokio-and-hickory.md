---
status: accepted
---

# Rust, on tokio and hickory

zinkhole is a DNS blocker and local DNS server for home networks: one static binary and one config file, on a Raspberry Pi, in a Proxmox container or in Docker. It parses untrusted packets from the LAN and untrusted lists from the internet, and it is the network's resolver: when it is down, nothing on the network can find anything.

**Decision.** zinkhole is written in Rust, idiomatically, using existing libraries freely. The domain is in `CONTEXT.md`.

## What it is built from

- **Runtime and DNS.** `tokio`; the `hickory` crates as building blocks: `hickory-proto` for the wire format and DNSSEC, `hickory-net`'s client transports for the upstream servers. The UDP and TCP listeners are zinkhole's own, on plain `tokio` sockets: the query pipeline works on bytes, and the listeners must drop UDP queries from disallowed clients unanswered, limit TCP connections per client, and bind IPv6-only next to IPv4. zinkhole's own code keeps the query pipeline, the cache, the failover order and the Metrics. `hickory-resolver` is not used: its own cache and server ordering would replace exactly those.
- **Upstream servers.** DNS over HTTPS (`{ url = "https://…", address = "…" }`) or DNS over QUIC (`{ url = "quic://…", address = "…" }`): the URL's name is checked against the certificate, the address avoids a bootstrap lookup, and one connection per server carries every query in flight. Plain DNS for forwarded zones and local resolvers. DNS over TLS is not offered: HTTPS and QUIC cover encrypted upstreams.
- **DNSSEC.** Flags are passed through by default, and a validating upstream refuses forged data. With `upstream.dnssec = "validate"`, hickory validates answers from the upstream servers, asking them with CD set so they hand over what they have (RFC 6840, 5.9). Bogus answers are SERVFAIL with their own Outcome, `bogus`, and are never cached or replaced by a stale answer. An upstream SERVFAIL, or a DS or DNSKEY lookup that gets no answer, is no answer, not bogus. Forwarded zones are not validated.
- **Concurrency.** A task per query. A `Semaphore` with `upstream.max_in_flight` permits bounds upstream exchanges; a cache miss that finds none free gets a stale answer or SERVFAIL at once, so local and cached answers never wait behind upstream ones and an outage cannot grow memory. TCP connections have their own limits and an idle timeout.
- **Config.** TOML, parsed into `serde` structs with `deny_unknown_fields`. Local records are a table with quoted names (`"nas.lan" = "192.168.1.10"`); the sync role is explicit (`sync.role = "origin" | "replica"`). The default blocklist is HaGeZi Pro.
- **Metrics.** Prometheus text format at `GET /metrics` on the HTTP port (ADR-0006): counters since start, a histogram of upstream answer times, gauges for the state of lists, cache and sync.
- **CLI.** `clap` subcommands: `serve`, `check [--lists]`, `healthcheck [ADDR]`, `secret`. The config comes from `-c/--config`, `ZINKHOLE_CONFIG` or `/etc/zinkhole/config.toml`.
- **Logging.** `tracing` to stderr, text by default or JSON; level and query log reloadable on SIGHUP; SIGUSR1 logs a summary read from the metric counters. Secrets are `secrecy` types and never logged.
- **HTTP and downloads.** `axum` for the HTTP port, `reqwest` with `rustls` for lists, `moka` for the cache.

## Safety and quality bar

- `#![forbid(unsafe_code)]`; all `unsafe` lives in dependencies.
- Release builds keep overflow checks (`overflow-checks = true`): integer overflow panics instead of wrapping. Panics unwind: one query's task dies, the server does not.
- Lints deny `unwrap_used`, `expect_used`, `panic`, `indexing_slicing` and `todo` outside tests, and warn on `clippy::pedantic`; CI runs `clippy -D warnings` and `rustfmt --check`.
- `Cargo.lock` is committed; `cargo-deny` checks advisories, licenses and sources; Dependabot keeps crates current. TLS is `rustls` with the `ring` provider, and the Mozilla root certificates are compiled in, so no system certificate store is needed.
- The toolchain tracks the latest **stable** Rust (`rust-toolchain.toml`), edition 2024.
- Builds are static musl binaries for **x86_64 and aarch64 only**, each built natively on GitHub's runners. Releases carry `SHA256SUMS`; a multi-arch image is published to GHCR.

## Hardening

- Queries from clients outside `server.allow_clients` are **dropped over UDP** (the source is unproven: an answer would let anyone aim packets at a third party), and their TCP connections are closed on arrival, so they never hold one. Dropped queries count as `refused`.
- At most 16 TCP connections, 4 per client address. The HTTP port gives a request head 2 seconds and serves at most 16 connections, one request each.
- The cache is bounded by size in bytes (`cache.size_mb`).
- A malformed upstream answer is SERVFAIL; it never skips the alias check.
- UDP answers are capped at 1232 bytes, so they are not fragmented; larger ones go over TCP.
- The query sent upstream depends only on the question and the client's DO and CD: client cookies and client subnet never leave the network, and one client's flags cannot change what the cache gives others.

## Considered options

- **YAML** for the config. Reads better for local records, but `serde_yaml` is unmaintained and TOML is the Rust ecosystem's own format.
- **`hickory-resolver`** for upstream. Much less code, but different failover, caching and serve-stale behaviour.
- **`hickory-server`** for the listeners. It does not drop UDP from disallowed clients unanswered, limit TCP per client, or bind IPv6-only next to IPv4 as needed, and the pipeline already works on bytes.
- **A fixed pool of worker tasks** instead of a task per query. More code for the same guarantee a semaphore gives.
- **DNS over TLS** upstream. One encrypted protocol with a dedicated port is enough, and QUIC offers it with lower latency; DoT would be a third variant to test and maintain.
