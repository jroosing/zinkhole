# zinkhole

A DNS blocker and local DNS server for home networks, in the spirit of
[blocky](https://github.com/0xERR0R/blocky), written in Rust. It blocks ads
and trackers using common blocklists, gives your own devices and apps
hostnames, and forwards everything else to upstream DNS servers over
encrypted DNS over HTTPS.

No web UI, no database, no state on disk: one static binary and one TOML
file (a sync replica keeps one more file: its last synced settings).

## Features

- **Blocklists** from URLs or files, in any common format, auto-detected per
  line: hosts files, plain domains, `*.wildcards`, Adblock (`||domain^`,
  `@@||domain^` exceptions) and dnsmasq (`address=/domain/`). Allowlists and
  inline rules. Lists refresh in the background. Answers that alias (CNAME) a
  blocked domain are blocked too, so trackers cannot hide behind a
  first-party name.
- **Local DNS**: `"nas.lan" = "192.168.1.10"`, several IPv4 and IPv6
  addresses per name, `*.apps.lan` wildcards, automatic reverse (PTR)
  lookups. Zones such as `lan` can be forwarded to your router, so its DHCP
  clients' names resolve while everything else goes to encrypted upstream
  servers.
- **Privacy**: private names (`.lan`, `.home.arpa`, `.internal`, single-label
  names, reverse lookups of private IPs) never leak upstream; client EDNS
  options (cookies, client subnet) are stripped before forwarding; Firefox's
  DNS-over-HTTPS canary is answered so it keeps using your resolver.
- **DNS over HTTPS or DNS over QUIC** to upstream servers, so your ISP can
  neither read nor alter your queries. One HTTP/2 or QUIC connection per
  server carries many queries at once. Plain DNS works too, for a local
  resolver or forwarded zones.
- **Caching** of upstream answers (TTL-aware, bounded by size). When no
  upstream server answers, answers that expired in the last 24 hours are
  served anyway (RFC 8767), so a short outage goes unnoticed for names
  already in use.
- **DNSSEC**: flags are passed through, so a validating upstream (Quad9 and
  Cloudflare both validate) refuses forged data; with
  `upstream.dnssec = "validate"`, zinkhole checks the signatures itself, from
  the root zone's keys, and answers forged data with SERVFAIL.
- UDP and TCP, IPv4 and IPv6, upstream failover. Upstream servers are tried
  in the order listed, starting with the one that answered last; after a
  failover, one query a minute tries the first server again, and it takes
  over once it answers.
- **Metrics** in Prometheus format: queries per outcome, upstream answer
  times and failures, and the state of the lists, cache and sync (see
  [Metrics](#metrics)).
- A per-query log (`log.queries`), a summary on `SIGUSR1`, and a health
  check for containers.
- Live reload with `SIGHUP`: local records and rules apply at once, and lists
  are downloaded again only when their sources changed.
- **Proxmox in one command**: a community script creates the LXC container,
  installs zinkhole in it, and gives it an `update` command (see
  [Proxmox LXC](#proxmox-lxc)).
- **Two instances, one config**: a replica syncs its local records and
  blocking settings from an origin, sealed with a shared secret (see
  [Running two instances](#running-two-instances)).

## Quick start

```sh
docker run -d --name zinkhole -p 53:53/udp -p 53:53/tcp ghcr.io/jroosing/zinkhole
dig @127.0.0.1 example.com
```

The image's config forwards to Quad9 and Cloudflare over DNS over HTTPS and
blocks with the [HaGeZi Pro](https://github.com/hagezi/dns-blocklists) list.
For your own config, see [Docker](#docker).

## Command line

```sh
zinkhole serve               # run the server
zinkhole check               # validate the config (no network), then exit
zinkhole check --lists       # also load every list once and count them
zinkhole healthcheck [ADDR]  # ask a running server for "localhost" (default: where the
                             # config listens, loopback for a wildcard; else 127.0.0.1:53)
zinkhole secret              # print a new secret for sync
zinkhole --version
```

The config is `-c/--config <path>`, else `$ZINKHOLE_CONFIG`, else
`/etc/zinkhole/config.toml`. Exit codes: 0 OK, 1 an invalid config, a
failed list or an unhealthy server, 2 wrong usage.

| Signal    | Effect |
|-----------|--------|
| `SIGHUP`  | Reload the config file; on a replica, also sync now. Server, upstream, cache, HTTP and sync settings need a restart (a reload names any it sees changed) |
| `SIGUSR1` | Log the queries per outcome since start and the cache entries |
| `SIGTERM`, `SIGINT` | Shut down, canceling queries in flight |

## Configuration

[config.example.toml](config.example.toml) documents every setting. Only
the upstream servers are required; a small config looks like:

```toml
[upstream]
servers = [
  { url = "https://dns.quad9.net/dns-query", address = "9.9.9.9" },
  { url = "https://cloudflare-dns.com/dns-query", address = "1.0.0.1" },
]

[blocking]
lists = ["https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"]

[local.records]
"nas.lan" = "192.168.1.10"
"*.apps.lan" = "192.168.1.20"
```

A DNS-over-HTTPS server is its URL plus the address to connect to: the URL's
name is checked against the server's certificate, and the address means no
name lookup is needed to reach it (zinkhole is the resolver). DNS over QUIC
(RFC 9250) takes the same form with a `quic://` URL, such as
`{ url = "quic://dns.adguard-dns.com", address = "94.140.14.14" }`. Unknown keys,
invalid values and contradicting settings are errors, reported with their
line or setting.

## Run

For permanent use, pick the setup that fits. Each runs zinkhole as an
unprivileged user that may only bind port 53; never run it as root.

|          | Debian, Ubuntu (systemd)       | Alpine (OpenRC)              | Docker                                 |
|----------|--------------------------------|------------------------------|----------------------------------------|
| Install  | `./deploy/install.sh`          | `./deploy/install.sh`        | `docker compose up -d`                 |
| Config   | `/etc/zinkhole/config.toml`    | `/etc/zinkhole/config.toml`  | `./config.toml`                        |
| Reload   | `systemctl reload zinkhole`    | `rc-service zinkhole reload` | `docker compose kill -s HUP zinkhole`  |
| Logs     | `journalctl -u zinkhole -f`    | `tail -f /var/log/messages`  | `docker compose logs -f`               |
| Tested on| Debian 13, systemd 257         | Alpine 3.24, OpenRC          | Docker 29                              |

On Proxmox, one command creates the container for you: see
[Proxmox LXC](#proxmox-lxc).

### Debian, Ubuntu or Alpine: as a system service

Take the binary for the machine from the
[latest release](https://github.com/jroosing/zinkhole/releases/latest)
(`zinkhole-x86_64-linux-musl` or `zinkhole-aarch64-linux-musl`, static, so
they run on any Linux), with `zinkhole-deploy.tar.gz` and `SHA256SUMS`:

```sh
base=https://github.com/jroosing/zinkhole/releases/latest/download
bin=zinkhole-$(uname -m)-linux-musl
curl -fsSLO $base/$bin && curl -fsSLO $base/zinkhole-deploy.tar.gz && curl -fsSLO $base/SHA256SUMS
grep -E " ($bin|zinkhole-deploy.tar.gz)\$" SHA256SUMS | sha256sum -c -    # must print "OK" twice
chmod +x $bin && tar -xzf zinkhole-deploy.tar.gz
./deploy/install.sh --binary ./$bin          # as root; detects systemd or OpenRC
```

The installer copies the binary to `/usr/local/bin`, creates
`/etc/zinkhole/config.toml` from the example (an existing config is kept),
and enables the service. Edit the config, check it with `zinkhole check
--lists`, then start the service. Or bring your own: `--config FILE` checks
it with the new binary and installs it, and `--start` starts the service at
once. Running the installer again upgrades, restarts, and waits until
zinkhole answers (it fails if it does not within 15 seconds);
`./deploy/install.sh --uninstall` removes the service and binary but keeps
the config.

- **systemd** ([deploy/zinkhole.service](deploy/zinkhole.service)): a
  throwaway dynamic user, read-only file system, syscall filter and other
  sandboxing (`systemd-analyze security zinkhole` rates it 1.6, "OK").
- **OpenRC** ([deploy/openrc/zinkhole](deploy/openrc/zinkhole)): a `zinkhole`
  user created on first start, restarted by supervise-daemon if it crashes,
  logs to syslog; `rc-service zinkhole stats` logs a summary.
- **Port 53 already in use?** `systemd-resolved` (default on Ubuntu, optional
  on Debian) listens on 127.0.0.53:53. Set `DNSStubListener=no` in
  `/etc/systemd/resolved.conf`, or listen on the LAN address only, e.g.
  `listen = ["192.168.1.5:53"]` under `[server]`.
- **Proxmox LXC with systemd:** the sandboxing needs the container's
  *nesting* feature. Without it the service fails with status 226/NAMESPACE.

### Proxmox LXC

One small container per node is the natural fit: zinkhole needs about 128 MB
of RAM (HaGeZi Pro takes about 30 MB) and a few MB of disk. The installer is
a [Proxmox VE community script](https://community-scripts.org): it runs on
the community scripts' own engine and works like theirs (for example
[AdGuard Home's](https://community-scripts.org/scripts/adguard)). On a
Proxmox node, as root:

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/jroosing/zinkhole/main/deploy/proxmox/ct/zinkhole.sh)"
```

It asks for the container OS (**Debian 13** or **Alpine**, which is smaller),
then offers the engine's usual menu: **Default settings** (DHCP, 1 core,
256 MB RAM and 2 GB disk on Debian, 128 MB and 1 GB on Alpine, unprivileged)
or **Advanced settings** (container ID, hostname, static or DHCP address,
IPv6, VLAN, bridge, DNS, root password, SSH, resources, and so on). Then it:

1. creates the container, upgrades its packages, and installs the latest
   zinkhole release, checked against the release's `SHA256SUMS`;
2. asks for the **role** (below) and writes a working
   `/etc/zinkhole/config.toml` (Quad9 over DNS over HTTPS with Cloudflare as
   a fallback, HaGeZi Pro, [metrics](#metrics) on the HTTP port, 5380);
3. starts zinkhole, waits until it answers, and prints how to use it.

The **role** sets up [two instances](#running-two-instances) for you:
*standalone* (the default), *origin* (a secret is made with `zinkhole
secret`, and shown at the end with the command for a replica) or *replica*
(asks for the origin's URL and secret). Run it on each node. To answer up
front, set `ZINKHOLE_ROLE`, and for a replica `ZINKHOLE_ORIGIN` and
`ZINKHOLE_SECRET`; the engine's own settings take its `var_*` variables, and
`mode=default` skips its menu:

```sh
# Unattended: a replica of an origin at 192.168.1.5
mode=default var_os=debian ZINKHOLE_ROLE=replica \
ZINKHOLE_ORIGIN=http://192.168.1.5:5380 ZINKHOLE_SECRET=<the origin's secret> \
  bash -c "$(curl -fsSL https://raw.githubusercontent.com/jroosing/zinkhole/main/deploy/proxmox/ct/zinkhole.sh)"
```

Afterwards, test with `dig @<address> example.com`, hand out the container's
address as the DNS server (typically in your router's DHCP settings), and
never forward port 53 from the internet to it.

- **Static or DHCP?** Clients need a DNS server whose address never changes.
  Choose a static address in the advanced settings, or give the container a
  fixed lease on your DHCP server (its MAC address is in `pct config <id>`).
  The HTTP port listens on all of the container's addresses, so a changed
  address keeps working; like DNS, it answers only clients in
  `server.allow_clients`.
- **IPv6**: with IPv6 on (advanced settings), zinkhole also listens on IPv6,
  and the installer adds the container's own IPv6 network to
  `server.allow_clients`: that list normally covers only private addresses,
  so clients using a global IPv6 address would be refused. If no network is
  found yet (SLAAC can be slow), the installer says so; add your prefix
  yourself.
- **`update`**: inside the container (or `pct exec <id> -- update`) upgrades
  the OS packages, then zinkhole if a newer release exists. The new version
  must accept your config (`zinkhole check`), the old binary is kept as
  `/usr/local/bin/zinkhole.old`, and it is put back if the new one does not
  answer within 15 seconds. With several nodes, **update the replicas before
  the origin**.
- **Trust**: the engine comes from the community scripts' repository and the
  install script from this one's `main` branch, both unpinned, as for every
  community script; zinkhole itself comes from a release and is checked
  against its `SHA256SUMS`.
- **Changing the config**: `pct enter <id>`, edit
  `/etc/zinkhole/config.toml`, then `systemctl reload zinkhole` (Alpine:
  `rc-service zinkhole reload`).
- **Backups**: the container holds only the config (and a replica's synced
  state), so a normal Proxmox backup of it is enough.

### Docker

The image is `FROM scratch`: the static binary, which carries its own root
certificates, and a config, 9 MB in all. It runs as an unprivileged user and
has a health check (`zinkhole healthcheck`). Images for `linux/amd64` and
`linux/arm64` are published as `ghcr.io/jroosing/zinkhole:<version>` and
`:latest`.

```sh
cp config.example.toml config.toml     # then edit it
docker compose up -d                   # hardened: read-only, no capabilities
docker compose kill -s HUP zinkhole    # reload config.toml
```

[docker-compose.yml](docker-compose.yml) builds the image from this
repository; use `image: ghcr.io/jroosing/zinkhole` instead to skip the
build. `docker build --target alpine .` builds a variant with a shell, for
debugging.

- **Docker Desktop** (macOS, Windows) may show clients with public
  addresses, which get no answer; for local testing there, add `0.0.0.0/0`
  to `server.allow_clients`. Docker on Linux keeps real addresses.
- **Metrics:** add an `[http]` section with `listen = ["0.0.0.0:5380"]` and
  publish the port (`-p 5380:5380`).
- **Port 53 taken on the host** (for example by `systemd-resolved`)? Publish
  one address only, e.g. `"192.168.1.5:53:53/udp"`.
- **A sync replica** saves its last settings in `/var/lib/zinkhole`; mount a
  volume there. [deploy/sync/](deploy/sync/) is a complete example with an
  origin and a replica.

### Running two instances

For redundancy, run zinkhole on two hosts and hand out both addresses (e.g.
via DHCP). One instance is the **origin**: you edit its config as usual. The
other is a **replica**: every minute it asks the origin for its `[blocking]`
and `[local]` sections and applies them like a reload. Each instance keeps
its own `[server]`, `[upstream]`, `[cache]` and `[log]` settings and
downloads its own lists.

```toml
# origin (its config also has the [blocking] and [local] sections)
[http]
listen = ["192.168.1.5:5380"]        # GET /sync for replicas, and /metrics
[sync]
role = "origin"
secret = "<64 hex digits, from `zinkhole secret`>"

# replica (no [blocking] or [local]: those come from the origin)
[sync]
role = "replica"
origin = "http://192.168.1.5:5380"
secret = "<the same secret>"
interval_secs = 60
```

Each answer is sealed (XChaCha20-Poly1305) under a one-time key derived from
the secret and a fresh nonce from the replica, so nobody without the secret
can read the settings, change them, or replay an old answer. A replica
checks the settings as if they were in its own file, keeps the last ones it
accepted in a sealed file in `/var/lib/zinkhole` (or `sync.state_dir`), and
starts from them if the origin is down. Reload the origin to publish a
change; reload a replica to sync at once. Changing an instance's role needs a
restart.

[deploy/sync/](deploy/sync/) has a Docker Compose setup with both roles and
an end-to-end test (`./deploy/sync/test.sh`). The design is in
[docs/adr/0002](docs/adr/0002-sync-replicas-from-an-origin.md) and
[docs/adr/0003](docs/adr/0003-sync-answers-sealed-with-an-aead.md).

### Metrics

With an `[http]` section, zinkhole serves Prometheus metrics, on the same
port as an origin's settings for its replicas:

```sh
curl http://192.168.1.5:5380/metrics
```

| Metric | Meaning |
|--------|---------|
| `zinkhole_queries_total{outcome}` | Queries since start, by [how they were answered](#how-a-query-is-answered): `local`, `blocked`, `private`, `cached`, `forwarded`, `failed`, `bogus`, `refused`, `invalid` |
| `zinkhole_upstream_answer_duration_seconds{server}` | Histogram of upstream answer times; its `_count` is the answers |
| `zinkhole_upstream_failures_total{server}` | Timeouts, connection errors, malformed answers and `REFUSED` |
| `zinkhole_upstream_preferred{server}` | 1 for the server asked first |
| `zinkhole_blocked_domains`, `zinkhole_allowed_domains` | Domains in the lists in force |
| `zinkhole_local_records`, `zinkhole_cache_entries` | Configured local records; answers in the cache |
| `zinkhole_list_loaded{kind,index,source}` | 1 if the source loaded completely; `kind` is `block` or `allow`, `index` its place in that list |
| `zinkhole_lists_last_complete_load_timestamp_seconds`, `zinkhole_lists_next_load_timestamp_seconds` | When the lists loaded, and load next |
| `zinkhole_sync_last_success_timestamp_seconds`, `zinkhole_sync_failures_in_a_row`, `zinkhole_sync_rejected`, `zinkhole_sync_state_file_ok` | On a replica: `rejected` is 1 while it refuses the origin's settings (keeping its last ones), `state_file_ok` 0 if it cannot save them |
| `zinkhole_sync_replica_last_fetch_timestamp_seconds{replica}` | On an origin, per replica |
| `zinkhole_build_info{version}`, `zinkhole_start_time_seconds` | The running instance |

Counts live in memory: a restart starts from zero, a reload keeps them.
Upstream attempts are counted per server: when the first server times out and
the second answers, each gets one. Only clients in `server.allow_clients` can
read the metrics; they hold no domain names, and list sources are shown
without credentials or query strings.

## How a query is answered

1. Client not in `server.allow_clients` → dropped (UDP); its TCP connection
   is closed on arrival
2. Name in `local.records` (or PTR for one of their addresses) → local answer
3. Blocked by a list or inline rule, and not allowed → `0.0.0.0`/`::` or
   `NXDOMAIN`
4. Name in a zone of `local.forward` → as 6–7, with the zone's server
5. Private or special-use name → `NXDOMAIN` (unless
   `private_names = "forward"`). The zone records (NS, SOA, DS, DNSKEY) of
   a single label, such as `com` or `lan`, go upstream: validating clients
   need them, and they say nothing about hosts
6. In the cache → cached answer, TTLs reduced by its age
7. Otherwise → forwarded upstream, then cached; if no upstream server
   answers (or one answers SERVFAIL), an answer that expired less than
   `cache.serve_stale_hours` ago, with TTL 30. With `upstream.dnssec = "validate"`, an answer whose
   signatures do not hold is `SERVFAIL` (`bogus`), never cached
   and never replaced by a stale one

A listed domain blocks itself and all of its subdomains; `*.example.com`
blocks only the subdomains. An upstream or cached answer whose CNAME records
point at a blocked name gets the block response instead (CNAME cloaking),
unless an allow rule matches the name asked for; this is checked on every
answer, so a reload that changes the rules applies at once. Allow rules
always win over block rules. Blocked names get an answer for every record
type (empty for types other than A/AAAA), so clients cannot get around a
block through HTTPS/SVCB records. Negative answers carry an SOA record, so
clients cache them for `blocking.ttl` or `local.ttl`.

## Build

Needs the newest stable Rust (`rust-toolchain.toml` picks it).

```sh
cargo build --release          # target/release/zinkhole
cargo test                     # offline: stub servers on loopback, TLS with test certificates
cargo clippy --all-targets -- -D warnings
cargo deny check               # licenses, advisories, sources
```

A static Linux binary: `cargo build --release --target
x86_64-unknown-linux-musl` (or `aarch64-…`) on a machine of that
architecture with `musl-tools`; or `docker build .`, which builds one inside
the image. Releases contain `x86_64` and `aarch64`; 32-bit platforms are not
supported.

### Releasing

A release is a tag; GitHub Actions does the rest (see
[.github/workflows/ci.yml](.github/workflows/ci.yml)). The version lives in
`Cargo.toml` only.

```sh
# 1. Bump `version` in Cargo.toml, commit.
# 2. Tag exactly v<version> and push the tag.
git tag v3.0.0 && git push origin main v3.0.0
```

On a `v*` tag the pipeline runs the checks, **fails if the tag does not
match `Cargo.toml`**, builds static `x86_64` and `aarch64` musl binaries on
runners of each architecture, packs the container updater (`update.sh`),
`zinkhole-deploy.tar.gz` (the installer, service files and example config)
and the `LICENSE`, writes `SHA256SUMS`, publishes everything as a GitHub
release, and pushes the image to GHCR. Downloads work without a login, at
stable links such as
`https://github.com/jroosing/zinkhole/releases/latest/download/SHA256SUMS`.
The steps are in [deploy/ci/release.sh](deploy/ci/release.sh), so they also
run locally (`publish --dry-run`).

## Design

| Module | Responsibility |
|--------|----------------|
| `main.rs`, `serve.rs` | The CLI; wiring the parts together, signals, Reload |
| `config.rs` | The TOML config: typed, validated |
| `server.rs` | UDP and TCP listeners: a task per query, TCP limits |
| `resolver.rs` | The query pipeline above, query counting and log |
| `policy.rs` | The Policy: local records, rules, forwarded zones and private names, and blocked aliases (ADR-0004) |
| `local.rs`, `domain_set.rs`, `rules.rs`, `name.rs` | Local records and reverse lookups; domain sets with subdomain matching; the list line parser |
| `answer.rs` | Building responses: local, blocked, negative, truncated |
| `cache.rs` | The answer cache (moka), with serve-stale |
| `upstream.rs` | Failover; plain DNS with TCP fallback; DNS over HTTPS and QUIC (hickory) |
| `lists.rs`, `refresh.rs` | Streaming list downloads; when lists load |
| `settings.rs` | Putting Policy settings in force, for a Reload, a Sync or a start |
| `sync.rs` | The origin's endpoint, the replica's fetch and state file, sealing |
| `http.rs`, `metrics.rs` | The HTTP port; the Prometheus metrics |
| `logging.rs`, `tls.rs` | Log output; TLS with the compiled-in roots |

The reasoning behind the larger design decisions is in [docs/adr/](docs/adr/)
(the foundations in [ADR-0001](docs/adr/0001-rust-on-tokio-and-hickory.md)),
and [CONTEXT.md](CONTEXT.md) defines the terms used in the code and docs.

**Concurrency.** Every query is a tokio task. Local records, blocked and
private names and cache hits are answered without waiting on anything. At
most `upstream.max_in_flight` upstream exchanges run at once; a cache miss
beyond that is answered SERVFAIL at once, so in an upstream outage local
names and cached answers keep answering instantly and memory cannot grow.
The Policy and lists are immutable once built: a reload or a list refresh
builds new ones on the side and swaps them in atomically, and each query
works on one snapshot.

**List loading.** The server answers immediately with local records and
inline rules while lists download in the background, which also lets the
host resolve the list servers' names through zinkhole itself. Lists are
streamed line by line, never held whole, and capped at 64 MiB each. A source
that has not finished after 2 minutes counts as failed. If a refresh fails
partway, the previous complete lists stay in use and the refresh is retried
with backoff; after a reload that changes the lists, the new ones are used
right away, even if some failed.

## Security

- Rust, with `unsafe` code forbidden in zinkhole itself and panicking
  shortcuts (`unwrap`, indexing) denied by lint outside tests. Release builds
  keep integer overflow checks. The list parser is tested with property
  tests; DNS messages are parsed by hickory.
- Upstream: DNS over HTTPS or QUIC with certificate checks against the
  Mozilla roots compiled into the binary. Plain DNS: a fresh source port and random query
  ID per exchange, and only answers from the right address with the same ID
  and question are accepted.
- Only allowed client networks are answered (default: private ranges), so
  an accidentally exposed port is not an open resolver; UDP queries from
  others are dropped, not answered, so the server cannot be used to reflect
  traffic. TCP: at most 16 connections, 4 per client address, closed after 5
  seconds idle or 100 queries. Zone transfers and non-IN classes are
  refused.
- Lists are fetched over TLS (plain `http://` sources produce a warning, and
  an `https://` list that redirects to `http://` is refused), with size and
  time limits.
- Sync: sealed with XChaCha20-Poly1305 under keys derived (HKDF-SHA256) from
  a 256-bit secret, per request (ADR-0003); the state file is sealed too and
  readable by its owner only. The secret is never logged.
- The HTTP port answers only `server.allow_clients`, gives a request head 2
  seconds, serves one request per connection and at most 16 at once. The
  config file is limited to 1 MiB.

## Limitations

- zinkhole answers plain DNS only (inside a LAN, encrypting the client side
  adds little).
- DNSSEC validation is off by default (a validating upstream does it); turn
  it on with `upstream.dnssec = "validate"`, which needs a correct clock.
  Blocked and local answers are unsigned, which only matters to clients that
  validate on their own.
- Regular-expression rules and per-client blocking groups are not supported.
- Lists are downloaded again on every start (nothing is stored on disk).

## License

[MIT](LICENSE): free to use, copy, modify and distribute, including
commercially. The only condition is that the copyright notice and license
text stay with the code.
