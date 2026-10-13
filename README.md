# zinkhole

A minimal DNS blocker and local DNS server for home networks, in the spirit of
[blocky](https://github.com/0xERR0R/blocky), written in Zig with no
dependencies. It blocks ads and trackers using common blocklists, gives your
own devices and apps hostnames, and forwards everything else to upstream DNS
servers.

No web UI, no database, no state on disk: one static binary and one YAML file
(a sync replica keeps one file: its last synced settings).

## Features

- **Blocklists** from URLs or files, in any common format, auto-detected per
  line: hosts files, plain domains, `*.wildcards`, Adblock (`||domain^`,
  `@@||domain^` exceptions) and dnsmasq (`address=/domain/`). Allowlists and
  inline rules. Lists refresh in the background.
- **Local DNS**: `nas.lan: 192.168.1.10`, multiple IPv4/IPv6 addresses per
  name, `*.apps.lan` wildcards, automatic reverse (PTR) lookups.
- **Privacy**: private names (`.lan`, `.home.arpa`, `.internal`, single-label
  names, reverse lookups of private IPs) never leak upstream; client EDNS
  options (cookies, client subnet) are stripped before forwarding; Firefox's
  DNS-over-HTTPS canary is answered so it keeps using your resolver.
- **DNS over TLS** to upstream servers, so your ISP can neither read nor
  alter your queries. Connections are reused, so after the first query it is
  as fast as plain DNS.
- **Caching** of upstream answers (LRU, TTL-aware, bounded).
- UDP and TCP, IPv4 and IPv6, upstream failover, TCP fallback for large
  answers.
- Live reload with `SIGHUP`; local records apply instantly, and lists are
  re-downloaded only when their sources changed.
- **Two instances, one config**: a replica syncs its local records and
  blocking settings from an origin (see [Running two instances](#running-two-instances)).

## Build

Requires Zig 0.17.

```sh
zig build --release            # ReleaseSafe: optimized, bounds checks kept
zig build test                 # unit tests (offline)
zig build test -Dnetwork       # also DNS over TLS to a public server
zig build --release -Dtarget=aarch64-linux-musl -Dstrip=true   # e.g. Raspberry Pi 64-bit
zig build --release -Dtarget=arm-linux-musleabihf -Dstrip=true # Raspberry Pi 32-bit
```

Linux builds are static binaries of about 1 MB (`-Dstrip=true` drops the
debug info, which costs disk space only, not memory).

## Run

Try it in the foreground first (port 53 needs privileges, so pick another
port in `server.listen` for a quick test):

```sh
cp config.example.yaml config.yaml     # then edit it
./zig-out/bin/zinkhole --test -c config.yaml   # validate and load all lists
./zig-out/bin/zinkhole -c config.yaml
```

For permanent use, pick the setup that fits. Each runs zinkhole as an
unprivileged user that may only bind port 53; never run it as root.

|          | Debian, Ubuntu (systemd)       | Alpine (OpenRC)              | Docker                                 |
|----------|--------------------------------|------------------------------|----------------------------------------|
| Install  | `./deploy/install.sh`          | `./deploy/install.sh`        | `docker compose up -d --build`         |
| Config   | `/etc/zinkhole/config.yaml`    | `/etc/zinkhole/config.yaml`  | `./config.yaml`                        |
| Reload   | `systemctl reload zinkhole`    | `rc-service zinkhole reload` | `docker compose kill -s HUP zinkhole`  |
| Logs     | `journalctl -u zinkhole -f`    | `tail -f /var/log/messages`  | `docker compose logs -f`               |
| Tested on| Debian 13, systemd 257         | Alpine 3.24, OpenRC 0.63     | Docker 29, Compose 5.4                 |

### Debian, Ubuntu or Alpine: as a system service

Build the binary for the target machine, copy the repository (or just the
binary, `config.example.yaml` and `deploy/`) there, and run the installer as
root:

```sh
zig build --release -Dstrip=true -Dtarget=x86_64-linux-musl   # or aarch64-linux-musl
./deploy/install.sh                  # detects systemd or OpenRC
./deploy/install.sh --init openrc    # ...or choose: systemd, openrc
```

The installer copies the binary to `/usr/local/bin`, installs the CA
certificates package if it is missing, creates `/etc/zinkhole/config.yaml`
from the example (an existing config is never overwritten), and enables the
service. Edit the config, then start the service. Running the installer
again upgrades and restarts; `./deploy/install.sh --uninstall` removes the
service and binary but keeps the config.

- **systemd** ([deploy/zinkhole.service](deploy/zinkhole.service)): a
  throwaway dynamic user, read-only file system, syscall filter and other
  sandboxing (`systemd-analyze security zinkhole` rates it 1.6, "OK").
- **OpenRC** ([deploy/openrc/zinkhole](deploy/openrc/zinkhole)): a `zinkhole`
  user created on first start, restarted by supervise-daemon if it crashes,
  logs to syslog; `rc-service zinkhole stats` logs statistics.
- **Port 53 already in use?** `systemd-resolved` (default on Ubuntu, optional
  on Debian) listens on 127.0.0.53:53. Set `DNSStubListener=no` in
  `/etc/systemd/resolved.conf`, or listen on the LAN address only, e.g.
  `server.listen: ["192.168.1.5:53"]`.
- **Proxmox LXC with systemd:** the sandboxing needs the container's
  *nesting* feature (on by default for new unprivileged containers). Without
  it the service fails with status 226/NAMESPACE.

No Zig on the build machine? Docker can build the binary (use
`linux/arm64` for 64-bit ARM):

```sh
docker buildx build --platform linux/amd64 -t zinkhole --load .
mkdir -p zig-out/bin && docker create --name zinkhole-tmp zinkhole
docker cp zinkhole-tmp:/usr/local/bin/zinkhole zig-out/bin/ && docker rm zinkhole-tmp
```

### Docker

The default image is `FROM scratch`: just the static binary, CA certificates
and a config (about 2 MB). `--target alpine` builds a variant with a shell.

```sh
cp config.example.yaml config.yaml     # then edit it
docker compose up -d --build           # hardened: read-only, no capabilities
docker compose kill -s HUP zinkhole    # reload config.yaml
```

The image has a healthcheck (`zinkhole --healthcheck`, which asks the server
for `localhost`). On Docker Desktop for macOS or Windows, UDP clients appear
with public addresses and get `REFUSED`; for local testing there, add
`0.0.0.0/0` to `server.allow_clients`. Docker on Linux keeps real addresses.

### Running two instances

For redundancy, run zinkhole on two hosts and hand out both addresses (e.g.
via DHCP). One instance is the **origin**: you edit its config as usual. The
other is a **replica**: every minute it asks the origin for its `blocking` and
`local` sections and applies them like a reload. Each instance keeps its own
`server`, `upstream`, `cache` and `log` settings and downloads its own lists.

```yaml
# origin (its config also has the blocking and local sections)
sync:
  serve: ["192.168.1.5:5380"]          # HTTP, for replicas only
  secret: "…at least 32 random characters…"

# replica (no blocking or local sections: those come from the origin)
sync:
  origin: http://192.168.1.5:5380
  secret: "…the same secret…"
  interval: 60                          # seconds
```

Answers are signed with the shared secret over a fresh challenge per
request, so they cannot be forged or replayed on the LAN. A replica keeps the
last settings it accepted in `/var/lib/zinkhole/synced.yaml` and starts from
them if the origin is down. Reload the origin to publish a change; reload a
replica to sync right away. Changing an instance's `sync` section needs a
restart.

**Promoting a replica** if the origin is gone for good: append the state
file to its config (`cat /var/lib/zinkhole/synced.yaml >>
/etc/zinkhole/config.yaml`), replace `sync.origin` with `sync.serve`, and
restart. Make the old origin a replica before it comes back.

[deploy/sync/](deploy/sync/) has a Docker Compose setup with both roles and
an end-to-end test (`./deploy/sync/test.sh`). The design is in
[docs/adr/0002](docs/adr/0002-sync-replicas-from-an-origin.md).

### Signals

| Signal    | Effect                                                      |
|-----------|-------------------------------------------------------------|
| `SIGHUP`  | Reload the config file (server/upstream/cache/sync need restart); on a replica, also sync now |
| `SIGUSR1` | Log query statistics                                        |
| `SIGTERM` | Shut down cleanly                                           |

## Configuration

See [config.example.yaml](config.example.yaml), which documents every
setting. A minimal config only needs upstream servers:

```yaml
upstream:
  servers:
    - tls://9.9.9.9#dns.quad9.net          # DNS over TLS: address#certificate name
    - tls://149.112.112.112#dns.quad9.net
blocking:
  lists:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
local:
  records:
    nas.lan: 192.168.1.10
    "*.apps.lan": 192.168.1.20
```

The parser accepts a strict subset of YAML (mappings, lists, `[a, b]` flow
lists, quoted and plain scalars, comments). Unsupported or ambiguous syntax,
unknown keys and invalid values are reported with their line number instead of
being silently ignored.

## How a query is answered

1. Client not in `server.allow_clients` → `REFUSED`
2. Name in `local.records` (or PTR for one of their addresses) → local answer
3. Blocked by a list or inline rule, and not allowed → `0.0.0.0`/`::` or `NXDOMAIN`
4. Private or special-use name → `NXDOMAIN` (unless `private_names: forward`)
5. In the cache → cached answer, TTLs reduced by its age
6. Otherwise → forwarded upstream, then cached

A listed domain blocks itself and all of its subdomains; `*.example.com`
blocks only the subdomains. Allow rules always win over block rules. Blocked
names get an answer for every record type (empty for types other than A/AAAA),
so clients cannot get around a block through HTTPS/SVCB records.

## Design

| File | Responsibility |
|------|----------------|
| `main.zig` | CLI, startup, signals, running list loads in the background |
| `config.zig`, `yaml.zig` | YAML subset parser and validated, typed config |
| `server.zig`, `tcp.zig` | UDP/TCP listeners, fixed worker pool, TCP framing with deadlines |
| `resolver.zig` | The query pipeline above, statistics, query log |
| `policy.zig` | `Policy`: steps 2-4 of the pipeline, over the config's rules (rebuilt on reload) and `Lists` (downloaded) |
| `refresh.zig` | When lists load: refresh interval, retry backoff, timeouts |
| `sync.zig` | Sync: the origin's endpoint, signed fetches, the replica's state file |
| `domain_set.zig` | Compact domain set with subdomain matching |
| `blocklist.zig` | Line parser for all list formats, streaming loader (file/HTTPS) |
| `local.zig` | Local records, wildcards, reverse lookups, private zones |
| `cache.zig` | Bounded LRU response cache |
| `upstream.zig` | Failover over upstream servers; plain DNS with TCP fallback |
| `dot.zig` | DNS over TLS: pooled TLS connections, certificate checks (`dot.Tls`) |
| `dns.zig` | DNS wire format: parsing, building, TTL handling |

**Domain set.** Every domain is stored once in one byte array as
`[length][name]`, and a hash table maps the 4-byte offset of each entry to
two flags (match the name itself, match its subdomains). A lookup hashes the
query name and walks up its parent domains (`a.b.example.com`,
`b.example.com`, `example.com`, `com`): at most one hash lookup per label,
with no allocation. 255,000 domains take about 8 MB (~31 bytes each). Each set
uses a random hash seed, so list content cannot be crafted to degrade it.

**Threads and memory.** Each worker thread owns one fixed query buffer and
one fixed response buffer, so answering a query allocates nothing; only cache
insertions do, and the cache has a fixed capacity. The config policy and
lists are immutable once built; a reload builds new ones on the side and
swaps a pointer under a read-write lock that queries hold only for the
in-memory lookup, never during network I/O.

**DNS over TLS.** A TLS handshake costs several round trips, so each
upstream server keeps up to 4 idle connections open (about 52 KB each). A
connection carries one query at a time and is thrown away after any error,
so a reused connection never holds a stray answer. Connections idle for more
than 8 seconds are closed (Cloudflare and Quad9 close them after about 10),
and if a reused connection turns out to be closed, the query is retried once
on a new one. Servers are addressed by IP, so no name lookup is needed to
reach them (no bootstrap problem); the configured name is checked against the
certificate, which must chain to the system's CA certificates.

**List loading.** The server starts answering immediately with local records
and inline rules while lists download in the background. This also lets the
host resolve the list servers' names through zinkhole itself. Lists are
streamed line by line, never held in memory as a whole, and capped at 64 MiB
each. If a refresh fails partway, the previous complete lists stay in use and
the refresh is retried with exponential backoff. After a reload that changes
the lists, the new ones are used right away, even if some of them failed.

## Security

- Built in ReleaseSafe: bounds and integer overflow checks stay on. Every
  length read from a DNS message is checked before use; malformed packets get
  `FORMERR` or are dropped. The parsers are tested against random and mutated
  input, and the server has been run under ThreadSanitizer with concurrent
  queries and reloads. Pointer-stability locks make safe builds panic if a
  buffer that other code points into (the listener sockets workers use, the
  domain bytes a hash table reads) could be reallocated.
- Upstream queries can use DNS over TLS with certificate verification. For
  plain DNS upstreams: a fresh socket (random source port) and a random
  query ID per exchange, and only answers from the right address with the
  same ID and question are accepted.
- Only allowed client networks are answered (default: private ranges), so an
  accidentally exposed port is not an open resolver. Zone transfers and
  non-IN classes are refused.
- Lists are fetched over TLS with system CA verification (plain `http://`
  sources produce a warning), with size limits. TCP clients have idle
  deadlines and a per-connection query limit.
- The config parser rejects YAML anchors/aliases (no "billion laughs") and
  duplicate keys; the file is limited to 1 MiB.
- Sync answers are signed (HMAC-SHA256) over a random challenge from the
  replica, and the state file is checked against the same signature. The sync
  endpoint is read-only and serves only `blocking` and `local`, never the
  secret; anyone on the LAN can read it, but those clients can already query
  the local records.

## Limitations

- No DNS over HTTPS upstream, and zinkhole itself answers plain DNS only
  (inside a LAN, encrypting the client side adds little).
- Regular-expression rules and per-client blocking groups are not supported.
- Lists are downloaded again on every start (nothing is stored on disk).
