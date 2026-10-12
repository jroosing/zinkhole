# dnsblock

A minimal DNS blocker and local DNS server for home networks, in the spirit of
[blocky](https://github.com/0xERR0R/blocky), written in Zig with no
dependencies. It blocks ads and trackers using common blocklists, gives your
own devices and apps hostnames, and forwards everything else to upstream DNS
servers.

No web UI, no database, no state on disk: one static binary and one YAML file.

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

## Build

Requires Zig 0.17.

```sh
zig build --release            # ReleaseSafe: optimized, bounds checks kept
zig build test                 # unit tests
zig build --release -Dtarget=aarch64-linux-musl -Dstrip=true   # e.g. Raspberry Pi 64-bit
zig build --release -Dtarget=arm-linux-musleabihf -Dstrip=true # Raspberry Pi 32-bit
```

Linux builds are static binaries of about 1 MB (`-Dstrip=true` drops the
debug info, which costs disk space only, not memory).

## Run

```sh
cp config.example.yaml config.yaml     # then edit it
./zig-out/bin/dnsblock --test -c config.yaml   # validate and load all lists
./zig-out/bin/dnsblock -c config.yaml
```

Port 53 needs privileges. On Linux, use the hardened systemd unit in
[deploy/dnsblock.service](deploy/dnsblock.service) (unprivileged dynamic user
with only `CAP_NET_BIND_SERVICE`), or grant the capability to the binary:
`setcap cap_net_bind_service=+ep /usr/local/bin/dnsblock`. Do not run it as
root.

| Signal    | Effect                                                     |
|-----------|------------------------------------------------------------|
| `SIGHUP`  | Reload the config file (server/upstream/cache need restart) |
| `SIGUSR1` | Log query statistics                                       |
| `SIGTERM` | Shut down cleanly                                          |

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
| `main.zig` | CLI, startup, signals, background list refresh scheduling |
| `config.zig`, `yaml.zig` | YAML subset parser and validated, typed config |
| `server.zig`, `tcp.zig` | UDP/TCP listeners, fixed worker pool, TCP framing with deadlines |
| `resolver.zig` | The query pipeline above, statistics, query log |
| `rules.zig` | `Rules` (from config, rebuilt on reload) and `Lists` (downloaded) |
| `domain_set.zig` | Compact domain set with subdomain matching |
| `blocklist.zig` | Line parser for all list formats, streaming loader (file/HTTPS) |
| `local.zig` | Local records, wildcards, reverse lookups, private zones |
| `cache.zig` | Bounded LRU response cache |
| `upstream.zig` | Forwarding with failover; plain DNS with TCP fallback |
| `dot.zig` | DNS over TLS: pooled TLS connections, certificate checks |
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
insertions do, and the cache has a fixed capacity. Rules and lists are
immutable once built; a reload builds new ones on the side and swaps a
pointer under a read-write lock that queries hold only for the in-memory
lookup, never during network I/O.

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
host resolve the list servers' names through dnsblock itself. Lists are
streamed line by line, never held in memory as a whole, and capped at 64 MiB
each. If a refresh fails partway, the previous complete lists stay in use and
the refresh is retried with exponential backoff.

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

## Limitations

- No DNS over HTTPS upstream, and dnsblock itself answers plain DNS only
  (inside a LAN, encrypting the client side adds little).
- Regular-expression rules and per-client blocking groups are not supported.
- Lists are downloaded again on every start (nothing is stored on disk).
