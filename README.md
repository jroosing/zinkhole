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
  inline rules. Lists refresh in the background. Answers that alias (CNAME) a
  blocked domain are blocked too, so trackers cannot hide behind a
  first-party name.
- **Local DNS**: `nas.lan: 192.168.1.10`, multiple IPv4/IPv6 addresses per
  name, `*.apps.lan` wildcards, automatic reverse (PTR) lookups. Zones such as
  `lan` can be forwarded to your router, so its DHCP clients' names resolve
  while everything else goes to encrypted upstream servers.
- **Privacy**: private names (`.lan`, `.home.arpa`, `.internal`, single-label
  names, reverse lookups of private IPs) never leak upstream; client EDNS
  options (cookies, client subnet) are stripped before forwarding; Firefox's
  DNS-over-HTTPS canary is answered so it keeps using your resolver.
- **DNS over TLS** to upstream servers, so your ISP can neither read nor
  alter your queries. Connections are reused, so after the first query it is
  as fast as plain DNS.
- **Caching** of upstream answers (LRU, TTL-aware, bounded). When no upstream
  server answers, answers that expired in the last 24 hours are served anyway
  (RFC 8767), so a short outage goes unnoticed for names already in use.
- **DNSSEC** flags are passed through, so a validating upstream (Quad9 and
  Cloudflare both validate) refuses forged data. zinkhole does not validate
  signatures itself.
- UDP and TCP, IPv4 and IPv6, upstream failover, TCP fallback for large
  answers. Upstream servers are tried in the order listed, starting with the one
  that answered last, so later ones act as fallbacks; after a failover, one
  query a minute tries the first server again, and it takes over once it answers.
- **Metrics** as JSON for `curl` or a browser: queries per outcome today
  (since local midnight) and in the last 24 hours, hour by hour, upstream
  answer times, and the state of the lists and sync (see [Metrics](#metrics)).
- A per-query log (`log.queries`), statistics (`SIGUSR1`) and a container
  health check.
- Live reload with `SIGHUP`; local records apply instantly, and lists are
  re-downloaded only when their sources changed.
- **Proxmox in one command**: a script creates the LXC container (static or
  DHCP address, IPv6 on or off), installs zinkhole in it, and gives it an
  `update` command (see [Proxmox LXC](#proxmox-lxc)).
- **Two instances, one config**: a replica syncs its local records and
  blocking settings from an origin (see [Running two instances](#running-two-instances)).

## Build

Requires Zig 0.17.

```sh
zig build --release            # ReleaseSafe: optimized, bounds checks kept
zig build test                 # unit tests (offline)
zig build test -Dnetwork       # also DNS over TLS to a public server
zig build test -Dtest-filter="name"   # only tests whose name contains this
zig build test --fuzz=1M -Dtest-filter="fuzz: no message"  # fuzz one target (see below)
zig build --release -Dtarget=aarch64-linux-musl -Dstrip=true   # e.g. Raspberry Pi 64-bit
zig build --release -Dtarget=arm-linux-musleabihf -Dstrip=true # Raspberry Pi 32-bit
```

The parsers for untrusted input have coverage-guided fuzz tests (their names
start with `fuzz:`: DNS messages, list lines and the config, which is also
what replicas receive). A plain `zig build test` runs only their starting
inputs; `--fuzz` searches for failures, one target at a time (pick it with
`-Dtest-filter`). Without a limit it runs until stopped and serves a web UI.

Linux builds are static binaries of about 1 MB (`-Dstrip=true` drops the
debug info, which costs disk space only, not memory). Releases contain the
`x86_64` and `aarch64` builds; for 32-bit ARM, build it yourself as above.

### Releasing

A release is a tag; GitLab CI does the rest (see [.gitlab-ci.yml](.gitlab-ci.yml)
and [docs/adr/0003](docs/adr/0003-proxmox-install-and-update.md)). The version
lives only in `build.zig.zon`: `zinkhole --version` is built from it.

```sh
# 1. Bump `.version` in build.zig.zon (e.g. "0.2.0"), update docs if needed, commit.
zig build test && zig fmt --check src build.zig   # what CI runs first (it also runs shellcheck)
# 2. Tag exactly v<version> and push the tag.
git tag v0.2.0 && git push origin main v0.2.0
```

On a `v*` tag the pipeline runs the tests, **fails if the tag does not match
`build.zig.zon`**, builds static `x86_64-linux-musl` and `aarch64-linux-musl`
binaries, packs the Proxmox scripts, `zinkhole-deploy.tar.gz` (the installer
and service files) and the `LICENSE`, writes `SHA256SUMS`, and publishes
everything as a public GitLab release. Downloads then work without a login,
at stable links:

```
https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads/zinkhole-x86_64-linux-musl
https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads/SHA256SUMS
```

- The project and its releases must be **public**, or the installers and the
  `update` command cannot download them.
- A tag that went wrong cannot be fixed in place: delete the release and the
  tag on GitLab, correct the problem, and tag again.
- To try the release steps without GitLab, run `sh deploy/ci/release.sh build`
  (needs Zig) and `sh deploy/ci/release.sh publish --dry-run`; the files land
  in `dist/`. `deploy/ci/install-zig.sh` installs the pinned Zig in an Alpine
  container, so the whole pipeline can be rehearsed there.

## Run

Try it in the foreground first (port 53 needs privileges, so pick another
port in `server.listen` for a quick test):

```sh
cp config.example.yaml config.yaml     # then edit it
./zig-out/bin/zinkhole --check -c config.yaml  # only validate (no network)
./zig-out/bin/zinkhole --test -c config.yaml   # validate and load all lists
./zig-out/bin/zinkhole -c config.yaml
```

| Option | Meaning |
|--------|---------|
| `-c`, `--config <path>` | config file (default `/etc/zinkhole/config.yaml`) |
| `--check` | only validate the config, without network access, then exit |
| `-t`, `--test` | validate the config and load all lists, then exit |
| `--healthcheck [addr]` | ask a running server for `localhost`; exit 0 if it answers |
| `-V`, `--version` / `-h`, `--help` | version / usage |

For permanent use, pick the setup that fits. Each runs zinkhole as an
unprivileged user that may only bind port 53; never run it as root.

|          | Debian, Ubuntu (systemd)       | Alpine (OpenRC)              | Docker                                 |
|----------|--------------------------------|------------------------------|----------------------------------------|
| Install  | `./deploy/install.sh`          | `./deploy/install.sh`        | `docker compose up -d --build`         |
| Config   | `/etc/zinkhole/config.yaml`    | `/etc/zinkhole/config.yaml`  | `./config.yaml`                        |
| Reload   | `systemctl reload zinkhole`    | `rc-service zinkhole reload` | `docker compose kill -s HUP zinkhole`  |
| Logs     | `journalctl -u zinkhole -f`    | `tail -f /var/log/messages`  | `docker compose logs -f`               |
| Tested on| Debian 13, systemd 257         | Alpine 3.24, OpenRC 0.63     | Docker 29, Compose 5.4                 |

On Proxmox, one command creates the container for you: see
[Proxmox LXC](#proxmox-lxc).

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
  *nesting* feature. Without it the service fails with status 226/NAMESPACE.
  See [Proxmox LXC](#proxmox-lxc) for the whole setup.

No Zig on the build machine? Docker can build the binary (use
`linux/arm64` for 64-bit ARM):

```sh
docker buildx build --platform linux/amd64 -t zinkhole --load .
mkdir -p zig-out/bin && docker create --name zinkhole-tmp zinkhole
docker cp zinkhole-tmp:/usr/local/bin/zinkhole zig-out/bin/ && docker rm zinkhole-tmp
```

### Proxmox LXC

One small container per node is the natural fit: zinkhole needs about 128 MB
of RAM (large blocklists take ~35 MB, briefly twice that while refreshing) and
a few MB of disk. On a Proxmox node, as root, one command creates the
container and installs and configures zinkhole in it:

```sh
# Debian 13 (systemd)
bash -c "$(curl -fsSL https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads/zinkhole-debian.sh)"
# Alpine (OpenRC): smaller, otherwise the same
bash -c "$(curl -fsSL https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads/zinkhole-alpine.sh)"
```

It asks a few questions (including an optional **root password**), shows what
it is about to do, and then:

1. creates an unprivileged container (1 core, 128 MB RAM, 1 GB disk, no swap)
   with a **static or DHCP address** (your choice) and optional IPv6, starting
   at boot (`nesting` is enabled on Debian only: systemd's sandboxing needs it);
2. upgrades the OS packages and installs zinkhole, writing a working
   `/etc/zinkhole/config.yaml` (Quad9 over TLS with Cloudflare as a fallback,
   the StevenBlack blocklist, [metrics](#metrics) on port 9153);
3. starts it, waits until it answers, and prints how to use and update it.

The container takes the node's time zone (`--timezone host`), so the
metrics' "today" starts at your midnight.

The **role** question sets up [two instances](#running-two-instances) for
you: *standalone* (the default), *origin* (a secret is generated and shown
once) or *replica* (asks for the origin's URL and secret). Run it on each node.

Every question can be answered up front with an environment variable, which
also makes it non-interactive. All are optional except the IPv4 address:

| Variable | Meaning (default) |
|----------|-------------------|
| `ZINKHOLE_IP` | `dhcp`, or a static address with prefix, e.g. `192.168.1.5/24` (required) |
| `ZINKHOLE_GATEWAY` | static only: the node's default gateway |
| `ZINKHOLE_IP6` | `off`, `auto` (SLAAC), `dhcp`, or a static address like `fd00::5/64` (`off`) |
| `ZINKHOLE_GATEWAY6` | static IPv6 only, optional |
| `ZINKHOLE_PASSWORD` | root password of the container (none; see below) |
| `ZINKHOLE_ROLE` | `standalone`, `origin` or `replica` |
| `ZINKHOLE_ORIGIN`, `ZINKHOLE_SECRET` | replica: the origin's URL and secret |
| `ZINKHOLE_METRICS`, `ZINKHOLE_METRICS_PORT` | serve [metrics](#metrics): `on` or `off` (`on`), on port `9153` |
| `ZINKHOLE_CTID`, `ZINKHOLE_HOSTNAME` | next free ID, `zinkhole-<node>` |
| `ZINKHOLE_BRIDGE`, `ZINKHOLE_VLAN` | `vmbr0`, none |
| `ZINKHOLE_NAMESERVER` | what the container itself uses; the gateway (static) or what DHCP hands out |
| `ZINKHOLE_STORAGE`, `ZINKHOLE_TEMPLATE_STORAGE` | the first suitable storage |
| `ZINKHOLE_CORES`, `ZINKHOLE_MEMORY`, `ZINKHOLE_DISK` | `1`, `128` (MB), `1` (GB) |
| `ZINKHOLE_YES=1` | do not ask for confirmation |
| `ZINKHOLE_KEEP_ON_FAIL=1` | keep the container if the installation fails |
| `ZINKHOLE_BASE_URL` | where to download the release files from (this script's own release; for mirrors and testing) |

```sh
# Unattended: a replica of the origin from the example above
ZINKHOLE_IP=192.168.1.6/24 ZINKHOLE_ROLE=replica ZINKHOLE_YES=1 \
ZINKHOLE_ORIGIN=http://192.168.1.5:5380 ZINKHOLE_SECRET=<the origin's secret> \
  bash -c "$(curl -fsSL https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads/zinkhole-debian.sh)"
```

Afterwards, test with `dig @192.168.1.5 example.com`, hand out the
container's address as the DNS server (typically in your router's DHCP
settings), and never forward port 53 from the internet to it.

- **Root password:** asked silently and twice; leave it empty for none, and
  enter the container with `pct enter <id>`. With a password you can also log
  in as `root` on the Proxmox console (at least 5 characters). It does not
  enable SSH logins with a password (Debian's default allows only keys for
  root). The node hashes it (SHA-512) before it goes into the container, so it
  is never on a command line or stored in plain text; `ZINKHOLE_PASSWORD` is
  there for unattended installs, but a value typed in a shell is kept in the
  shell history, so prefer the prompt.
- **Static or DHCP?** Clients need a DNS server whose address never changes.
  Static is the simplest way to get that. With `dhcp` the script shows the
  address the container received; give the container a fixed lease on your
  DHCP server (its MAC address is in `pct config <id>`), or the address may
  change one day. A DHCP container's name server comes from DHCP too. A DHCP
  *origin* serves its settings on all addresses (still only to
  `server.allow_clients`), since its address may change.
- **IPv6** is `off` by default: the container gets no IPv6 address and zinkhole
  listens on IPv4 only. With `auto`, `dhcp` or a static address, zinkhole also
  listens on IPv6, and the script adds the container's own IPv6 network to
  `server.allow_clients`: that list normally covers only private addresses, so
  without it clients using a global IPv6 address would be refused. If the
  network is not found (for example SLAAC is slow), the script says so; add
  your IPv6 prefix to `server.allow_clients` yourself. An address from SLAAC
  can change, so for a DNS server prefer a static or reserved one. Upstream
  servers stay IPv4 (Quad9, then Cloudflare, over TLS); add IPv6 ones in the
  config if you want.

- **Everything downloaded is checked** against the release's `SHA256SUMS`
  before it is used (a download that does not match stops the script before
  anything is created). The checksums come from the same GitLab release, so
  they protect against corrupt downloads, not against a compromised project.
- **If the installation fails** the new container is removed again, so a
  retry starts clean (`ZINKHOLE_KEEP_ON_FAIL=1` keeps it for debugging).
- **`update`**: inside the container (or `pct exec <id> -- update`) it
  upgrades the OS packages, then updates zinkhole to the latest release if
  there is a newer one. It checks that the new version accepts your config
  (`--check`), keeps the old binary as `/usr/local/bin/zinkhole.old`, and puts
  it back if the new one does not answer within 15 seconds. With several nodes,
  **update the replicas before the origin**.
- **Changing the config**: `pct enter <id>`, edit `/etc/zinkhole/config.yaml`,
  then `systemctl reload zinkhole` (Alpine: `rc-service zinkhole reload`).
- **Removing it**: `pct stop <id> && pct destroy <id>`.
- **Backups**: the container holds only the config (and a replica's synced
  state), so a normal Proxmox backup of it is enough.

<details>
<summary>The same by hand</summary>

Create the container yourself (storage names and template versions differ per
setup; `pveam available` lists the templates). For Alpine use an `alpine-*`
template and drop `--features nesting=1`:

```sh
pveam update
pveam download local debian-13-standard_<version>_amd64.tar.zst

# static address; for DHCP use  --net0 name=eth0,bridge=vmbr0,ip=dhcp  and drop --nameserver
pct create 200 local:vztmpl/debian-13-standard_<version>_amd64.tar.zst \
  --hostname zinkhole --unprivileged 1 --features nesting=1 \
  --cores 1 --memory 128 --swap 0 --rootfs local-lvm:1 \
  --net0 name=eth0,bridge=vmbr0,ip=192.168.1.5/24,gw=192.168.1.1 \
  --nameserver 192.168.1.1 --onboot 1 --start 1
pct enter 200
```

Inside, install the latest [release](#releasing) (on Alpine:
`apk add --no-cache curl ca-certificates`):

```sh
apt-get update && apt-get install -y curl ca-certificates
base=https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads
bin=zinkhole-$(uname -m)-linux-musl      # x86_64 or aarch64

mkdir /root/zinkhole && cd /root/zinkhole
curl -fsSLO $base/$bin && curl -fsSLO $base/zinkhole-deploy.tar.gz && curl -fsSLO $base/SHA256SUMS
grep -E " ($bin|zinkhole-deploy.tar.gz)\$" SHA256SUMS | sha256sum -c -    # must print "OK" twice
chmod +x $bin && tar -xzf zinkhole-deploy.tar.gz
./deploy/install.sh --binary ./$bin
```

Then edit `/etc/zinkhole/config.yaml`, check it with `zinkhole --check -c
/etc/zinkhole/config.yaml`, and start the service (the installer prints the
command). No release or no network in the container? Build the binary as in
[Build](#build) and copy it and the `deploy/` folder in with `pct push`.

</details>

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

- **No published image:** `docker compose up -d --build` builds it from this
  repository (the Dockerfile cross-compiles with a pinned, checksum-verified
  Zig, so no Zig is needed on the host). Without Compose:
  `docker build -t zinkhole . && docker run -d --name zinkhole -p 53:53/udp
  -p 53:53/tcp -v $PWD/config.yaml:/etc/zinkhole/config.yaml:ro zinkhole`.
- **Time zone:** the image has no zone files, so [metrics](#metrics) count in
  UTC unless you mount the host's: `-v /etc/localtime:/etc/localtime:ro`
  (Compose: under `volumes:`). Or set `TZ` to a rule such as
  `CET-1CEST,M3.5.0,M10.5.0/3`; a name like `Europe/Amsterdam` needs the zone
  files, which the `alpine` target can get with `apk add tzdata`.
- **Metrics:** listen on `0.0.0.0:9153` in the config and publish the port
  (`-p 9153:9153`). Docker on Linux keeps the client's address, which must be
  in `server.allow_clients`.
- **Port 53 taken on the host** (for example by `systemd-resolved`)? Publish
  one address only, e.g. `"192.168.1.5:53:53/udp"` and `"192.168.1.5:53:53/tcp"`
  in `docker-compose.yml`.
- **A sync replica** saves its last settings in `/var/lib/zinkhole`, which the
  hardened (`read_only`) container does not allow by default. Mount a volume
  there: `- zinkhole-state:/var/lib/zinkhole` under `volumes:` and a top-level
  `volumes: {zinkhole-state: {}}`. [deploy/sync/](deploy/sync/) is a complete
  example with an origin and a replica.
- **Docker inside a Proxmox LXC** needs the container's `nesting` and `keyctl`
  features and adds a layer for little gain; for a DNS server the plain
  [Proxmox LXC](#proxmox-lxc) install above is simpler, or use a VM.

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
last settings it accepted in `/var/lib/zinkhole/synced.yaml` (set another
folder with `sync.state_dir`) and starts from them if the origin is down.
Reload the origin to publish a change; reload a replica to sync right away.
Changing an instance's `sync` section needs a restart.

**Promoting a replica** if the origin is gone for good: append the state
file to its config (`cat /var/lib/zinkhole/synced.yaml >>
/etc/zinkhole/config.yaml`), replace `sync.origin` with `sync.serve`, and
restart. Make the old origin a replica before it comes back.

[deploy/sync/](deploy/sync/) has a Docker Compose setup with both roles and
an end-to-end test (`./deploy/sync/test.sh`). The design is in
[docs/adr/0002](docs/adr/0002-sync-replicas-from-an-origin.md).

### Metrics

With a `metrics` section, zinkhole serves one JSON document over plain HTTP:

```yaml
metrics:
  listen: ["192.168.1.5:9153"]
```

```sh
curl http://192.168.1.5:9153/metrics
```

```json
{
  "format": 1, "version": "0.3.0", "role": "origin",
  "now": "2026-10-13T14:05:00+02:00", "started": "…", "uptime_s": 103336,
  "time_zone": "Europe/Amsterdam",
  "queries": {
    "today": {
      "total": 5120, "blocked": 830, "blocked_pct": 16.2,
      "cached": 1900, "cache_hit_pct": 47.3,
      "local": 210, "private": 40, "forwarded": 2120,
      "failed": 3, "refused": 0, "invalid": 17
    },
    "last_24h": { "…": "the same fields" }
  },
  "upstream": [
    { "server": "tls://9.9.9.9:853#dns.quad9.net", "preferred": true,
      "today": { "answers": 2100, "failures": 2, "avg_ms": 18.4 },
      "last_24h": { "answers": 2950, "failures": 2, "avg_ms": 19.1 } }
  ],
  "lists": {
    "blocked_domains": 194332, "allowed_domains": 0,
    "sources": [ { "source": "https://…/pro.txt", "ok": true } ],
    "last_complete_load": "…", "next_load": "…"
  },
  "cache": { "entries": 812, "capacity": 4096 },
  "local_records": 4,
  "sync": { "fetched_by": [ { "address": "192.168.1.6", "last_fetch": "…" } ] },
  "hourly": [
    { "hour": "2026-10-12T15:00+02:00", "total": 180, "blocked": 31, "…": "every outcome" }
  ]
}
```

- **today** counts from 00:00 local time; **last_24h** is the current hour
  plus the 23 before it; **hourly** has those 24 hours, oldest first, one line
  each. The queries are counted by [how they were answered](#how-a-query-is-answered).
  `blocked_pct` is blocked / total; `cache_hit_pct` is the share of queries
  needing an upstream answer that the cache had.
- **upstream** counts every attempt: when the first server times out and the
  second answers, each gets one. `avg_ms` covers answers only, including the
  TLS handshake when a connection was new.
- **sync** depends on the role: an origin lists the addresses that fetched its
  settings in the last 24 hours (any allowed client that asks counts); a
  replica shows `origin`, `last_sync` and `failures_in_a_row`.
- Counts live in memory: a restart starts from zero, a reload keeps them.
  Times are local, with their offset. New fields may be added; a breaking
  change would raise `format`.
- **Local time** comes from `TZ` (a zone name or a POSIX rule), else
  `/etc/localtime`, else UTC (logged as a warning). It is read at startup.
- Only clients in `server.allow_clients` can read it, without a password; it
  holds no domain names and nothing per client. A list source's query string
  (which may hold a token) is left out.

**Adding it to a container installed before metrics existed** (`update` does
not change the config): on the Proxmox node, for Alpine first
`pct exec <id> -- apk add tzdata` (Debian has the zone files already), then
`pct set <id> --timezone host`. Add the two lines above to
`/etc/zinkhole/config.yaml`, with the container's address, and restart the
container (`pct reboot <id>`).

### Signals

| Signal    | Effect                                                      |
|-----------|-------------------------------------------------------------|
| `SIGHUP`  | Reload the config file (server/upstream/cache/sync/metrics need restart); on a replica, also sync now |
| `SIGUSR1` | Log query statistics (totals since start)                   |
| `SIGTERM` | Shut down cleanly                                           |

## Configuration

See [config.example.yaml](config.example.yaml), which documents every
setting. Only the upstream servers are required; a small config looks like:

```yaml
upstream:
  servers:
    - tls://9.9.9.9#dns.quad9.net          # DNS over TLS: address#certificate name
    - tls://149.112.112.112#dns.quad9.net
    - tls://1.0.0.1#one.one.one.one        # a second provider as a fallback
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
4. Name in a zone of `local.forward` → cached answer, or the zone's server
5. Private or special-use name → `NXDOMAIN` (unless `private_names: forward`)
6. In the cache → cached answer, TTLs reduced by its age
7. Otherwise → forwarded upstream, then cached; if no upstream server answers,
   an answer that expired less than `cache.serve_stale_hours` ago, with TTL 30

A listed domain blocks itself and all of its subdomains; `*.example.com`
blocks only the subdomains. An upstream or cached answer whose CNAME records
point at a blocked name gets the block response instead (CNAME cloaking),
unless an allow rule matches the name asked for; this is checked on every
answer, so a reload that changes the rules applies at once. Allow rules always win over block rules. Blocked
names get an answer for every record type (empty for types other than A/AAAA),
so clients cannot get around a block through HTTPS/SVCB records. Answers that
say a name or record type does not exist (NXDOMAIN, or no records of the type
asked for) carry an SOA record, so clients cache them for `blocking.ttl` or
`local.ttl` instead of asking again every time.

## Design

| File | Responsibility |
|------|----------------|
| `main.zig` | CLI, startup, signals, running list loads in the background |
| `config.zig`, `yaml.zig` | YAML subset parser and validated, typed config |
| `server.zig`, `tcp.zig` | UDP/TCP listeners, fixed worker and TCP connection pools, TCP framing with deadlines |
| `forwarder.zig` | The forwarding slots: cache misses go to upstream servers without holding up a worker |
| `resolver.zig` | The query pipeline above, statistics, query log |
| `policy.zig` | `Policy`: steps 2-5 of the pipeline (local, blocked, forwarded zone, private) and blocked aliases (ADR-0006), from the config (rebuilt on reload) and the downloaded `Lists` |
| `refresh.zig` | When lists load: refresh interval, retry backoff, timeouts |
| `sync.zig` | Sync: the origin's endpoint, signed fetches, the replica's state file |
| `metrics.zig` | Counts per local hour, the JSON document and its endpoint |
| `localtime.zig` | The UTC offset at a moment, from `TZ` or a zone file (TZif and POSIX rules) |
| `http_service.zig` | The small HTTP server behind the sync and metrics endpoints |
| `domain_set.zig` | Compact domain set with subdomain matching |
| `blocklist.zig` | Line parser for all list formats, streaming loader (file/HTTPS) |
| `local.zig` | Local records, wildcards, reverse lookups, private zones |
| `cache.zig` | Bounded LRU response cache |
| `upstream.zig` | Failover over upstream servers; plain DNS with TCP fallback |
| `dot.zig` | DNS over TLS: pooled TLS connections, certificate checks (`dot.Tls`) |
| `dns.zig` | DNS wire format: parsing, building, TTL handling |
| `ip.zig` | IP addresses, networks (`allow_clients`) and parsing |
| `log.zig` | Log output and the runtime log level |

The reasoning behind the larger design decisions is in [docs/adr/](docs/adr/),
and [CONTEXT.md](CONTEXT.md) defines the terms used in the code and docs.

**Domain set.** Every domain is stored once in one byte array as
`[length][name]`, and a hash table maps the 4-byte offset of each entry to
two flags (match the name itself, match its subdomains). A lookup hashes the
query name and walks up its parent domains (`a.b.example.com`,
`b.example.com`, `example.com`, `com`): at most one hash lookup per label,
with no allocation. 255,000 domains take about 8 MB (~31 bytes each). Each set
uses a random hash seed, so list content cannot be crafted to degrade it.

**Threads and memory.** A UDP worker answers refusals, local records, blocked
and private names, and cache hits itself. A cache miss goes to one of a fixed
pool of forwarding slots (`upstream.max_in_flight`, 64 by default), and the
worker goes back to receiving at once, so a slow upstream server never holds
up an answer that needs none. When every slot is busy, as in an upstream
outage, a cache miss gets SERVFAIL at once, so local names and cache hits keep
answering instantly. TCP connections are served by a pool of 16 connection
slots shared by all listeners, so a few idle or slow TCP clients cannot hold
up the others; a connection that finds every slot busy is closed at once.
Each worker and slot owns one fixed query buffer and one fixed response
buffer, so answering a query allocates nothing; only cache insertions do, and
the cache has a fixed capacity. On one CPU this answers about 340,000
blocked or cached queries a second, and 50 new names at once in the time of
one upstream round trip (measured with a 20 ms upstream; see
[docs/adr/0005](docs/adr/0005-forward-from-a-pool-of-slots.md)). The config policy and
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
each. A source that has not finished after 2 minutes counts as failed, so a
server that stops sending cannot hold up the others. If a refresh fails partway, the previous complete lists stay in use and
the refresh is retried with exponential backoff. After a reload that changes
the lists, the new ones are used right away, even if some of them failed.

## Security

- Built in ReleaseSafe: bounds and integer overflow checks stay on. Every
  length read from a DNS message is checked before use; malformed packets get
  `FORMERR` or are dropped. The parsers are tested against random and mutated
  input, and fuzzed with coverage guidance (`zig build test --fuzz`). The tests, including concurrent forwarding, shutdown in the middle of
  exchanges, reloads and syncs, pass under ThreadSanitizer
  (`zig build test -Dsanitize-thread`, which CI runs on every push). Pointer-stability locks make safe builds panic if a
  buffer that other code points into (the listener sockets workers use, the
  domain bytes a hash table reads) could be reallocated.
- Upstream queries can use DNS over TLS with certificate verification. For
  plain DNS upstreams: a fresh socket (random source port) and a random
  query ID per exchange, and only answers from the right address with the
  same ID and question are accepted.
- Only allowed client networks are answered (default: private ranges), so an
  accidentally exposed port is not an open resolver. TCP connections from
  other networks are closed on arrival, so they cannot occupy a TCP slot; at
  most 16 connections are served at once, and further ones are closed. Zone
  transfers and non-IN classes are refused. The TCP ports are not shared
  with other processes (no `SO_REUSEPORT`).
- Lists are fetched over TLS with system CA verification (plain `http://`
  sources produce a warning, and an `https://` list that redirects to `http://`
  is refused), with size limits. TCP clients have idle deadlines and a
  per-connection query limit. Query names are escaped in the query log, so a
  crafted name cannot forge log lines.
- The config parser rejects YAML anchors/aliases (no "billion laughs") and
  duplicate keys; the file is limited to 1 MiB.
- Sync answers are signed (HMAC-SHA256) over a random challenge from the
  replica, and the state file is checked against the same signature. The sync
  endpoint is read-only, answers only `server.allow_clients` (other
  connections are closed before anything is read), and serves only `blocking`
  and `local`, never the secret. It is plain HTTP, so the settings are not
  encrypted: anyone on the LAN can read them, but those clients can already
  query the local records. The state file is flushed to disk before it
  replaces the old one.
- The metrics endpoint is read-only and answers only `server.allow_clients`,
  in the same way; it holds counts and settings, no domain names or client
  addresses (an origin lists the addresses that fetched its settings), and
  list sources without their query strings.

## Limitations

- No DNS over HTTPS upstream (some providers, such as Quad9, require
  HTTP/2, which Zig's standard library does not have), and zinkhole itself
  answers plain DNS only (inside a LAN, encrypting the client side adds
  little). Zig has no TLS server either, so the sync endpoint is signed but
  not encrypted.
- No DNSSEC validation in zinkhole itself: it relies on a validating upstream
  (Quad9 and Cloudflare both validate). Blocked and local answers are
  unsigned, which only matters to clients that validate on their own.
- Regular-expression rules and per-client blocking groups are not supported.
- Lists are downloaded again on every start (nothing is stored on disk).

## License

[MIT](LICENSE): free to use, copy, modify and distribute, including
commercially. The only condition is that the copyright notice and license text
stay with the code.
