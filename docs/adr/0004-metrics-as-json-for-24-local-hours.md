---
status: accepted
---

# Metrics are served as JSON for the last 24 local hours

Users want to see how much was blocked today, and whether the upstream servers, lists and sync are healthy. They want this without running Prometheus or keeping history.

**Decision.** An optional HTTP listener (`metrics.listen`) serves one JSON document at `GET /metrics`. It holds:
- Outcome counts in hourly buckets aligned to local hours;
- upstream server results;
- the current state of the lists, cache, sync and the instance.

Everything is kept in memory only, and a restart starts from zero.

## How it works

**Config.**
```yaml
metrics:
  listen: ["10.10.50.85:9153"]
```
- Without the section, metrics are off: no listener and no time zone loading.
- The section belongs to the instance. It is never synced, and it is allowed in a replica's file.
- Changes need a restart.
- The port is the user's choice. It must not clash with the DNS listen addresses or `sync.serve`; the config check reports a clash. A listener that cannot bind stops startup, like the other listeners.

**Who can read it.**
- Only clients in `server.allow_clients`. Other connections are closed before anything is read.
- No authentication and no CORS headers. Plain HTTP.
- Like `/sync`: one request at a time, with a 5 s deadline.
- Other paths get 404 and other methods 405. Answers carry `Cache-Control: no-store`.

**Queries are counted per local hour.**
- Every Outcome is counted per local hour, in 25 hourly buckets. A day with a daylight saving change can have 25 hours.
- "Today" is the sum of the buckets since 00:00 local time.
- "Last 24 h" is the latest 24 buckets: the current, partial hour plus 23 full ones.
- When a query falls in a newer hour, the oldest bucket is cleared and reused.
- Buckets are fixed arrays of word-sized atomics (32-bit targets lack 64-bit atomics). Counting allocates nothing.

**Upstream servers are counted per attempt, per server.**
- **Answer:** any response except REFUSED, so SERVFAIL and NXDOMAIN are answers too.
- **Failure:** a timeout, a connection error, a malformed response, or REFUSED.
- **Response time:** answers only, from sending the query to receiving the answer. It includes setting up a TLS connection when one is needed.
- A query that needs several attempts counts against every server it tried. It still counts as one Outcome.
- Each server has 25 hourly buckets of answers, failures and total time.

**Lifetime of the counts.**
- Reloads and syncs keep the counts. Upstream servers change only on restart, so their counts stay valid.
- A restart clears everything.
- SIGUSR1 still logs the totals since start.

**Current state that is reported.**
- **Instance:** version, role, start time, uptime, time zone, number of local records, and cache entries against capacity.
- **Upstream:** per server, today and the last 24 h: answers, failures and average response time. Also which server is preferred, meaning the one that answered most recently and is tried first.
- **Lists:**
  - the number of blocked and allowed domains;
  - for each source, whether it loaded in the last load;
  - the last complete load and the next load.
  - Sources are shown without their query strings, which can hold tokens.
- **Sync on a replica:** the origin, the last successful sync, and the failures in a row.
- **Sync on the origin:** `fetched_by`, the addresses that fetched `/sync` in the last 24 h, each with its last fetch.
  - At most 16 addresses are kept; when the list is full, the oldest is replaced.
  - `/sync` requests are not authenticated, so any allowed client that fetches it is listed, not only replicas.
- **Never reported:** domain names, top-N lists and counts per client.

**The document.** It is written by hand with `print`, so `std.json` is not needed. Shortened example:
```json
{
  "format": 1,
  "version": "0.3.0",
  "role": "origin",
  "now": "2026-10-13T14:05:00+02:00",
  "started": "2026-10-12T09:12:44+02:00",
  "uptime_s": 103336,
  "time_zone": "Europe/Amsterdam",
  "queries": {
    "today": {
      "total": 5120, "blocked": 830, "blocked_pct": 16.2,
      "cached": 1900, "cache_hit_pct": 47.3,
      "local": 210, "private": 40, "forwarded": 2120,
      "failed": 3, "refused": 0, "invalid": 17
    },
    "last_24h": { "...": "the same fields" }
  },
  "upstream": [
    { "server": "tls://9.9.9.9:853#dns.quad9.net", "preferred": true,
      "today": { "answers": 2100, "failures": 2, "avg_ms": 18.4 },
      "last_24h": { "answers": 2950, "failures": 2, "avg_ms": 19.1 } }
  ],
  "lists": {
    "blocked_domains": 194332, "allowed_domains": 0,
    "sources": [ { "source": "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", "ok": true } ],
    "last_complete_load": "2026-10-13T08:00:12+02:00",
    "next_load": "2026-10-14T08:00:12+02:00"
  },
  "cache": { "entries": 812, "capacity": 4096 },
  "local_records": 4,
  "sync": { "fetched_by": [ { "address": "10.10.50.50", "last_fetch": "2026-10-13T14:04:31+02:00" } ] },
  "hourly": [
    { "hour": "2026-10-12T15:00+02:00", "total": 180, "blocked": 31, "cached": 70, "local": 8, "private": 1, "forwarded": 70, "failed": 0, "refused": 0, "invalid": 0 }
  ]
}
```
- **Indented**, with the summary first and `hourly` last. `hourly` has one line per hour, oldest first.
- **Times** are ISO 8601 in local time with the offset. The two 02:00 hours of an autumn daylight saving change differ by offset.
- **Percentages** have one decimal:
  - `blocked_pct` = blocked / total;
  - `cache_hit_pct` = cached / (cached + forwarded + failed), the share of the queries needing an upstream answer that came from the cache.
- **The `sync` block depends on the role:**
  - origin: `fetched_by`;
  - replica: `origin`, `last_sync` and `failures_in_a_row`;
  - standalone: no block at all.
- **`format`** only changes on a breaking change. New fields are only ever added.

**Local time.**
- At startup, zinkhole checks these in order:
  1. **`TZ`.** A zone name is read from `/usr/share/zoneinfo`; a POSIX rule such as `CET-1CEST,M3.5.0,M10.5.0/3` is used directly.
  2. **`/etc/localtime`.**
  3. **Neither:** UTC, with one warning that says how to fix it.
- The time zone is read once. Changing it needs a restart.
- **Calculating the offset:**
  - `std.tz` parses the TZif file. zinkhole's own code finds the offset in its transitions.
  - Past the last transition, zinkhole evaluates the file's POSIX rule footer. "Slim" zone files, as Alpine ships them, depend on this.
- **Proxmox:** the installer passes `--timezone host` to `pct create`. Proxmox only links `/etc/localtime` to a zone file the container has, and Alpine's template has none. So on Alpine the installer also installs `tzdata` and links the node's zone itself.
- **Docker** (`FROM scratch`, no zone files): mount `/etc/localtime`, or set `TZ` to a rule.

**Installers.**
- **The Proxmox installer** writes the `metrics` section on the container's address, port 9153. With DHCP it uses `0.0.0.0`, like the sync `serve` address.
  - `ZINKHOLE_METRICS=off` leaves the section out, and `ZINKHOLE_METRICS_PORT` changes the port.
  - The final summary prints the `curl` command.
- **`update`** never touches the config. The README shows how to add metrics to existing containers.
- **Docker and `install.sh`:** `config.example.yaml` has a commented-out `metrics:` block.

**Footprint.**
- No libc is needed: the build stays static musl.
- Estimated cost: 20–40 KB on a 1.23 MB release binary, plus about 2 KB of memory.
- The growth is measured after implementation. If it exceeds 5% (about 60 KB), a `-Dmetrics=false` build option is added, with metrics still included in releases.
- Measured (x86_64, stripped ReleaseSafe): 1,228,472 → 1,287,464 bytes, +59 KB or 4.8%. That is under the limit, so there is no build option.

**Tests.**
- **Bucket rotation with an injected clock:** midnight, days with 23 and 25 hours, and gaps longer than 24 h.
- **The time zone rule evaluator against known transitions:** Europe/Amsterdam, America/New_York, Australia/Sydney, Asia/Kolkata (a half-hour offset), and a slim file.
- **The endpoint over loopback:** `allow_clients`, 404/405, and the document's shape.
- **Upstream counting with the loopback test server:** answers, timeouts and REFUSED.

## Why this shape

- **JSON read by a person.** `curl` or a browser is enough, with no extra software. Because the format is stable, a script or dashboard can be built on it later.
- **Hourly buckets give both windows.** "Today" (reset at local midnight) and "last 24 h" come from fixed memory with no state on disk. History beyond a day is not wanted.
- **Local hours, because "today" is the user's day.** In the Netherlands, UTC midnight is 01:00 or 02:00.
- **Our own time zone code instead of libc.** Linking libc would change the whole build for one function.
- **No authentication.** This is the same model as DNS and `/sync`: `server.allow_clients`. The content is low in sensitivity by choice: no domains and no clients.
- **Counting each attempt.** A failing first server stays visible even when a fallback hides the failure from clients.

## Considered options

- **The Prometheus text format with Prometheus and Grafana.** It needs a time-series database for the history that is not wanted. The same counters could be offered in that format later.
- **An AdGuard Home- or Pi-hole-compatible API for dashboard cards** (Homer, Homarr). It copies another project's API and its logins, and their cards show only a blocked percentage.
- **A dashboard's generic JSON widget as the target** (Homepage, Homarr 2 custom widgets). It shapes the format for one tool; a stable document serves all of them.
- **A built-in web page.** It is more code, and a browser already shows JSON as a tree.
- **Logging the numbers periodically, or extending SIGUSR1.** It needs log access and has no "today".
- **A rolling 24 h window only, as in AdGuard Home.** It has no "today since midnight".
- **A separate daily counter reset at midnight.** It adds a second atomic per query, and the buckets already give the same number.
- **Buckets in UTC.** "Today" would be wrong.
- **Top-N domains or counts per client.** Memory grows with traffic, and they record what people look up.
- **Writing the counters to disk.** It breaks "no state on disk" for a nice-to-have.
- **A build flag from the start.** It means two binaries to test and release; it is only added if the measured growth is more than 5%.
