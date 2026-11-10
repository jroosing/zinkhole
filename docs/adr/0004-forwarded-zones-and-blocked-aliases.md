---
status: accepted
---

# The Policy also decides forwarded zones and blocks aliases of blocked names

Two kinds of names need more than "local, blocked, private, or upstream":

- **Names the router knows.** The router's DHCP clients can only be resolved by the router. Making it an upstream server gives up encrypted DNS for every query, and sending private names to the public upstream servers leaks LAN names.
- **Trackers behind an alias.** Checking only the query name lets a tracker behind a first-party name through (`metrics.shop.example CNAME shop.example.tracker.net`, known as CNAME cloaking), even when `tracker.net` is blocked. AdGuard Home, blocky and Pi-hole all check the alias targets.

**Decision.** Both are part of the Policy.

- A **Forwarded zone** (`local.forward`) sends the names at and below it to a server of its own.
- An upstream answer that makes the queried name an alias (CNAME) of a Blocked name gets the Block response.

## How it works

**Forwarded zones.**

```toml
[local.forward]
"lan" = "192.168.1.1"
"1.168.192.in-addr.arpa" = "192.168.1.1"
```

- **A Policy setting.** It lives in `[local]`, so it is synced to Replicas and applied on Reload, like local records.
- **Plain DNS only.** Routers rarely speak encrypted DNS.
- **Its place in the pipeline.** Local records and their reverse lookups come first, then blocking, then forwarded zones, then Private names.
  - A blocked name in a forwarded zone stays blocked.
  - A Private name in a forwarded zone is forwarded instead of answered NXDOMAIN.
  - The longest matching zone wins.
- **Answering.** Like an upstream query: the cache first, then the zone's server with the same exchange as plain upstream servers (a random query ID and source port, answer matching, TCP fallback, `upstream.timeout_ms`). There is no failover, no preferred server, and no DNSSEC validation (LAN zones are unsigned). The Metrics' per-server counts list the configured upstream servers only; the Outcome is `forwarded`.
- **The cache** keys answers by the server they came from, so a Reload or Sync that adds or removes a zone takes effect at once.

**Aliases of blocked names.**

- **Where it is checked.** On every upstream answer, every cache hit and every stale answer, the resolver reads the CNAME targets in the answer section and asks the Policy whether the alias is blocked.
- **When it blocks.** The target is a Blocked name (a block rule and no allow rule matches it), and no allow rule matches the name asked for. An allow rule for the queried name is how a user opts a name out.
- **The answer.** The Block response with the Block TTL, counted as `blocked`.
- **Caching.** The upstream answer is cached as it came, and checked again on each hit. A Reload or Refresh that changes the rules applies at once, and a blocked alias costs no further upstream queries.
- **No setting.** It is always on.

## Why this shape

- **Forwarded zones are a Policy setting** because they answer "how is this name answered?" from the config, and they change exactly when local records change. As an `[upstream]` setting they would need a restart and would not sync.
- **Checking aliases on every answer, not once before caching,** keeps the cache a cache of upstream answers. Storing the Block response instead would keep blocking after a Reload that unblocks the target, until the entry expired.
- **Always on.** It is what users expect from a blocker, and it costs one walk over the answer's records. An allow rule for the queried name covers the rare false positive.

## Considered options

- **The router as an upstream server.** No code, but it loses encrypted DNS for every query and leaks LAN names to a public provider when one is in the list.
- **`upstream.forward`, a setting per instance.** Not synced, and changes need a restart. An origin and its replicas usually share the router anyway.
- **A setting to turn alias checking off.** No case was found where blocking the alias is wrong and an allow rule is not the better fix.
- **Checking answer addresses against IP blocklists.** The supported list formats hold no IP rules.
- **Following alias chains with more queries.** Upstream servers already return the whole chain in one answer, which is what is checked.
