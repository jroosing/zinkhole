---
status: accepted
---

# The Policy also decides forwarded zones and blocks aliases of blocked names

Two kinds of names went through the query pipeline in a way users did not expect.

- **Names the router knows.** The router's DHCP clients could only be resolved by making the router an upstream server, because `private_names: forward` sends Private names to the same upstream servers as everything else. That gave up DNS over TLS for every query, and leaked LAN names to a public provider when the upstream servers were public.
- **Trackers behind an alias.** Blocking checked only the query name. A tracker behind a first-party name (`metrics.shop.example CNAME shop.example.tracker.net`, known as CNAME cloaking) got through even when `tracker.net` was blocked. AdGuard Home, blocky and Pi-hole all check the alias targets.

**Decision.** Both become part of the Policy.

- A **Forwarded zone** (`local.forward`) sends the names at and below it to a server of its own.
- An upstream answer that makes the queried name an alias (CNAME) of a Blocked name gets the Block response.

This amends ADR-0001:
- `Policy.decide` gains a `forward` decision, and the Policy gains `blockAlias`.
- The `private` decision now carries a TTL, for the SOA record in negative answers.
- The Policy covers steps 2–5 of the query pipeline instead of 2–4.

## How it works

**Forwarded zones.**

```yaml
local:
  forward:
    lan: 192.168.1.1
    "1.168.192.in-addr.arpa": 192.168.1.1
```

- **A Policy setting.** It lives in the `local` section, so it is synced to Replicas and applied on Reload, like local records.
- **Plain DNS only.** Targets are `ip[:port]`; `tls://` is rejected by the config check.
- **Its place in the pipeline.** Local records and their reverse lookups come first, then blocking, then forwarded zones, then Private names.
  - A blocked name in a forwarded zone stays blocked.
  - A Private name in a forwarded zone is forwarded instead of answered NXDOMAIN.
  - The longest matching zone wins.
- **The decision.** `decide` returns `forward` with the server's address, copied into the decision like every other decision's data (ADR-0001).
- **Answering.** The resolver treats `forward` like `upstream`: the cache first, then the zone's server through `Upstream.forwardTo`.
  - `forwardTo` uses the same exchange as the upstream servers: a random query ID and source port, answer matching, the TCP fallback, and `upstream.timeout_ms`.
  - There is no failover and no preferred server.
  - The Metrics' per-server counts do not include it; they list the configured upstream servers. The Outcome is `forwarded`.
- **The forwarding slots stay as they are (ADR-0005).** A slot asks the Policy again for the server instead of having it handed along: one lookup in memory before a network exchange.
- **The cache key does not change.** The Policy runs before the cache, so a name answered by a zone's server is never mistaken for one answered by an upstream server while the config stays the same.

**Aliases of blocked names.**

- **Where it is checked.** On every upstream answer, every cache hit and every stale answer, the resolver reads the CNAME targets in the answer section and asks `Policy.blockAlias(name, target)`.
- **Reading the targets.** `dns.readName` follows compression pointers only backwards, so it cannot loop. It reads at most 255 bytes.
- **When it blocks.** The target is a Blocked name (a block rule and no allow rule matches it), and no allow rule matches the name asked for. An allow rule for the queried name is how a user opts a name out.
- **The answer.** The Block response with the Block TTL, counted as `blocked`.
- **Caching.** The upstream answer is cached as it came, and checked again on each hit. A Reload or Refresh that changes the rules applies at once, and a blocked alias costs no further upstream queries.
- **No setting.** It is always on.

**Tests.**
- Config: parsing `local.forward`, and its errors with their line numbers.
- Policy: the longest zone, the order against local records, blocking and Private names.
- Resolver: through a loopback stub, a forwarded name is answered by the zone's server and then from the cache.
- Resolver: an alias of a blocked name is blocked, both from upstream and from the cache; an allow rule for the queried name wins.
- `dns.readName`: compressed names, pointer loops, forward pointers and truncated names, and its own fuzz test.

## Why this shape

- **Forwarded zones are a Policy setting** because they answer "how is this name answered?" from the config, and they change exactly when local records change. As an `upstream` setting they would need a restart and would not sync.
- **Plain DNS only.** Routers rarely speak DNS over TLS. A `tls://` target would need the CA bundle loaded by any Reload or Sync that adds one, which today only happens at startup. It can be added as a variant later.
- **Asking the Policy again in the slot** keeps the code that ADR-0005 reviewed unchanged, at the cost of one in-memory lookup per forwarded query.
- **Checking aliases on every answer, not once before caching,** keeps the cache a cache of upstream answers. Storing the Block response instead would keep blocking after a Reload that unblocks the target, until the entry expired. Not caching at all would send every query for the name upstream again.
- **Always on.** It is what users expect from a blocker. It costs one walk over the answer's records, with no allocation. An allow rule for the queried name covers the rare false positive.

## Considered options

- **The router as an upstream server** (the old way). It needs no code, but loses DNS over TLS for every query and leaks LAN names to a public provider when one is in the list.
- **`upstream.forward`, a setting per instance.** Not synced, and changes need a restart. An origin and its replicas usually share the router anyway.
- **Carrying the zone's server through the forwarding slot.** It saves one Policy lookup, but changes the forwarder's interface for every query.
- **A `blocking.cname_inspection` setting.** Not added: no case was found where blocking the alias is wrong and an allow rule is not the better fix.
- **Checking answer addresses against IP blocklists.** The supported list formats hold no IP rules.
- **Following alias chains with more queries** (asking upstream for each CNAME target). Upstream servers already return the whole chain in one answer, which is what is checked.
