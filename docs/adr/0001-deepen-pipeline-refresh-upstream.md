---
status: accepted
---

# Deepen the query pipeline decision, the Refresh schedule and upstream server exchange

zinkhole's most subtle behaviour has no tests. It lives in the resolver, in the supervisor in `main.zig`, and in `upstream.zig`/`dot.zig`, and each spreads its logic across modules that only expose fields. We will move each piece of logic behind one small interface that tests can call directly. In this order:

1. **Query pipeline decision: the Policy** (`src/policy.zig`, formerly `rules.zig`).
   - **What it decides.** `decide(name, qtype)` covers steps 2–4 of the query pipeline: local records (including `localhost`), reverse lookups, the Firefox canary, blocked names (allow rules win) and private names.
   - **What stays in the resolver.** The allowed-client check stays out because it depends on the client and only changes on restart. Zone-transfer and non-IN refusals stay out because they are protocol rules.
   - **Input.** `name` must already be in the form `dns.Query.name` uses: lowercase, with no trailing dot.
   - **Output.** It returns a `Decision`: `local`, `reverse`, `blocked`, `private` or `upstream`. The decision carries the addresses, hostname, block response and TTL it needs. They are copied into the value, so it never points into the Policy.
   - **The resolver's part.** The resolver turns the decision into a DNS response and never reads `ConfigPolicy` or `Lists`.
   - **Ownership and locking.** The Policy owns `ConfigPolicy` and `Lists` and the read-write lock that guards them. `ConfigPolicy` is private: `Policy.init(config)` builds it, and `applyConfig(config)` replaces it on reload. Lists are still loaded outside the Policy and handed in with `replaceLists`. The Policy frees whatever it replaces.
   - **Which lists win.** `replaceLists` decides whether new lists replace the current ones, checking and swapping under one lock:
     - If the new lists come from the **same** sources (a Refresh), partial lists never replace complete ones.
     - If they come from **different** sources (a Reload changed them), they replace the current lists even when partial. A list you removed stops blocking at once, even if a newly added source is broken.

     For this, `Lists` remember the `Sources` they were loaded from. `listsComplete()` is no longer public.
   - **Tests.**
     - Policy tests start from config text. Lists come from temp files through the real `Lists.load`.
     - A list source that fails to load is logged as a warning, not an error. zinkhole keeps serving and retries, and Zig's test runner fails any test that logs an error, so the keep-or-swap rule could not be tested otherwise.
     - `LocalZone`'s behaviour tests move up to the Policy. The `blocklist`, `DomainSet` and `parseReverseName` tests stay.
     - `Resolver.handle` gets tests too, using a real `Cache` and an `Upstream` with no servers. That covers turning each decision into a DNS response, refusals and truncation, with no sockets.
2. **Refresh schedule** (`src/refresh.zig`, `Schedule`). It decides *when* lists load and nothing else.
   - **Interface.** `next(now, interval) → idle | start | cancel`, plus three events: `started(now)`, `finished(now, complete)` and `sourcesChanged()`. Time is plain seconds, and `interval` comes from the current config (`null` means no Refresh).
   - **No stale timer.** The schedule stores only what happened: when the last complete load finished, and the current backoff. It works out the next load from the interval in force when asked, so a reload that changes `refresh_hours` takes effect immediately. That includes turning Refresh on.
   - **Retries.** Incomplete loads retry after 60 s, then 120 s, 240 s and so on, capped at the interval (24 h when there is none). A complete load resets this to 60 s. A load that could not be started counts as an incomplete load.
   - **Timeout.** A load running for more than 10 minutes gets `cancel` and counts as incomplete.
   - **Changed sources.** `sourcesChanged()` while a load is running also gets `cancel`, because that load's sources are out of date. This cancel does not count as a failure: the backoff resets and the next load starts at once. While idle, the next load starts at once.
   - **The supervisor.**
     - It keeps signals, Reload, the load task and cancelling. On `cancel` it cancels the task, destroys any lists the task returns, and calls `finished(now, false)`; the schedule knows why it asked.
     - The task only loads. The supervisor calls `replaceLists` after awaiting it, so a superseded load can never swap in old lists.
     - The supervisor has no tests, because it holds no rules any more. The schedule's tests use plain integer times.
   - **Docs.** `refresh_hours: 0` means "only at start, and when a reload changes the sources", which is what the code always did. The comments in `config.example.yaml` and `config.zig` that say "and on reload" are corrected.
3. **Upstream server exchange** (`upstream.Server`, a tagged union of `Plain` and `dot.Tls`).
   - **Interface.** `exchange(io, query: dns.UpstreamQuery, out, deadline)` returns the server's answer to exactly that query.
   - **What each adapter does.** The adapter picks a random query ID and puts the original back, so callers never see it. It matches the answer by sender, ID and question.
     - Plain uses a fresh UDP socket and falls back to TCP when the answer is truncated.
     - TLS keeps the connection pool, checks certificates, and retries once on a stale connection.
   - **What stays in `Upstream`.** Removing EDNS options before forwarding, the failover order and the preferred server, treating REFUSED as "try the next server", and loading the CA certificates once.
   - **Shared certificates.** Each `dot.Tls` gets a pointer to `Upstream`'s CA bundle when it is created. `exchange` never mentions it.
   - **The query value.** `dns.rewriteForUpstream` returns `dns.UpstreamQuery { bytes, question_end }`, and the answer check becomes `query.isAnswer(response)`. This replaces passing `question_end` alongside the bytes.
   - **Why a tagged union.** The two adapters are a closed set. There is no test adapter, and a future transport such as DNS over HTTPS would be a third variant.
   - **Naming.**
     - The configured value (IP address, port, TLS name) is renamed `upstream.ServerAddress`.
     - `Endpoint` goes away.
     - `Trust`, `Pool` and `Connection` become private to `dot.zig`, apart from what `Upstream` needs to own the bundle.
   - **Timeout.** One deadline, `now + timeout_ms`, covers everything an adapter does for one server, including the TCP fallback and the TLS retry. The worst case before trying the next server is exactly `upstream.timeout_ms`. Today the TCP fallback restarts the clock.
   - **Tests.**
     - Stub servers on loopback (UDP and TCP on an ephemeral port, scripted per query) test the plain adapter and failover through the real interfaces. That covers answers, spoofed packets, the TCP fallback within the deadline, timeouts, REFUSED, the preferred server, all servers failing, and removing EDNS options.
     - The TLS adapter gets one opt-in test, `zig build test -Dnetwork`, which sends two queries to a public DNS-over-TLS server. It covers the handshake, certificate checks and connection reuse. Normal test runs stay offline.

All three items are settled. *(ADR-0006 adds the `forward` decision, `blockAlias` and a TTL on `private`.)*

## Considered options

- **End-to-end tests only, on loopback.** Running the whole server against a stub upstream would cover the same behaviour without restructuring. But every test would need sockets and a stub, and the logic would stay spread across the same modules.
- **A TLS stub server on loopback** for testing the TLS adapter offline. Zig's standard library has a TLS client but no TLS server.
- **Making the TLS connection pool generic** so its staleness logic can be tested with fake connections. That would add a seam only for tests, around about 20 lines of logic.
- **Keeping the last good copy of each failed source** instead of choosing between whole sets of lists. This is the most precise way to handle a partial load. But `Lists` merge every source into one block set and one allow set, so it would need one set per source. That means more lookups per query and a redesign of list storage.
