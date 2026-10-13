---
status: proposed
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
   - **Tests.**
     - Policy tests start from config text. Lists come from temp files through the real `Lists.load`.
     - `LocalZone`'s behaviour tests move up to the Policy. The `blocklist`, `DomainSet` and `parseReverseName` tests stay.
     - `Resolver.handle` gets tests too, using a real `Cache` and an `Upstream` with no servers. That covers turning each decision into a DNS response, refusals and truncation, with no sockets.
2. **Refresh schedule.** A pure module takes the current time and events and returns two things: when to load the lists next, and whether newly loaded lists replace the current ones. The events are: a load finished complete, partial or failed; a load timed out; a reload changed the sources. The supervisor keeps signal handling, the load task and the swap, and asks the schedule what to do.
3. **Upstream server exchange.** Each upstream server gets one exchange call that hides its transport:
   - plain DNS, over UDP and TCP when the answer is truncated;
   - DNS over TLS, with the connection pool, the CA certificates and one retry when a reused connection is stale.

   `Upstream` keeps only the failover order. Failover tests use stub servers on loopback that speak plain DNS, rather than a mock adapter. That way they run the real UDP and TCP code, including the spoofing checks.

The Policy's interface (item 1) is settled. Items 2 and 3 will each be designed before their refactor starts.

## Considered options

- **End-to-end tests only, on loopback.** Running the whole server against a stub upstream would cover the same behaviour without restructuring. But every test would need sockets and a stub, and the logic would stay spread across the same modules.
