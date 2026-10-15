---
status: accepted
---

# Queries for upstream servers are forwarded from a pool of slots

Each UDP worker used to answer a query from start to finish, the upstream round trip included. With the default 4 workers per address, at most 4 queries were with an upstream server at any moment. A page load with 50 new names then took about 300 ms (at a 20 ms round trip), and blocked, local and cached answers waited behind them. Measured on one CPU: 168 upstream queries per second, against 13,500 for AdGuard Home and 19,600 for blocky.

**Decision.** A UDP worker answers what it can itself: refusals, local records, blocked and private names, and cache hits. A cache miss goes to a **forwarding slot**, and the worker goes straight back to receiving. A fixed pool of slots (`upstream.max_in_flight`, 64 by default) each runs the existing upstream exchange, then caches and sends the answer.

## How it works

- **Slots.** They are allocated at startup, each with room for one query and one answer, so forwarding allocates nothing per query. Each slot has a task of its own that waits for work.
- **A full pool fails at once.** When every slot is busy, the worker answers SERVFAIL right away (counted as a `failed` Outcome) and does not wait for a slot. A warning is logged at most once a minute. Memory and threads stay bounded, even when an allowed client floods the server with uncached names.
  - This happens when more than 64 uncached queries are in flight at the same moment, which is over 3,000 per second at a 20 ms round trip, so not in normal use. The case that matters is an upstream outage: then every forwarded query holds its slot for the whole timeout (2 s per server).
  - Workers waiting for a slot, as first built, made local names and cache hits wait too. Measured with a dead upstream and 80 uncached queries outstanding: `nas.lan` took 1.5 s. An outage is exactly when local names matter most.
  - With SERVFAIL, clients learn at once that this server cannot help, and retry or ask their other DNS server. Silently dropping the query, as Unbound does when its request list is full, would leave them waiting for their own timeout of 1–5 s.
- **Unchanged exchanges.** A slot uses `Upstream.forward` as before:
  - a fresh socket with a random source port and a random query ID per exchange;
  - only answers from the server's address, with the same ID and question, are accepted;
  - TCP when the answer is truncated;
  - DNS over TLS with certificate checks;
  - failover in the configured order.
- **The same answers.** Truncation for the client's UDP size, caching, Outcome counting, Metrics and the query log work as before. TCP clients are still answered by their worker, start to finish; TCP is only used for truncated answers. *(Amended October 2026: TCP connections now have a pool of 16 connection slots of their own, shared by all listeners, so a few idle TCP clients cannot hold up the others; a connection that finds every slot busy is closed at once.)*
- **DNS over TLS.** Parallel queries mean parallel connections. A server gets at most 16 connections at once. An exchange beyond that waits for one to come free, within its own timeout: a busy server is only treated as failed when that timeout passes, like any other timeout. Up to 8 idle connections are kept per server, so a burst does not need a new handshake for each query.
- **Shutdown.** Stopping the server cancels the slots, including exchanges in flight, before it closes the sockets they answer on.
- **Memory.** Two defaults would have cost more than the slots themselves, so they changed:
  - In safe builds, `alloc` fills new memory with `0xAA`, which made all 64 slots resident at once (4.4 MB). The slots are allocated without that fill: a slot's bytes are always written before they are read.
  - Zig gives every thread a 256 KiB alternate signal stack, so that a stack overflow can still print a stack trace. With 64 slot threads that was 18.7 MB. It is turned off (`std_options.signal_stack_size = null`). A stack overflow still stops the process at the guard page, and the service manager restarts it; only that trace is lost.

## Measured

One CPU, 256 MB, Hagezi Pro (194,000 domains), an upstream answering in 20 ms over UDP, load from dnsperf. Before the change, with 4 workers:

| | Before | After (4 workers, 64 slots) |
|---|---|---|
| Upstream queries per second | 168 | 2,519 |
| 50 new names at once, all answered after | 304 ms | 44 ms |
| Blocked or cached queries per second | 341,000 | 341,000 |
| Memory with the lists loaded (after the tests) | 9.5 MB (10.2 MB) | 9.4 MB (12.9 MB) |

For comparison, in the same setup: blocky 19,600 upstream queries a second and the 50 names after 46 ms, at 29 MB (96 MB after the tests).

## Why this shape

- **The code that touches upstream packets is unchanged.** Only who runs it, and when, changes. Its defences against spoofing are the ones that were reviewed and tested.
- **A fixed pool, not a task per query.** The pool keeps memory predictable, and it gives backpressure without a separate limit.
- **One TLS query per connection at a time.** Zig's TLS client is not safe to read and write from different threads: when the server updates its keys, the reader replaces the client's write keys. Pipelining queries on one connection would need a single task that both writes and reads, and so a different design.

## Considered options

- **More workers.** 64 workers already reach about 2,400 upstream queries per second. But blocked and cached answers still wait behind upstream ones, and every worker carries buffers for both kinds of traffic.
- **An event loop that polls all upstream sockets,** as dnsmasq and Unbound do. It costs far less memory per query in flight and reaches tens of thousands of queries per second. But it rewrites exactly the security-sensitive code: answer matching, timeouts, failover, TCP fallback, and a TLS driver for pipelining. A home network does not need that throughput.
- **Zig's evented `Io`** (io_uring, kqueue). It is still experimental, and container runtimes often block io_uring.
- **Combining identical queries in flight**, so that 10 clients asking for the same new name cause one upstream query. It can be added on top later.
- **Pipelining DNS over TLS:** many queries on one connection, answered out of order. This was designed far enough to judge, then rejected for now, because the gain is small for a home network and the code would be where memory-safety bugs live.
  - **The servers support it.** Measured in October 2026: Quad9 (9.9.9.9 and 149.112.112.112) and Cloudflare (1.0.0.1) answer pipelined queries out of order, popular names first. Both accept 300 queries in flight on one connection and answer them all within 50 ms.
  - **The gain is small.** 50 new names at once to Quad9 (7 ms away) take 108 ms from a cold start and 68 ms on warm connections. Pipelining would bring that to an estimated 20–40 ms. A page load has far fewer new names; for 10 names the difference is about 10–15 ms, and only the queries beyond the 8 warm idle connections pay for a handshake. Pipelining would also mean fewer TLS handshakes per burst.
  - **The cost is high.** It needs a pending-query table per connection, a handoff of answers between tasks, and reference counting of connections.
  - **Zig's evented `Io` would not make it simpler.** It makes the slots cheaper, not pipelining: Zig's TLS client still lets its reader change the write keys, whatever task runs it.
  - **If it is ever built, two decisions are already made:**
    - *Sharing a connection:* one reader task per connection, while slots encrypt and send under one lock, so records go out in sequence-number order. The reader waits, without the lock, until a whole encrypted record is buffered, then decrypts only that record under the lock, so the lock is never held while waiting for the server. This is safe because `std.crypto.tls.Client` reads its input before it touches any keys, and only decryption changes keys, including the client's write keys on a key update.
    - *Handing over answers:* each connection has a table of pending queries. IDs are random and unique per connection, and an answer is accepted only if both its ID and its question match. The reader removes the entry, copies the answer into the slot's buffer and wakes the slot, all under the table lock. A slot that times out or is canceled removes its own entry under the same lock before it returns, so the reader never writes into a buffer whose slot has left.
  - **Still open:** freeing a connection that the pool, its reader and pending slots all refer to (reference counting was proposed); the number of connections per server; and retrying the queries of a connection that dies.
