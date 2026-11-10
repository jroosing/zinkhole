---
status: accepted
---

# The Metrics and Sync share one HTTP port

zinkhole serves two things over HTTP: the Metrics, for a monitoring system, and an origin's Policy settings, for its replicas (ADR-0002). Both go only to allowed clients, and both are small.

**Decision.** One section, `[http]` with `listen`, starts one HTTP listener per address. It serves:
- `GET /metrics`, always: the Metrics exist exactly when the listener does;
- `GET /sync`, on an origin (`sync.role = "origin"`, which needs the `[http]` section).

Other paths get 404, other methods 405. Only clients in `server.allow_clients` are answered; others have their connection closed on arrival. A request head must arrive within 2 seconds of connecting, a connection serves one request and lasts at most 10 seconds, and at most 16 are served at once. The port in the docs and the Proxmox installer is 5380.

## Considered options

- **Two ports**, one per purpose. Two listeners to configure, two ports to open, and two sections that both say "listen here over HTTP to allowed clients".
- **9153**, the port other DNS servers use for Prometheus metrics. Either works; one port for both purposes needed one number.
