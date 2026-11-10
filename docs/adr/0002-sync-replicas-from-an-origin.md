---
status: accepted
---

# Replicas pull their Policy settings from an origin

Running two zinkhole instances in a homelab is common, for redundancy. Settings should then be edited in one place only.

**Decision.** One instance is the **origin**. It serves its Policy settings (its `[blocking]` and `[local]` sections) over HTTP. Other instances are **replicas**: they poll the origin, check what they get, and apply it like a Reload. A replica keeps the last settings it accepted in one state file, so it can start without the origin. Nothing ever writes to an instance's config file.

## How it works

**Config.** The role is explicit: `sync.role = "origin"` or `"replica"`. Both need the same `sync.secret` (256 bits, from `zinkhole secret`). A replica also takes `sync.origin` (the origin's HTTP port, e.g. `http://192.168.1.5:5380`), `sync.interval_secs` (default 60) and `sync.state_dir` (default `/var/lib/zinkhole`). An origin needs an `[http]` section (ADR-0006). There are no chains: a replica serves nothing.

**What is synced.** Only `[blocking]` and `[local]`: everything the Policy is built from, which is what a Reload applies at once. Everything else stays in each instance's own file: `[server]`, `[upstream]`, `[cache]`, `[log]`, `[http]` and `[sync]`.
- A replica's file must not contain `[blocking]` or `[local]`.
- Lists are not synced, only their sources. Each instance downloads its own lists.

**What the origin serves.** `GET /sync`: its Policy settings in force, as TOML, sealed for the replica that asked (ADR-0003). It answers only clients in `server.allow_clients`, and never serves more than replicas accept (the config file limit, 1 MiB).

**Applying a sync.**
- The replica checks the settings as it would its own file: invalid settings (for example from a newer origin), or ones that do not fit this instance (a forwarded zone pointing at the replica itself), leave the last good settings in place. The refusal is logged once per version and shown in the Metrics.
- Valid settings are put in force like a Reload: the Policy at once, and the lists again if their sources changed.
- A Reload on a replica re-reads its own file and syncs at once.
- A replica keeps serving its last settings when the origin is unreachable, warns after three failed syncs in a row, and notes when syncing works again.

**The state file.**
- A replica writes it after each accepted change, atomically, readable by its owner only, sealed with the secret (ADR-0003).
- At startup the replica checks that it can write there, and starts from the saved settings until the first sync succeeds.
- systemd: `StateDirectory=zinkhole`. Docker: a named volume. Everything else stays read-only.

**Promotion is manual.** Turn the replica into an origin (`sync.role = "origin"`, an `[http]` section, the Policy settings in its file) and restart. A returning old origin must be turned into a replica, or there are two origins.

**Tests.** In-process tests run an origin and a replica over loopback: serving, sealing and replay, applying, the state file and refusals. `deploy/sync/` has a Docker Compose setup with an origin and a replica, and a script that tests propagation, a Reload on the origin and starting from the state file.

## Why this shape

- **Pull keeps zinkhole read-only.** The config is never written, and the network code only reads. A replica that was down catches up on its next poll; push would need retries.
- **The state file is a deliberate exception to "no state on disk".** It applies to replicas only and is one file. Without it, a replica restarted while the origin is down would serve no local records and block nothing, which defeats redundancy exactly when it is needed.

## Considered options

- **Push: the origin writes the config to replicas over HTTP**, as adguardhome-sync and Technitium do. Those projects already have a write API with logins and a config they write themselves. zinkhole would need both, plus write access through its sandbox, and retries for replicas that were down.
- **Syncing the whole config.** Listen addresses, upstream servers and caches differ per host; only the Policy is shared.
- **Syncing the downloaded lists.** Larger transfers for no gain: each instance can download them itself.
