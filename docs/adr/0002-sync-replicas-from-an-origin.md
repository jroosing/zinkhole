---
status: accepted
---

# Replicas pull their Policy settings from an origin

Running two zinkhole instances in a homelab is common, for redundancy. Settings should then be edited in one place only.

**Decision.** One instance is the **origin**. It serves the Policy settings (its `blocking:` and `local:` sections) over HTTP. Other instances are **replicas**: they poll the origin, check what they get, and apply it like a Reload. A replica writes the last settings it accepted to one state file, so it can start without the origin. Nothing ever writes to an instance's config file.

## How it works

**Config.** The role follows from the `sync` section:
- `sync.serve` (listen addresses) makes an instance the origin.
- `sync.origin` (a URL) makes it a replica.

Both instances need `sync.secret` (at least 32 characters). Replicas also take `sync.interval` (default 60 s). Having both `serve` and `origin` is an error, so there are no chains. The `sync` section changes only on restart.

**What is synced.** Only `blocking` and `local`: everything the Policy is built from, which is what a Reload already applies instantly. Everything else stays in each instance's own file: `server`, `upstream`, `cache`, `log` and `sync`.
- A replica's file must not contain `blocking` or `local`.
- Lists are not synced, only their sources. Each instance downloads its own lists.

**What the origin serves.**
- The exact text of its `blocking:` and `local:` sections as of its last successful load, comments included. A half-edited file never reaches replicas.
- One endpoint, `GET /sync`, over plain HTTP. It answers only clients in `server.allow_clients`, one request at a time, and its size is bounded by the 1 MiB config limit.

**Checking what arrives.**
- Every poll carries a random nonce and the fingerprint (`ETag`) of the settings the replica has.
- The origin signs nonce, fingerprint and body with HMAC-SHA256 and the shared secret. It signs `304 Not Modified` answers too.
- A replica accepts only answers signed over its own nonce. A replayed old answer is rejected, so a rollback needs the secret.
- No clocks are involved. Raspberry Pis boot with the wrong time.

**Applying a sync.**
- The replica parses the text with the normal config parser and validation, then calls `policy.applyConfig`. If the list sources changed, it calls `schedule.sourcesChanged()`.
- Invalid text (for example from a newer origin version) leaves the last good settings in place, and an error is logged.
- SIGHUP on a replica reloads its own file and syncs immediately.
- A replica keeps serving its last settings when the origin is unreachable, and logs a warning when syncs keep failing.

**The state file.**
- A replica writes `/var/lib/zinkhole/synced.yaml` after each accepted change: the served text, with the signature and nonce in a first-line comment.
- At startup the replica checks the signature and uses the file until the first sync succeeds.
- systemd: `StateDirectory=zinkhole`. Docker: a named volume. Everything else stays read-only.

**Promotion is manual.** Append the state file to the config, replace `sync.origin` with `sync.serve`, and restart. A returning old origin must be turned into a replica, or there are two origins.

**Tests.**
- In-process tests run the origin and replica over loopback: serving, signatures and replay, applying, the state file, and config errors.
- `deploy/sync/` has a Docker Compose setup with an origin and a replica, plus a script that tests propagation, SIGHUP and starting from the state file.

## Why this shape

- **Pull keeps zinkhole read-only.** The config is never written, and the new network code only reads. A replica that was down catches up on its next poll; push would need retries.
- **Plain HTTP with a signature, not HTTPS.** Zig's standard library has no TLS server. The signature protects integrity and freshness, which is what matters: synced settings decide DNS answers. They are not secret, since any allowed client can already query the local records. A `sync.origin` URL may still be `https://` if a reverse proxy sits in front.
- **The state file is a deliberate exception to "no state on disk".** It applies to replicas only and is one file. Without it, a replica restarted while the origin is down would serve no local records and block nothing, which defeats redundancy exactly when it is needed.

## Considered options

- **Push: the origin writes the config to replicas over HTTP.** This is the adguardhome-sync and Technitium style. Those projects already have a write API with logins and a config they write themselves. zinkhole would need both, plus write access through its sandbox, and retries for replicas that were down.
- **An external sync tool** (git pull, Syncthing, or cron plus SIGHUP). It needs no code, but it is a moving part on every host, and it overwrites per-instance settings unless the files are split.
- **Replicas pull from a URL the user hosts.** This avoids an HTTP server in zinkhole, but "the origin" becomes a file server that also has to be reliable.
- **Syncing the whole config file.** It would expose the secret and per-instance settings such as listen addresses. `server`, `upstream` and `cache` cannot be applied without a restart anyway.
- **Long-polling or notifications from the origin.** Changes would arrive faster, but this needs held connections or an inbound port on replicas. Changes made by hand do not need sub-minute propagation.
- **Version numbers or timestamps for freshness.** They depend on the clocks the nonce avoids.
- **Automatic promotion.** It needs leader election and risks split-brain. Technitium does not do it either.
