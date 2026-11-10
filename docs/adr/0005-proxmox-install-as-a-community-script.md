---
status: accepted
---

# The Proxmox installer is a community script, built on GitHub releases

zinkhole is meant to run in Proxmox, one small container per node. Users who know the Proxmox VE community scripts expect exactly their behaviour: the Debian/Alpine choice, Default and Advanced settings, and an `update` command inside the container. zinkhole is not part of the official community-scripts project, whose eligibility rules (an app at least 6 months old, 600+ GitHub stars) it does not meet.

**Decision.** The installer is a community script in the community scripts' own layout, run by their engine (`github.com/community-scripts/core`), exactly as their scripts are (for example AdGuard Home's). zinkhole itself comes from this repository's GitHub releases.

## Releases

- Public GitHub releases, created by CI when a tag `v<version>` is pushed. The version lives only in `Cargo.toml`, so `zinkhole --version` always matches the release; CI refuses to publish a tag that does not match it.
- A release carries the static `x86_64` and `aarch64` musl binaries, `update.sh`, `zinkhole-deploy.tar.gz` (`deploy/install.sh`, the service files and `config.example.toml`) and `LICENSE`, with `SHA256SUMS` over all of them. The deploy bundle replaces GitHub's on-demand source archive, whose checksum we cannot publish.
- **Integrity.** `SHA256SUMS` from the same release protects against corrupted or truncated downloads, not against someone who can publish to the GitHub project. That risk is accepted for a homelab project.

## The installer

- `deploy/proxmox/ct/zinkhole.sh` runs on the node. It sets `COMMUNITY_SCRIPTS_URL` to this repository (`raw.githubusercontent.com/jroosing/zinkhole/main/deploy/proxmox`) and sources the engine's `build.func`. The engine does everything about the container: the Debian/Alpine choice, the Default and Advanced settings, creating it, the description, tags and the summary.
- `deploy/proxmox/install/zinkhole-install.sh` runs inside the new container, fetched by the engine from the same base URL. It downloads the latest release, checked against `SHA256SUMS`, asks for the role (ADR-0002) and writes the config:
  - DNS over HTTPS upstream servers, the HaGeZi Pro blocklist, and the Metrics on the HTTP port, 5380 (ADR-0006), listening on `0.0.0.0` (still only for `server.allow_clients`), because the engine does not tell the script whether the address is static.
  - With IPv6, the container's own global IPv6 networks are added to the default `server.allow_clients`, which covers no global IPv6 prefix.
  - An origin gets a secret from `zinkhole secret`, shown at the end with the command for a replica; a replica is asked for the origin's URL and secret. `ZINKHOLE_ROLE`, `ZINKHOLE_ORIGIN` and `ZINKHOLE_SECRET` answer up front.
- It installs through `deploy/install.sh`, which checks the config with the new binary, installs the service (systemd or OpenRC), starts it and fails unless it answers.

## `update`

- `update` inside the container is the engine's: it runs `ct/zinkhole.sh` again, whose update step upgrades the OS packages and runs the latest release's `update.sh --skip-os`, checked against `SHA256SUMS`. Each release brings its own updater, so containers never run a stale one.
- `update.sh` exits if the latest release is not newer than `zinkhole --version` (compared with `sort -V`, never downgrading); downloads the binary and the deploy bundle and checks them; runs the new binary's `check` against the current config before changing anything; keeps the old binary as `zinkhole.old`; and installs through `deploy/install.sh`, which restarts the service and puts the old binary back if the new one does not answer within 15 seconds.
- On an origin, `update` reminds the user to update the replicas first: a newer origin may serve a setting an older replica does not know, which the replica then refuses (keeping its last good settings).

## Consequences

- The scripts are served from `main`, and the engine from the community scripts' `main`: neither is pinned or checksummed, as for every community script. A change pushed to `main` reaches new installs at once.
- Container settings use the engine's `var_*` variables and `mode=default`.
- The engine asks once whether to send anonymous diagnostics to the community scripts (off unless accepted).

## Considered options

- **Installers of our own** that imitate the community scripts. They never match exactly, and every engine improvement would have to be copied.
- **Copying the engine into this repository.** Exact, pinned and checksummable, but about 15,000 lines to keep in step by hand.
- **Pinning the engine to a commit.** Protects against a breaking engine change, but `update` would keep running against the old engine, and community scripts never do this.
- **Signed checksums** (a key kept off GitHub) or **Sigstore**. Both protect against a compromised GitHub project, at the cost of an extra step per release and extra tooling on every node.
- **A private project with a token on each node.** It puts a secret on every container.
