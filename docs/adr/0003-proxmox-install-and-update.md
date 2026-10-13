---
status: accepted
---

# Proxmox install scripts and an `update` command, built on GitLab releases

zinkhole is meant to run in Proxmox, one container per node. We provide community-script-style installers and an `update` command inside the container that upgrades the OS packages and the zinkhole binary. They work from this repository's own releases. They are not part of the official community-scripts project, which only accepts new scripts for applications that meet its eligibility rules (an app at least 6 months old, 600+ GitHub stars, GitHub release tarballs).

## Decision

**Releases.**
- Public GitLab releases, created by CI when a tag `v<version>` is pushed. The version lives only in `build.zig.zon`; `main.zig` takes it from there at build time, so `zinkhole --version` always matches the release.
- The release job refuses to publish if the tag does not match `build.zig.zon`.
- CI runs the offline tests on every push, and on a tag also cross-compiles static `x86_64-linux-musl` and `aarch64-linux-musl` binaries with the Zig version the Dockerfile pins, writes `SHA256SUMS`, and attaches everything.
- The release also carries the Proxmox scripts: `zinkhole-debian.sh`, `zinkhole-alpine.sh`, `lib.sh` and `update.sh`. All scripts download from one base URL variable, so another host could be used later.

**Integrity.** `SHA256SUMS` from the same release protects against corrupted or truncated downloads. It does not protect against someone who can publish to the GitLab project. That risk is accepted for a homelab project; see the considered options.

**Two installers, one library.**
- `zinkhole-debian.sh` (Debian 13) and `zinkhole-alpine.sh` (Alpine) run on a Proxmox node. Each sets a few variables (template, package commands, nesting) and fetches `lib.sh` from the same release, so an old script never mixes with a newer library. `lib.sh` holds the shared work: prompts, checks, `pct create`, and installing inside the container with the existing `deploy/install.sh`.
- The container is unprivileged, with 1 vCPU, 128 MB RAM and 1 GB disk. Debian needs `nesting=1` (the systemd sandbox); Alpine does not (OpenRC has no sandbox). It gets a static IP, because clients need a fixed DNS address, on `vmbr0` with an optional VLAN, and is named `zinkhole-<node>`.
- The script asks for a role: standalone, origin or replica (ADR-0002). An origin gets a generated secret (`openssl rand -hex 32`), printed once, with `sync.serve` on the container's address. A replica is asked for the origin's URL and the secret (not echoed), and gets no `blocking` or `local` sections. Every question can be answered by an environment variable (`ZINKHOLE_ROLE`, `ZINKHOLE_IP`, `ZINKHOLE_ORIGIN`, `ZINKHOLE_SECRET`, …) for unattended installs. The config stays world-readable, as the systemd unit requires; the container has no other users.

**`update`.**
- `/usr/local/bin/update` is a small stub, identical on Debian and Alpine. It downloads `update.sh` and `SHA256SUMS` from the latest release, verifies the checksum, and runs the script. Each release therefore brings its own updater and containers never run a stale one.
- `update.sh` then: upgrades the OS packages (`apt full-upgrade` or `apk upgrade`); exits if the latest release is not newer than `zinkhole --version` (compared with `sort -V`, never downgrading); downloads the binary and checks its SHA-256; runs the new binary with `--check` against the current config before changing anything; keeps the old binary as `zinkhole.old`, swaps, restarts and runs `--healthcheck`; and restores `zinkhole.old` if the health check fails within about 15 seconds.
- `zinkhole --check` is new: it parses and validates the config and exits 0 or 1, with no network access. `--test` is unchanged. It was not used for this because it also downloads every blocklist and fails when one source is down, which would block a security update.
- On a node whose config has `sync.serve`, `update` prints a reminder first: update the replicas before the origin. A newer origin may serve a setting an older replica does not know; the replica then refuses the whole sync, keeps its last good settings, and logs an error, which is why the order is advice and not enforced.

## Considered options

- **Submit to the official community scripts.** Not possible yet (eligibility rules above), and its helpers assume GitHub releases. Because every script reads its base URL from one variable, a GitHub mirror and a submission stay possible later.
- **Private project with a token on each node.** It puts a secret on every container, and a root `update` that carries it.
- **Signed checksums** (an Ed25519 key kept off GitLab, public key in the scripts, verified with `openssl`) or **Sigstore/cosign.** Both protect against a compromised GitLab project. Not chosen: an extra step per release and, for cosign, extra tooling on every node, for a homelab project. Worth revisiting if zinkhole gains users beyond the author.
- **Releases built by a local `release.sh`.** No CI to maintain, but builds depend on one laptop's state and nothing runs the tests on a tag.
- **Only one OS.** Debian alone is what most users know; Alpine alone is smaller. Both are offered because their init systems and package managers are already supported.
- **One script with an `--os` flag, or two self-contained scripts.** The first was rejected because separate scripts per OS were requested; the second because every fix would have to be made twice.
- **An updater copied into the container once, or driven from the Proxmox node with `pct exec`.** The first goes stale; the second needs a second entry point that someone with only the container does not have. An "update all nodes" helper can be added later.
- **Enforcing the update order** (replicas report their version and the origin's updater refuses to run while one is older). It needs a new endpoint and state for a homelab of two to five nodes.
