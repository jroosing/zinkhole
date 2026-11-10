---
status: accepted
---

# Sync answers are sealed with an AEAD

Synced settings decide the network's DNS answers: whoever can change them in transit can point any name anywhere. They also show the network's local hostnames and blocking setup. Sync runs on the plain HTTP port (ADR-0006), on a LAN that cannot be assumed friendly.

**Decision.** Each answer is sealed, with standard constructions:

- A replica sends a fresh random nonce with each request.
- The origin derives a one-time key with **HKDF-SHA256** from the shared secret and that nonce, and seals its answer with **XChaCha20-Poly1305** under a fresh random nonce of its own.
- Every answer a replica accepts is a 200: its sealed payload says "unchanged" or carries the settings (TOML, the same `serde` structs as the config). A 304 is not used, as it cannot have a body.
- The ETag is a fingerprint keyed with the secret, so it reveals nothing about the settings, and it is the associated data, so it is authenticated too.
- This gives integrity, freshness (a different key per request, so a replayed answer does not open) and confidentiality, from one standard primitive.
- The replica's **state file** is sealed the same way, under a key derived for that purpose: tampering is detected, and it cannot be read on disk without the secret.
- The **secret** is a generated 256-bit value (`zinkhole secret`); the config check rejects anything else. It is held in a `secrecy` type, never logged, and compared in constant time.

Crates: `hkdf`, `hmac`, `sha2` and `chacha20poly1305` from RustCrypto.

## Considered options

- **An HMAC over a hand-built string** (nonce, fingerprint, body), with the settings in plain text. Works, but it is a home-made construction and leaves the settings readable on the LAN.
- **HTTPS with the origin's self-signed certificate pinned on replicas.** The textbook answer, but the origin must keep a certificate, every replica needs its fingerprint, and rotating it means editing every replica. Because the Metrics share the port (ADR-0006), `curl` and dashboards would need `-k` or the pin.
- **Mutual TLS.** Strongest, but certificates on both sides is too much setup for a homelab.
