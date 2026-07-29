# Security model

## Trust boundary

The copied desktop client and the single owner are trusted. Caddy terminates
public TLS. The Rust process and its SQLite/state directory are always trusted
to preserve availability and ciphertext integrity. For a custom-password E2EE
vault, they are not trusted with vault plaintext or the vault encryption
password because that password never reaches the server. For the client's
managed-encryption mode, the server generates, stores, and returns the recovery
password and is therefore also trusted for vault confidentiality. Operators
who require a zero-knowledge server boundary must use a custom vault password.

The server observes account timing, vault and revision counts, ciphertext
sizes, timestamps, extensions, device labels, and traffic patterns. It stores
encrypted paths, hashes, bodies, session-token digests, and revision metadata.
E2EE does not hide those facts.

## Primary controls

| Risk | Control |
| --- | --- |
| Internet exposure | Native and OCI defaults are loopback; the qualified Linux Docker topology uses host networking without published plaintext ports; Caddy is the only public TLS/WSS boundary |
| Password theft | Argon2id verifier supplied by a root-readable environment file; plaintext production configuration is rejected; accepted PHC work parameters are bounded before verification |
| Token theft | Random 256-bit sessions, SHA-256 digests at rest, bounded lifetime, sign-out revocation, and an offline revoke-all command |
| Login guessing/CPU exhaustion | Uniform credential error, one bounded Argon2 check off the async reactor, an eight-waiter fair queue, a six-attempt/60-second per-source bucket that refunds successful owner sign-in, and forwarded addresses trusted only from one exact configured proxy |
| Cross-origin control calls | Bounded exact renderer-origin allowlist, matched-origin preflight responses, bounded 64 KiB JSON bodies |
| Memory/disk exhaustion | 2 MiB frames, 16 default/maximum WebSockets, four unauthenticated sockets per source, declared-size/piece validation, per-file cap, upload/response/database semaphores, private staging files, and external disk monitoring |
| Partial uploads/crashes | Unique mode-0600 staging files, a bounded progress deadline that releases capacity and removes idle partials, commit only after exact byte/piece match and fsync, cleanup on every commit result, and startup cleanup |
| SQLite corruption or hostile schema | WAL with FULL synchronous commits, foreign keys, defensive/untrusted-schema connections, copy-first offline per-version migrations with transactional validation/rollback, graceful checkpoint, online backup API, exact schema/logical verification, and restore drills |
| Endpoint rotation | Canonical data-host validation, startup equality gate across persisted vaults, and a verified-backup-first transactional rebind command |
| Data leakage through logs | Structured events omit credentials, tokens, ciphertext paths/hashes/bodies, and managed vault recovery passwords |
| Privilege escalation | Static unprivileged systemd user, empty capabilities, strict filesystem/device/kernel protections, syscall and address-family restrictions |
| Client drift | Version-specific deterministic patch anchors, upstream/generated hashes, updates disabled in the copied profile, and official-client E2E qualification |
| Dependency supply chain | Locked crates, a checksum-pinned advisory/license/source scanner, explicit license allowlist, Cargo plus native/runtime notices, digest-pinned build images, and commit-pinned CI actions |
| Operations endpoint exposure | Health, readiness, and metrics remain loopback/private by default; the example public Caddy route returns 404 for them |

## Residual risk and exclusions

This is an authorized compatibility implementation, not an Obsidian-supported
server. The client protocol can change without notice. The server does not
provide multi-user authorization, sharing, public registration, high
availability, object storage, mobile qualification, malware
scanning, quotas per vault, or protection against a compromised desktop
client. A malicious or stolen authenticated client can read and mutate every
vault available to the single owner.

A compromise of a managed-encryption deployment can expose its stored recovery
password and therefore its vault plaintext. A custom-password deployment does
not store that password, but host compromise can still delete, replay, or
replace ciphertext and metadata.

Restore and destructive vault replacement retain high-entropy retired vault
IDs so stale clients can enter the renderer's recovery flow. A request with a
recorded retired ID and any token having the exact 64-character lowercase-hex
session shape receives `Vault not found` even if that token is no longer a
valid session; malformed token shapes and arbitrary missing IDs receive only
the generic authentication error. This intentional retired-ID existence signal
is the compatibility tradeoff that lets post-backup clients recover cleanly.

SQLite protects transactional consistency, not host compromise. Encrypt the
host and off-host backups, patch the OS/Caddy, restrict administrative access,
and monitor disk space. Tested backups and a fresh client recovery drill are
the recovery boundary.

## Incident actions

1. Remove public proxy access while preserving the state directory.
2. Stop the Rust service and copy logs plus the failed database/WAL files for
   forensics.
3. Rotate the account password hash and revoke all sessions if a token or
   client may be compromised.
4. Verify the newest off-host backup, restore it to a new path, and run a fresh
   client recovery test.
5. Re-enable TLS endpoints only after `/ready`, integrity verification, and
   official-client sync pass.
