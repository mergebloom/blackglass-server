# Security model

## Trust boundary

The copied desktop clients and their authenticated local users are trusted. Caddy terminates
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
| Password theft | Account hashes live only in mode-0600 SQLite state; offline commands read plaintext from standard input; generated hashes use the qualified maximum Argon2id work policy and imported hashes are bounded before verification |
| Token theft | Random 256-bit user-bound sessions, SHA-256 digests at rest, bounded lifetime, immediate sign-out revocation, and scoped offline revocation commands |
| Login guessing/CPU exhaustion | Uniform credential error with a valid dummy hash, one bounded Argon2 check off the async reactor, an eight-waiter fair queue, a six-attempt/60-second per-source bucket, and forwarded addresses trusted only from one exact configured proxy |
| Cross-origin control calls | Bounded exact renderer-origin allowlist, matched-origin preflight responses, bounded 64 KiB JSON bodies |
| Memory/disk exhaustion | 2 MiB frames, bounded global and per-user WebSocket/upload ceilings, four unauthenticated sockets per source, declared-size/piece validation, per-file cap, atomic global and per-owner retained-ciphertext quotas, upload/response/database semaphores, private staging files, and external disk monitoring |
| Partial uploads/crashes | Unique mode-0600 staging files, a bounded progress deadline that releases capacity and removes idle partials, commit only after exact byte/piece match and fsync, cleanup on every commit result, and startup cleanup |
| SQLite corruption or hostile schema | WAL with FULL synchronous commits, foreign keys, defensive/untrusted-schema connections, copy-first offline per-version migrations with transactional validation/rollback, graceful checkpoint, online backup API, exact schema/logical verification, and restore drills |
| Endpoint rotation | Canonical data-host validation, startup equality gate across persisted vaults, and a verified-backup-first transactional rebind command |
| Data leakage through logs | Structured events omit credentials, tokens, ciphertext paths/hashes/bodies, and managed vault recovery passwords |
| Data leakage through metrics | Authorization and SQLite counters use fixed operation/reason labels only; no tenant, account, vault, session, database error, or payload value becomes a label |
| Sharing enumeration/abuse | Invitations accept only existing active local accounts, return a uniform unavailable error, use bounded keyed target digests in memory, and enforce source, user, distinct-target, and global rolling-hour budgets |
| Privilege escalation | Static unprivileged systemd user, empty capabilities, strict filesystem/device/kernel protections, syscall and address-family restrictions |
| Client drift | Version-specific deterministic patch anchors, upstream/generated hashes, updates disabled in the copied profile, and official-client E2E qualification |
| Dependency supply chain | Locked crates, a checksum-pinned advisory/license/source scanner, explicit license allowlist, Cargo plus native/runtime notices, digest-pinned build images, and commit-pinned CI actions |
| Operations endpoint exposure | Health, readiness, and metrics remain loopback/private by default; the example public Caddy route returns 404 for them |
| Admin console exposure | Disabled by default on a distinct loopback listener; exact loopback HTTP authority; independent fixed-shape, hash-only bearer authentication with a bounded per-source failure budget that never blocks valid credentials; bounded API projections; restrictive CSP and no-store responses; no admin routes on Sync listeners |

## Residual risk and exclusions

This is an authorized compatibility implementation, not an Obsidian-supported
server. The client protocol can change without notice. The server does not
provide public registration, fine-grained collaborator roles, high
availability, object storage, mobile qualification, malware
scanning, quotas per vault, or protection against a compromised desktop
client. A malicious or stolen authenticated client can read and mutate every
vault authorized for that user.

Removing a collaborator stops future server access and closes that user's live
vault connections, but it cannot erase ciphertext or plaintext already
synchronized to the collaborator's device. The stock sharing protocol also has
no member-specific key wrapping. Restoring confidentiality after a compromise
requires a new remote vault encryption key and complete re-encryption.

A compromise of a managed-encryption deployment can expose its stored recovery
password and therefore its vault plaintext. A custom-password deployment does
not store that password, but host compromise can still delete, replay, or
replace ciphertext and metadata.

Restore and destructive vault replacement retain high-entropy, owner-bound
retired vault IDs so an authenticated stale client can enter the renderer's
recovery flow. Invalid, expired, token-shaped, cross-tenant, and arbitrary
identifiers receive only the generic authentication error.

SQLite protects transactional consistency, not host compromise. Encrypt the
host and off-host backups, patch the OS/Caddy, restrict administrative access,
and monitor disk space. Tested backups and a fresh client recovery drill are
the recovery boundary.

## Incident actions

1. Remove public proxy access while preserving the state directory.
2. Stop the Rust service and copy logs plus the failed database/WAL files for
   forensics.
3. Replace the affected user's password or revoke that user's sessions if a token or
   client may be compromised.
4. Verify the newest off-host backup, restore it to a new path, and run a fresh
   client recovery test.
5. Re-enable TLS endpoints only after `/ready`, integrity verification, and
   official-client sync pass.
