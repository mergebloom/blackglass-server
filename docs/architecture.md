# Blackglass Server architecture

## Objective

Provide a stable, self-hosted implementation of the Sync control and data
planes expected by qualified Obsidian desktop clients. Client-release analysis
and adaptation live separately in Blackglass Bridge.

## Control plane

The Rust service provides one configured user and the account and vault
operations required to create, connect, migrate encryption, rename, and delete
a Sync vault. Registration, password-recovery, and business-subscription routes
return explicit administrator-managed JSON errors instead of transport errors.
Sharing reports an empty list and invite/remove operations fail cleanly in
single-user mode. Passwords are verified with Argon2id. Successful sign-in
creates a random 256-bit bearer session whose digest, expiry, and revocation
state live in SQLite.

## Data plane

The WebSocket service implements the observed request/response protocol and
stores encrypted Sync payloads as opaque data. Custom-password vault keys never
reach the server. Managed-encryption vaults instead retain the server-generated
recovery password required by the stock client, placing the operator inside
that mode's confidentiality trust boundary. File pushes use private staging
files and SQLite incremental BLOB writes; pulls are read in 2 MiB pieces.
Memory is therefore bounded by configured concurrency rather than attachment
size.

## Persistence

SQLite is the supported database for the single-node, single-owner deployment.
WAL commits use FULL synchronous durability. Startup, backup, restore, and
offline session revocation fail closed on unexpected schema objects or logical
state inconsistencies instead of silently repairing an unknown database.
Recognized older schemas are upgraded only through an offline, copy-first
command whose per-version validation runs inside each migration transaction.
SQLite connections use defensive mode with trusted schemas disabled.
Current revisions store encrypted paths, encrypted hashes, and encrypted file
bodies. A separate server timestamp supports history even when a deletion has
zero file timestamps. The service is content-blind but not metadata-blind:
sizes, timestamps, extensions, device labels, and account identity remain
visible.

## Compatibility boundary

Blackglass Server owns the durable protocol contract. Blackglass Bridge owns
release-specific endpoint changes and qualifies each new desktop renderer.
That boundary allows server upgrades and client-release maintenance to proceed
independently. Unknown client protocol changes must fail qualification rather
than being guessed at in production.

Every current Bridge qualification report is bound to the server binary's
reported semantic version, byte size, architecture, and SHA-256. Rebuilding or
renaming a binary creates a new artifact that must earn a new client E2E record.

## Security posture

- Production origins use HTTPS and WSS through a reverse proxy.
- Native installs and OCI images default to loopback; qualified Linux Docker
  uses host networking behind host Caddy without published plaintext ports.
- Endpoint authorization uses exact origins.
- Account tokens and vault key material are never logged.
- Custom-password vault secrets never reach the server; managed mode stores its
  server-generated recovery password and requires a stronger operator trust
  boundary.
- Password verification has a one-check memory bound and runs off the async
  reactor; a bounded fair queue and per-source limiter protect admission.
- Session tokens expire and can be revoked; only token digests are persisted.
- Upload frames, files, concurrent staging, and metadata fields are bounded.
- Backups use SQLite's online backup API and verify the exact schema, migration
  history, logical invariants, integrity, and foreign-key consistency.
