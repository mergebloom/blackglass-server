# Blackglass Server architecture

## Objective

Provide a stable, self-hosted implementation of the Sync control and data
planes expected by qualified Obsidian desktop clients. Client-release analysis
and adaptation live separately in Blackglass.

## Control plane

The Rust service provides durable SQLite-backed local users and the account and
vault operations required to create, connect, migrate encryption, rename,
delete, and share a Sync vault. Each vault has one durable owner and may have
bounded active collaborators; every session is bound to one user. Serving never
loads account credentials from environment variables. Registration,
password-recovery, and business-subscription routes return explicit
administrator-managed JSON errors instead of transport errors. Owners may
invite existing active local accounts and remove collaborators; collaborators
may leave using their own membership ID. Passwords are verified with Argon2id.
Successful sign-in creates a random 256-bit bearer session whose digest, user,
expiry, and revocation state live in SQLite.

## Data plane

The WebSocket service implements the observed request/response protocol and
stores encrypted Sync payloads as opaque data. Custom-password vault keys never
reach the server. Managed-encryption vaults instead retain the server-generated
recovery password required by the stock client, placing the operator inside
that mode's confidentiality trust boundary. File pushes use private staging
files and SQLite incremental BLOB writes; pulls are read in 2 MiB pieces.
At most two pull frames stream concurrently; readers queue between 2 MiB
pieces, so slow readers cannot monopolize pull capacity. A fair shared
memory-admission pool reserves three of four permits for password verification,
leaving one authenticated Sync lane available while Argon2 runs. Memory is
therefore bounded by fixed concurrency rather than attachment size. Reconnect
replay retains at most 16 notices with at most 512 KiB of event text per client
and releases memory admission after every notice, so slow readers cannot hold
the pool indefinitely.

Each authenticated connection has a registry-owned cancellation channel bound
to its session and vault. Online signout, membership removal, and destructive
vault replacement signal that channel directly. Every data mutation also
revalidates the exact session, active user, and owner-or-collaborator access
inside the same immediate SQLite transaction that commits the change, making
transaction order authoritative for revoke-versus-write races.

## Persistence

SQLite is the supported database for the single-node, multi-account deployment.
WAL commits use FULL synchronous durability. Startup, backup, restore, and
offline session revocation fail closed on unexpected schema objects or logical
state inconsistencies instead of silently repairing an unknown database.
Recognized older schemas are upgraded only through an offline, copy-first
command whose per-version validation runs inside each migration transaction.
SQLite connections use defensive mode with trusted schemas disabled.
Database work has a bounded worker queue, SQLite busy timeout, and dedicated
admin-query deadline. Fixed-cardinality metrics distinguish request and admin
snapshot pressure without database text or tenant identifiers.
Current revisions store encrypted paths, encrypted hashes, and encrypted file
bodies. A separate server timestamp supports history even when a deletion has
zero file timestamps. The service is content-blind but not metadata-blind:
sizes, timestamps, extensions, device labels, and account identity remain
visible.

## Compatibility boundary

Blackglass Server owns the durable protocol contract. Blackglass owns
release-specific endpoint changes and qualifies each new desktop renderer.
That boundary allows server upgrades and client-release maintenance to proceed
independently. Unknown client protocol changes must fail qualification rather
than being guessed at in production.

Every current Blackglass qualification report is bound to the server binary's
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
