# Phase 3 and Phase 4 implementation plan

Date: 2026-07-30

Protocol authority: [`docs/protocol/phase-3-4-client-demands.md`](../protocol/phase-3-4-client-demands.md), qualified against the preserved Obsidian 1.12.7 floor and the current Obsidian 1.13.4 candidate baseline.

## Goal

Build multi-account isolation first, then stock-client shared-vault collaboration, without destabilizing the deployed single-owner Sync service.

- Phase 3: durable users, user-bound sessions, owned vaults, and complete tenant isolation. Sharing routes remain unsupported.
- Phase 4: owner-managed collaborator membership and shared-vault Sync using the contract observed in Obsidian 1.12.7 and revalidated against 1.13.4.

The phases are separate production releases. Phase 4 cannot begin implementation until Phase 3's authorization boundary and adversarial tests pass.

“Tenant isolation” in these phases means authorization, confidentiality, and integrity isolation. Resource use is bounded per user and globally, but Blackglass does not promise reserved per-tenant capacity or a per-tenant availability SLA; a saturated shared process or SQLite database can still affect all users.

## Non-negotiable invariants

1. Every request starts from an authenticated user context. Client-supplied user IDs never grant authority.
2. Every vault operation authorizes that user against the requested vault before querying or mutating vault data.
3. Unknown, unauthorized, retired, and revoked vault resources have non-enumerating external failures. The only accepted exception is the separately documented, authenticated, rate-bounded existing-account disclosure created by immediate Phase 4 invitations.
4. Session tokens, password hashes, key hashes, salts, encrypted paths, encrypted file bodies, and raw database errors never enter logs, metrics, admin JSON, or test artifacts.
5. Custom E2EE passwords remain client-only and are shared out of band.
6. Production keeps the existing control/data/admin listener isolation and the read-only Phase 1 admin posture.
7. No application-level backup timer or backup service is reintroduced. Production migrations remain offline, copy-first, verified, and pre-activation rollback-ready; after the first accepted write, recovery is roll-forward only.
8. Existing revision ordering, replay, transfer framing, connection bounds, file limits, and SQLite resource limits remain bounded.
9. The exact qualified client artifacts and checksums are recorded for every compatibility release. Phase 3 and Phase 4 must pass both the preserved 1.12.7 compatibility floor and the current 1.13.4 candidate; a later candidate may replace 1.13.4 only through the same reviewed-baseline process.
10. A collaboration revocation stops future server access but is never described as erasing a collaborator's local copy.

## Workstream 0 — Turn client observations into executable contracts

### Task 0.1 — Extend the protocol inventory

Repository: `blackglass`.

Update:

- `tools/analyze-release.ts`
- `docs/client-audit-1.12.7.md` and the corresponding 1.13.4 audit/addendum;
- `docs/protocol/obsidian-1.12.7.md` and a versioned 1.13.4 delta or compatibility-matrix document;

Record and assert:

- `/vault/list` request key `supported_encryption_version` and response categories `vaults`, `shared`, and `limit`;
- sharing requests and exact consumed keys;
- shared-vault `share_uid`;
- share-list item keys `uid`, `email`, optional `name`, and `accepted`;
- `init.userId`, revision `user`, and the `usernames` operation;
- owned-vault versus shared-vault UI capabilities;
- absence of a renderer `/vault/share/accept` call and role fields.
- the 1.13.4 `/user/pow-challenge` route, its signup-only use, and its explicit unsupported Blackglass response;
- exact success bodies, error bodies, and HTTP behavior consumed by invite, remove, list, duplicate-invite, and unavailable-account flows in both qualified clients.

Do not store or redistribute renderer source. Generated evidence may contain route names, JSON field names, counts, hashes, and pass/fail results only.

### Task 0.2 — Add protocol types and synthetic fixtures

Merge in this order so the observed Blackglass client contract is the source for the server fixture:

1. In `blackglass`, extend `tests/client-adapter.test.ts` and `tools/analyze-release.ts` with scrubbed shape assertions.
2. In `blackglass-server`, update `packages/protocol/src/control.ts`, `packages/protocol/src/sync.ts`, and add the matching cases to `tests/client-contract.integration.test.ts`.

Add typed fixtures for:

- owned and shared vault lists;
- accepted share items;
- owner removal and collaborator self-leave;
- distinct user IDs and username maps;
- collaborator-authored revisions.

Keep pending invitations as a contract fixture, but do not implement an undeliverable pending-invite workflow in the first Blackglass collaboration release.

### Task 0.3 — Qualify the baseline again

Before changing server behavior:

1. Re-run Blackglass client analysis against the official 1.12.7 artifact and the reviewed 1.13.4 candidate artifact.
2. Verify each published compressed-artifact digest and record each decompressed ASAR digest.
3. Re-run current single-owner server and client tests.
4. Run the existing two-client single-owner macOS E2E for both qualified renderer versions from copied profiles and temporary vaults.
5. Save a scrubbed validation manifest; retain no account secrets, local-vault content, or renderer source.

Gate: no Phase 3 coding while the known-good single-owner baseline is red.

## Phase 3 — User-bound tenancy without sharing

### Phase 3 data model

Add schema version 5.

#### `users`

Required fields:

- durable numeric `id` allocated monotonically, rejected before JavaScript's maximum safe integer, and never accepted from a client as authority;
- canonical unique email plus display email;
- bounded display name;
- Argon2 password hash;
- status (`active` or `disabled`);
- created and updated timestamps.

Email canonicalization is fixed for these phases: trim surrounding ASCII whitespace, require a bounded printable ASCII address with exactly one non-edge `@`, and store `to_ascii_lowercase()` as the unique canonical key while preserving a bounded display form. Sign-in, provisioning, invitation, and uniqueness checks must all call the same function. Internationalized email support requires a later explicit normalization design. Do not add public signup, email confirmation, MFA, or password-reset claims in Phase 3.

Cap durable users at 256 for these phases. User creation fails before mutation at that bound. The database verifier rejects out-of-range IDs, more than one `sqlite_sequence` row for each AUTOINCREMENT table, sequence values beyond JavaScript's safe integer, and any user count above the cap. `user list`, `usernames`, admin projections, limiter maps, and migration verification use this same bound.

#### Existing tables

- `sessions.user_id` becomes a required foreign key to `users.id`.
- `vaults.owner_user_id` becomes a required foreign key to `users.id`.
- `revisions.user_id` becomes the authenticated author's required foreign key; `user` remains only the client wire field.
- retired-vault/tombstone state gains `owner_user_id` plus an optional internal replacement-vault reference for bounded lifecycle accounting. WebSocket `init` authenticates an active session before consulting vault state: invalid tokens always receive the generic authentication failure, while a valid session receives the same `Vault not found` contract for unknown, unauthorized, or retired IDs. Token shape or tombstone presence alone never changes the response.
- transfer staging remains ephemeral, but each staged transfer is bound to the authenticated connection and authorized vault.

Keep server-wide revision UIDs and per-vault ordering. The client does not require per-user UID spaces, and changing UID semantics adds unnecessary migration and replay risk.

### Task 3.1 — Build an explicit v4-to-v5 migration

Update:

- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/main.rs`
- `apps/server-rust/src/config.rs`
- `tests/database-migration.integration.test.ts`
- `docs/production.md`
- `ops/blackglass-server.env.example`

Requirements:

1. Migration writes a new destination database and never mutates the source in place.
2. The current configured owner becomes durable user ID `1`.
3. Every existing vault becomes owned by user `1`.
4. Every existing revision is attributed to user `1`.
5. Existing sessions are deliberately invalidated once; this is documented as a required re-login.
6. Foreign keys, schema history, WAL/checkpoint state, row counts, retained bytes, and integrity checks are verified before cutover.
7. `blackglass-server migrate <source> <destination>` reads the legacy owner email, display name, and password hash from the existing protected `SELFHOST_*` environment, applies the same bounded email/name validation used at runtime, and fails closed when any value is missing or invalid. None of those values is placed in process arguments or output.
8. Re-running migration into an existing destination fails closed.
9. A round-trip test proves the old database remains usable by the previous exact binary.

After schema v5 cutover, the database is the sole runtime authority for users and password hashes. The legacy `SELFHOST_EMAIL`, `SELFHOST_NAME`, and `SELFHOST_PASSWORD_HASH` settings may be read by the explicit offline migration path, but Phase 3 serving must never silently fall back to them or auto-bootstrap a missing user. Runtime serving and migration must never accept a plaintext `SELFHOST_PASSWORD`; user creation reads the password from standard input while the service is offline. Keep the old production values only in protected rollback material until the Phase 3 rollback window closes, then retire them deliberately.

Update `restore_database` and `rotate_recovery_epoch` for schemas v5/v6 and add a separate tenant-safe stale-backup mode; a normal schema migration must not resurrect accounts or sharing authorization from an old restore point. While every listener and edge route is detached, the current binary writes a new recovered destination that:

- clears all sessions;
- marks every user disabled while preserving IDs, ownership, and historical attribution;
- clears every Phase 4 collaborator membership when schema v6 is present;
- rotates the recovery epoch and all remote vault identities using the existing fresh-client recovery contract;
- verifies the recovered database before replacement.

The restore must preserve durable user IDs, owner foreign keys, revision author IDs, retained ciphertext, and logical counts while deliberately clearing memberships and sessions and disabling users. It creates no token-shape or recovery-token exception: old clients follow the documented fresh-profile recovery path. The operator then reviews the bounded offline user list, sets a new password, and explicitly re-enables each intended account before reconnecting the edge. Owners re-invite intended collaborators after recovery. No old membership, account-active flag, session, or client cursor is trusted merely because it existed in the restored backup. Add a stale-backup test that disables a user and removes a collaborator after the backup, restores the older copy, and proves neither access path returns before deliberate re-enrollment.

Gate: independently review migration code and test a byte-for-byte preserved source database plus verified logical counts in the destination.

### Task 3.2 — Add offline user lifecycle commands

Update:

- `apps/server-rust/src/main.rs`
- `apps/server-rust/src/auth.rs`
- `apps/server-rust/src/db.rs`
- CLI documentation

Add these bounded offline commands:

- `blackglass-server user list <database>`: list IDs, bounded names/emails, status, owned-vault count, and session count without hashes.
- `blackglass-server user create <database> <email> <name>`: read the new password from standard input and create an active user.
- `blackglass-server user set-password <database> <user-id>`: read the replacement password from standard input and revoke that user's sessions transactionally.
- `blackglass-server user set-email <database> <user-id> <email>`: canonicalize and uniqueness-check the new email, then update it and revoke that user's sessions transactionally.
- `blackglass-server user set-status <database> <user-id> <active|disabled>`: change status and revoke sessions when disabling.
- `blackglass-server user set-name <database> <user-id> <name>`: update the current bounded attribution name.
- `blackglass-server user revoke-sessions <database> <user-id>`: revoke all sessions for that user.

Do not implement destructive user deletion in Phase 3 or Phase 4. A user who owns vaults remains a durable identity even while disabled.

Every `user` command, including `list`, must acquire the same OS path ownership lock that the serving process holds for its entire lifetime (the existing `acquire_database_lock` mechanism), then open the database. If the service is running, the CLI fails without reading or mutating account state; the operator must stop the service first, which also closes every socket and discards staging. A SQLite transaction or busy lock alone is not sufficient. Do not pass passwords or password hashes in arguments. Do not add write actions to the Phase 1 browser console as part of this work.

Because these lifecycle commands are deliberately offline, they do not publish in-process invalidation events. Service shutdown is their immediate connection-revocation boundary. The online `/user/signout` path revokes exactly its authenticated session and directly cancels every live connection using that session. Any future online account-disable or password-change surface requires a separate design and must reuse the same cancellation path; no such write surface is added in Phase 3.

Add a process-level `P3-CLI-LOCK` test that starts the server, proves every `user` command refuses while the ownership lock is held, stops the server, performs `user set-password`, restarts, and proves the old session token fails on both control and data paths before the client can re-login with the replacement password.

### Task 3.3 — Make authentication return an `AuthContext`

Update:

- `apps/server-rust/src/auth.rs`
- `apps/server-rust/src/config.rs`
- `apps/server-rust/src/server.rs`
- `apps/server-rust/src/model.rs`

Replace boolean/global-owner authentication with a single context containing at least:

- user ID;
- canonical/display identity fields needed by control responses;
- session identifier or digest reference;
- session expiry;
- active/disabled state.

Every authenticated handler receives this context. Sign-in verifies a database-backed user; info and signout operate only on that session. Password changes and disablement revoke all sessions for the affected user. Session expiry and periodic WebSocket revalidation remain enforced.

Sign-in must preserve the existing bounded per-source attempt budget, trusted-proxy boundary, global Argon2 concurrency, waiter, memory, and request limits. It must not add a globally exhaustible canonical-account lockout: distributed invalid attempts against a known email cannot prevent a valid login from another admitted source. Any account-aware fairness key is a bounded, process-local `(source, keyed-canonical-account-digest)` bucket, never a global email bucket, and raw emails or stable unsalted email hashes never enter limiter state, logs, metrics, or artifacts. Run Argon2 verification off the async worker threads, use one valid dummy Argon2 hash for unknown/disabled accounts, return the same stable authentication error, and test timing only as a coarse regression guard rather than claiming perfect constant-time database behavior. Successful authentication checks user status again in the same transaction that issues the session.

Disabling an owner disables only that user's account and sessions; it does not silently revoke collaborators or delete/freeze the owned vault. The durable disabled owner and ownership rows remain so an operator can re-enable the account. Vault-wide suspension or ownership transfer is a separate future policy.

### Task 3.4 — Scope every control-plane operation

Update:

- `apps/server-rust/src/server.rs`
- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/model.rs`
- `packages/protocol/src/control.ts`
- `tests/tenant-isolation.integration.test.ts`

Required behavior:

- `/vault/list` returns only the authenticated user's owned vaults, `shared: []`, and a per-user owned-vault limit.
- create assigns `owner_user_id` from the session.
- access, rename, migrate, and delete require ownership.
- count/limit checks are per owner; the current hard cap of 100 total vaults remains the independent global deployment ceiling. An owner may consume at most the configured owned-vault limit but never bypass the global cap.
- `/subscription/list` and `/user/info` are user-scoped; every authenticated active local account receives the existing self-hosted `sync: true` entitlement and the account's own email/name fields, while disabled users cannot obtain or use a session;
- account size is user-scoped;
- Phase 4 sharing routes continue to return explicit unsupported errors.
- direct requests using another user's vault ID return the same non-enumerating contract as an unknown ID.

Centralize ownership checks in database authorization helpers. Do not duplicate ad hoc `WHERE owner_user_id = ?` logic across handlers without a single tested policy boundary.

### Task 3.5 — Scope every data-plane operation

Update:

- `apps/server-rust/src/server.rs`
- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/model.rs`
- `packages/protocol/src/sync.ts`
- `tests/tenant-isolation.integration.test.ts`

At WebSocket initialization:

1. authenticate the session;
2. resolve the vault;
3. authorize ownership;
4. bind connection, transfer staging, user ID, and vault ID into immutable connection state.

Then use the authenticated user ID for:

- `init.userId`;
- pushed revisions;
- restores;
- activity state and connection projections.

Audit all operations:

- init and replay;
- pull and binary response;
- push and binary staging/commit;
- server-pushed revisions;
- history and deleted listings;
- restore and purge;
- usernames;
- size;
- ping/session revalidation;
- disconnect and shutdown cleanup.

Every query must be scoped by the authorized vault. Except for the explicitly documented aggregate capacity of a shared resource below, a user must not learn another user's vault existence from an event, UID, path, total, error, timing branch, or transfer response.

Replace the current global retired-marker pruning with two uniform bounds: at most 512 markers per owner and 8,192 globally. Prune only the same owner's oldest markers when that owner reaches its bound. If an insertion would exceed the global bound because of other owners, fail the delete/migrate/recovery operation before changing the vault instead of evicting another owner's marker. Preflight bulk recovery rotation against both bounds. Test that one owner cannot evict or alter another owner's retained markers and that invalid token shape does not expose marker existence.

Online signout and every Phase 4 membership mutation publish a bounded internal invalidation event that immediately closes matching sockets and discards their staged transfers. Offline user lifecycle commands run only while the service lock is unowned and therefore rely on the required service shutdown to close sockets. Periodic session revalidation remains defense in depth, not the primary online revocation mechanism.

The close signal is not the authorization boundary. Every database mutation must re-check the session user and ownership predicate inside the same SQLite transaction that commits the mutation; serialized transaction order decides a revoke-versus-write race. Give each connection an out-of-band cancellation handle owned by the live-connection registry rather than relying on the outer socket event receiver. Revocation triggers that handle directly. Replay checks it before and after every bounded database wait and page send; pull checks before every binary frame; upload checks while reading each chunk and again in the final commit transaction; every socket write races cancellation. A handler must never remain authorized merely because the outer loop is awaiting it and cannot poll a broadcast receiver. A process crash drops all sockets, so no connection survives loss of the in-memory signal.

### Task 3.6 — Define quota and size ownership

Update:

- `apps/server-rust/src/config.rs`
- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/server.rs`
- `apps/server-rust/src/model.rs`
- `ops/blackglass-server.env.example`
- `docs/security.md`
- `tests/tenant-isolation.integration.test.ts`

Use uniform deployment configuration rather than per-user quota columns in these phases:

- the existing owned-vault constant remains the per-user owned-vault limit and shared vaults never consume it;
- `SELFHOST_STORAGE_QUOTA_BYTES` remains the global retained-storage ceiling;
- add `SELFHOST_STORAGE_QUOTA_BYTES_PER_OWNER`, defaulting to the global ceiling and never allowed above it;
- add a per-user active-session ceiling of 64 under the existing global session ceiling;
- add `SELFHOST_MAX_WS_CONNECTIONS_PER_USER`, defaulting to `min(4, SELFHOST_MAX_WS_CONNECTIONS)` and never allowed above the global limit;
- add `SELFHOST_MAX_CONCURRENT_UPLOADS_PER_USER`, defaulting to `min(2, SELFHOST_MAX_CONCURRENT_UPLOADS)` and never allowed above the global limit;
- keep the existing per-source connection/request limits as a separate abuse boundary;
- retain storage charging to the vault owner;
- for both owned and shared connections, `size.size` is the selected vault owner's total retained usage because that is the account whose quota governs writes;
- `size.limit` is that owner's uniform `SELFHOST_STORAGE_QUOTA_BYTES_PER_OWNER` value;
- `size.vault_size` is the selected owned or shared vault's current live logical size;
- the global storage/resource ceilings are never exposed as the user's quota.

The global ceilings for these phases are therefore 256 durable users, 100 total vaults, 1,024 retained session rows, 8,192 retired-vault markers, the existing configured WebSocket/upload ceilings, and the configured retained-storage ceiling. Reaching a per-user or global session ceiling rejects session issuance with one stable bounded retry error after expired/revoked-row pruning; it never silently revokes another live session. All in-memory per-user maps are bounded by the durable-user cap or the smaller live connection/session limit.

Do not count the same shared bytes against every collaborator in Phase 4. An authorized collaborator therefore sees only the owning account's aggregate used/quota numbers needed to explain shared-vault admission; no other vault count, name, identity, or per-vault breakdown is exposed. Record this bounded shared-resource capacity disclosure explicitly in the security documentation and exact-client fixture. Keep size fields numeric and compatible with 1.12.7.

When a collaborator writes in Phase 4, quota admission is charged atomically to the vault owner and the global deployment ceiling, never to the acting collaborator. Concurrent writers must not oversubscribe either bound.

### Task 3.7 — Extend read-only administration and observability

Update:

- `apps/server-rust/src/admin.rs`
- the dedicated admin snapshot in `apps/server-rust/src/db.rs`
- `docs/architecture.md`
- `docs/security.md`
- `docs/production.md`
- `ops/blackglass-server.env.example`
- `ops/release/INSTALL.md`
- metrics and alert documentation

Add bounded, redacted projections for:

- active/disabled user counts;
- owned vault counts per user using bounded operator-readable identity;
- session and connection user attribution;
- authorization-denial, SQLite-busy/deadline, and invitation-budget counters with bounded reason/operation labels only;
- per-owner usage summaries with visible/total/truncated counts.

Never expose password/session/admin hashes, tokens, key material, encrypted paths, or client payloads. Keep snapshot queries on the dedicated read-only connection and within existing busy/deadline/single-flight bounds.

### Task 3.8 — Phase 3 adversarial test matrix

Add Rust unit/integration tests and process-level tests covering at least three users: owner A, owner B, and outsider C.

For every control and data operation, test:

- A can access A's vault;
- B can access B's vault;
- A cannot access B's vault;
- C cannot access either vault;
- invalid and unauthorized identifiers are externally indistinguishable;
- cross-user session substitution fails;
- cross-user vault, revision, and retired-vault IDs fail;
- concurrent pushes do not deliver cross-vault events;
- disablement/session revocation closes active sockets;
- a revoked or expired connection cannot finish a staged upload;
- account sizes, limits, diagnostics, and admin projections do not include hidden tenants except for the explicit aggregate owner capacity returned inside an authorized shared-vault `size` response;
- restart and migration preserve ownership and boundaries.

Include identifier fuzzing, malformed JSON, duplicate email canonicalization, transaction rollback, busy SQLite, replay gaps, interrupted transfer, and resource-bound cases. `P3-AUTH` must assert that every observed client-facing signup/password-reset route remains explicitly unsupported. `P3-ENUMERATION` must cover active, retired, unauthorized, and random vault IDs with valid, invalid, expired, and merely token-shaped credentials.

### Task 3.9 — Phase 3 exact-client E2E

Using two copied Obsidian profiles and two temporary vaults:

1. provision two local Blackglass accounts;
2. sign each profile into a distinct account;
3. create/connect one remote vault per account;
4. synchronize text, binary, rename, delete, history, restore, and reconnect independently;
5. prove neither profile lists or connects to the other's vault;
6. sign out and expire normally, then stop the test server, run offline operator `user set-password`/`user set-status`, restart, prove old tokens fail, and re-login through the client;
7. verify browser console/client logs contain no protocol errors or secrets;
8. save only scrubbed manifests and synthetic checksums.

Gate: Phase 3 is releasable only after static analysis, Rust tests, Bun/integration tests, exact-client E2E, independent security review, release resource gates, and migration rehearsal all pass.

## Release and schema boundaries

Phase 3 is released as `v0.3.0` with schema v5. Phase 4 is released as `v0.4.0` with schema v6. Each release manifest records the exact supported source schema, destination schema, previous rollback binary/tag, client tooling revision, and qualified renderer matrix. Release automation must reject a tag/version/schema disagreement.

## Phase 3 production rollout

1. Produce checksum-verified exact-source AMD64/ARM64 artifacts through CI/release workflows.
2. Confirm a successful whole-LXC/PBS backup no older than 24 hours and a restore drill with a target post-activation RPO of at most 24 hours and RTO of at most four hours. Do not create an application backup timer.
3. Stop the service and copy-migrate schema v4 to a new schema-v5 database; preserve the untouched v4 file and old exact binary as rollback material.
4. Verify integrity, counts, size, schema history, owner mapping, and file permissions. Clone the migrated candidate, add synthetic accounts only to that disposable clone, and exercise Phase 3 isolation with the candidate binary on isolated loopback test ports. Discard the clone; do not add qualification-only users to the production candidate and do not let a real client write to it yet.
5. **Pre-activation rollback boundary:** before reconnecting the production edge or allowing any client request, rollback may restore the untouched v4 database plus old exact binary. This has RPO 0 and a target RTO of 15 minutes. Never run the old binary against schema v5.
6. Activate Phase 3, verify listeners, readiness, admin isolation, monitoring, and alerts, then allow the legacy owner to re-login. The first accepted client write permanently closes the old-database rollback path.
7. Verify the legacy owner path and complete a 24-hour Phase 3 soak before Phase 4 starts. New real users are provisioned only during a later explicit maintenance window with the offline user CLI.
8. **Post-activation recovery is roll-forward only:** preserve the current v5 database, deploy a fixed v5-compatible binary, or use the tenant-safe stale-backup recovery mode above with a current binary and new recovery epoch. Do not restore v4 beneath client profiles whose revision cursors may be ahead. If database loss requires PBS recovery, the accepted bound is the verified 24-hour RPO/four-hour RTO above; all restored accounts remain disabled until offline password replacement and re-enrollment, and every client follows the documented fresh-client recovery procedure.

Record the exact Prometheus job selector and both monitoring backends in the release manifest. During the entire Phase 3 soak require `up == 1` on both backends, zero firing Blackglass alerts, zero unplanned service restarts, `increase(blackglass_errors_total[24h]) == 0`, and no unexpected increase in upload-timeout, quota-rejection, or authorization-denial counters. Run the exact-client owner sync/history/restore probe at the start and end. Any cross-tenant success, client protocol error, integrity failure, persistent SQLite-busy symptom, critical alert, or unexplained restart aborts expansion: detach the edge, preserve the current database and logs, and repair forward on schema v5.

## Phase 4 — Shared-vault collaboration

### Phase 4 data model

Add schema version 6 with a membership table:

- `id INTEGER PRIMARY KEY AUTOINCREMENT` used as protocol `share_uid`; reject insertion before it exceeds JavaScript's maximum safe integer, never reset `sqlite_sequence`, and never reuse an ID within the active database/recovery epoch;
- `vault_id` foreign key;
- collaborator `user_id` foreign key;
- `invited_by_user_id` foreign key;
- accepted/created timestamps plus nullable `revoked_at`;
- a partial unique index on `(vault_id, user_id)` where `revoked_at IS NULL`.

Keep at most 64 revoked membership rows per vault and 8,192 membership rows globally. Before a re-invitation inserts a new row, prune only that vault's oldest revoked rows down to its bound without resetting `sqlite_sequence`. If the global bound is still exhausted by other vaults, fail before changing membership state rather than evicting another vault's history. Active rows are never pruned. The database verifier enforces the per-vault/global counts, sequence shape, safe-integer boundary, and active-row uniqueness. These bounds keep `usernames`, administration, migration, recovery, and invitation work finite even after repeated remove/re-invite cycles.

Use foreign-key actions deliberately: deleting a vault must remove its collaborator rows in the same transaction, while a user who owns vaults must not be destructively removed by user-lifecycle tooling. Index owner and membership lookup paths used on every request.

The owner remains `vaults.owner_user_id` and is not duplicated as a collaborator row. The first release supports existing active users and creates accepted memberships immediately. Keep the schema open to a future, separate email invitation table rather than creating unusable unknown-email memberships now.

There are exactly two authorization relationships:

- owner;
- collaborator.

Do not add dormant role columns without a client-visible product and policy design.

### Task 4.0 — Build an explicit v5-to-v6 migration

Update:

- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/main.rs`
- `tests/database-migration.integration.test.ts`
- `docs/production.md`

The offline migration writes a new destination and refuses an existing destination. Preserve the untouched v5 source and exact Phase 3 binary. The destination starts with zero memberships, deliberately invalidates v5 sessions for one documented re-login, and preserves user IDs/status, vault ownership, revision authors, retained bytes, and all Phase 3 limits. Verify schema history, foreign keys, partial uniqueness, `sqlite_sequence`, row counts, permissions, WAL/checkpoint state, and SQLite integrity. Prove the untouched source still opens with the exact Phase 3 binary. A failed rehearsal or pre-activation cutover returns to the untouched v5 source; after the first accepted v6 write, recovery is roll-forward only.

Gate: `P4-MIGRATE-V6` passes from a copied production-shaped v5 database before any Phase 4 authorization implementation merges.

### Task 4.1 — Centralize `VaultAccess`

Update:

- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/model.rs`
- `apps/server-rust/src/server.rs`
- `tests/collaboration.integration.test.ts`

Add one tested authorization result used by control, data, transfer, event, and admin code:

- `Owner { user_id, vault_id }`
- `Collaborator { user_id, vault_id, share_uid }`

Owner-only actions:

- rename;
- delete;
- encryption migration;
- list collaborators;
- invite collaborator;
- remove another collaborator.

Owner and collaborator actions:

- access/connect;
- pull/push;
- history/deleted;
- restore/purge;
- usernames;
- size;
- normal live events.

Collaborator-only self-service:

- leave by submitting their own `share_uid` to `/vault/share/remove`.

Reject cross-vault share IDs, owner self-removal, member removal of another member, duplicate active membership rows, self-invite, disabled users, and unknown users with the stable contracts below. Vault existence remains non-enumerating; immediate invitation of an existing account has a separately documented, bounded account-existence disclosure.

### Task 4.2 — Implement the observed sharing API

Update:

- `apps/server-rust/src/server.rs`
- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/config.rs`
- `apps/server-rust/src/model.rs`
- `ops/blackglass-server.env.example`
- `tests/collaboration.integration.test.ts`

Implement exactly:

- `/vault/share/list { token, vault_uid } -> { shares }`
- `/vault/share/invite { token, vault_uid, email }`
- `/vault/share/remove { token, vault_uid, share_uid }`

Rules:

- owner only for list and invite;
- canonical email lookup finds an existing active local account;
- first release creates `accepted: true` membership;
- response items contain bounded `uid`, `email`, optional `name`, and `accepted`;
- enforce a maximum of 20 active collaborators per vault;
- re-inviting the same accepted collaborator is an idempotent success and never creates a second row or share UID;
- after removal, a later re-invitation creates a new `share_uid` not previously used in the current recovery epoch; the stale removed ID cannot leave or remove the new membership;
- self-invite, unknown email, and disabled account all return the same stable `User unavailable for sharing` error.

Canonicalization and structural validation happen first. Before any account lookup, enforce uniform rolling-hour budgets of 60 invite attempts per source, 30 per authenticated user, 20 distinct canonical target digests per authenticated user, and 300 deployment-wide. Target digests are process-local keyed digests using an ephemeral secret; limiter state contains no raw address or stable unsalted address hash, is capped at 300 attempt records and 256 user entries, and resets on process restart. Successful, failed, duplicate, and rotating-address attempts all consume the applicable attempt budgets; metrics use only bounded outcome labels and never email or user labels. Return one stable bounded rate-limit error when any budget is exhausted. These defaults may be lowered by deployment configuration but not disabled.

Within one `BEGIN IMMEDIATE` transaction, re-check the active session, active owner, vault ownership, target active status, self-invite rule, existing active membership, active `COUNT(*) < 20`, and the final membership insert. Check an existing active membership before the count so an idempotent re-invite still succeeds at the limit. A removal sets `revoked_at`; re-invitation inserts a fresh AUTOINCREMENT row. This serialized transaction is the only collaborator-count authority.

Immediate success for an existing active account versus failure for an unknown account inherently reveals bounded account existence to an already-authenticated vault owner. Phase 4.1 accepts that narrow disclosure because the stock client has no pending invitation/acceptance route; the attempt, source, distinct-target, and global budgets are mandatory abuse controls. Do not describe stable errors alone as preventing the oracle.

Every share lookup and mutation binds the full `(vault_uid, share_uid, authenticated user_id)` tuple; `share_uid` is never a global bearer capability. Tenant-safe stale-backup recovery may rewind the restored SQLite sequence, so its mandatory recovery-epoch rotation gives every vault a new `vault_uid` before access is re-enabled and old memberships remain cleared. Thus an old `(vault_uid, share_uid)` pair never becomes valid again even if a numeric share ID is later reissued in the new epoch. Add a recovery test that forces numeric reuse from an older backup and proves the old vault/share pair and old user token remain invalid.

Do not claim email delivery or pending acceptance in Phase 4.1.

### Task 4.3 — Return owned and shared vault inventories

Update:

- `apps/server-rust/src/server.rs`
- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/model.rs`
- `packages/protocol/src/control.ts`
- `tests/collaboration.integration.test.ts`

`/vault/list` must return:

- `vaults`: descriptors owned by the user;
- `shared`: descriptors for accepted memberships, each including its own `share_uid`;
- `limit`: owned-vault limit only.

Shared descriptors contain the same connection and encryption metadata required by an owner descriptor. They must not expose owner account secrets or unrelated membership data.

Test both custom E2EE and server-managed encryption. For custom E2EE, no password is returned; the collaborator enters the shared password locally. For managed encryption, return only the existing client-required managed key field to authorized members.

### Task 4.4 — Attribute revisions and usernames

Update:

- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/server.rs`
- `apps/server-rust/src/model.rs`
- `packages/protocol/src/sync.ts`
- `tests/collaboration.integration.test.ts`

Use the authenticated writer's numeric user ID on push and restore. Preserve it through replay, history, deleted entries, and server-pushed revisions.

`usernames` must return only the bounded mapping needed for revision attribution in the authorized vault. It may include a removed collaborator's current bounded display name when their historical revisions remain, but must not enumerate all server users or expose email addresses.

Attribution follows the current account display name: revisions retain the durable numeric author ID, and renaming a user changes the name returned for old and new revisions. Users are never destructively deleted in these phases, so historical author IDs remain resolvable. Obsidian 1.12.7 caches the username map for the connected changes view, so a rename is only required to appear after reconnect/reload; Blackglass does not invent an unsupported live username-invalidation message. Test rename and removed-collaborator history after reconnect explicitly.

### Task 4.5 — Make membership revocation immediate

Update:

- `apps/server-rust/src/db.rs`
- `apps/server-rust/src/server.rs`
- `tests/collaboration.integration.test.ts`

On owner removal, collaborator self-leave, user disablement, password/session revocation, vault deletion, or ownership-affecting migration:

1. commit the authorization change transactionally;
2. notify matching live connections with a bounded internal invalidation event;
3. close affected sockets;
4. discard staged uploads and pending binary transfers;
5. reject reconnect, pull, push, replay, history, restore, purge, usernames, and size immediately;
6. ensure queued vault events are not delivered after invalidation.

Periodic session validation remains defense in depth, not the primary revocation mechanism.

The invalidation notification is only the fast close path. All mutating SQL must re-check active session/user status and current owner/membership authorization in the same transaction that writes. If the mutation transaction wins first, it commits before revocation; if revocation wins first, the mutation affects zero rows and returns the generic authorization failure. Reuse the Phase 3 out-of-band per-connection cancellation handle for replay, pull, upload, database waits, and every socket write, and still re-check the authorization generation at final commit so a dropped or delayed notification cannot authorize work.

### Task 4.6 — Preserve event isolation

Update:

- `apps/server-rust/src/server.rs`
- `tests/collaboration.integration.test.ts`

Every outbound live event must carry enough internal scope to select only connections that are currently authorized for that vault. Membership-change events must be targetable to the affected user/connection without disconnecting unrelated collaborators.

Add race tests for:

- revoke concurrent with push metadata;
- revoke between push metadata and binary body;
- revoke concurrent with pull;
- revoke while replay is in progress;
- leave and re-invite, including delayed use of the removed `share_uid` after a new membership exists;
- concurrent duplicate invite and remove/re-invite ordering;
- start with 19 active members, concurrently invite two distinct active users, and assert exactly one succeeds and the final active count is 20;
- rotating unknown-email attempts exhaust the per-user distinct-target budget before lookup and never place addresses in metrics/logs;
- allocation at the JavaScript-safe `share_uid` boundary fails closed without reusing an ID;
- vault delete/migrate with multiple live collaborators;
- delayed event queued before revocation.

A request that loses authorization before commit must not mutate data.

### Task 4.7 — Qualify collaborator operations

With owner A, collaborator B, and outsider C, exercise:

- invitation by existing-account email;
- owner share-list rendering;
- recipient `shared` inventory and connect flow;
- wrong/right E2EE password behavior;
- A-to-B and B-to-A text/binary synchronization;
- concurrent edits and merge behavior;
- history and **hide my changes** attribution;
- delete, restore, purge, replay, reconnect, and cold-device bootstrap;
- interrupted upload/download and retry;
- owner rename/migrate/delete behavior with B connected;
- owner removal and B self-leave;
- re-invitation after removal;
- 20-member bound at API level using synthetic users;
- complete outsider and former-member isolation.

Explicitly verify that B's already-downloaded local vault remains after revocation and document that expected security limitation.

The current encryption migration replaces the remote vault with a new vault ID. Phase 4 migration must transfer ownership and accepted memberships transactionally, preserve each membership's `share_uid`, retire the old ID, and invalidate all old sockets. The stock collaborator client has no server-driven remote-ID replacement message, so the documented compatible recovery is to reconnect from the refreshed `shared` list and enter the new E2EE password when applicable. Do not redirect or alias the retired vault ID. Test this exact flow.

### Task 4.8 — Exact-client collaboration E2E

Use at least three copied profiles:

- owner profile A;
- collaborator profile B;
- unrelated profile C.

Drive the real 1.12.7 and 1.13.4 UIs for invitation, share-list display, connect, collaboration, history attribution, leave, and removal. Use synthetic temporary vaults and local Blackglass accounts only. Do not alter an installed application in place or a real user vault. Capture scrubbed request/response shape manifests and screenshots containing no secrets or user content.

Gate: Phase 4 is not releasable until every API, race, adversarial isolation, and exact-client scenario passes and two independent reviews approve authorization and migration behavior.

## Qualification traceability and commands

Every authorization slice is test-first. Before changing a schema, handler, query, replay path, transfer path, event audience, or revocation path, add the focused named test and record its expected RED result against the prior implementation; then implement only that slice, make the focused test pass, and run `bun run check` before moving to the next surface. Tasks 3.8 and 4.7 consolidate the already-green slices into the final adversarial matrix rather than postponing security coverage.

Create these named suites rather than extending one undifferentiated integration file:

- `tests/tenant-isolation.integration.test.ts`: `P3-AUTH`, `P3-CONTROL`, `P3-DATA`, `P3-REVOKE`, `P3-QUOTA`, and `P3-ENUMERATION`.
- `tests/user-lifecycle.process.test.ts`: `P3-CLI-LOCK`, including refusal while the serving process owns the database and old-token failure after offline mutation/restart.
- `tests/collaboration.integration.test.ts`: `P4-SHARE`, `P4-INVENTORY`, `P4-ATTRIBUTION`, `P4-DATA`, `P4-REVOKE`, `P4-RACES`, and `P4-MIGRATE`.
- `tests/database-migration.integration.test.ts`: `P3-MIGRATE-V5`, `P4-MIGRATE-V6`, source preservation, pre-activation rollback, and post-activation roll-forward fixtures.
- Rust unit tests beside `auth.rs`, `db.rs`, and `server.rs`: email canonicalization, password/session lifecycle, `VaultAccess`, SQL scoping, foreign-key invariants, quota transactions, event audiences, and invalidation races.
- Blackglass contract tests: the `CLIENT-1127-*` fixtures plus matching `CLIENT-1134-*` fixtures, including `CLIENT-1134-POW-UNSUPPORTED`.
- Exact-client macOS scenarios: `E2E-P3-TENANCY`, `E2E-P4-CUSTOM-E2EE`, and `E2E-P4-MANAGED-ENCRYPTION`. The two Phase 4 scenarios each use owner A, collaborator B, and outsider C; managed encryption is not allowed to pass solely through a protocol mock.

Each requirement has one release-blocking owner:

- sign-in/info/signout, user-bound sessions, offline operator password replacement, disablement, and continued rejection of every observed client-facing password-reset route → `P3-AUTH`, `P3-CLI-LOCK`, and `E2E-P3-TENANCY`;
- owned inventory, create/access/rename/migrate/delete isolation, vault limits, and retired IDs → `P3-CONTROL`, `P3-ENUMERATION`, and `P3-MIGRATE-V5`;
- init/replay/pull/push/history/deleted/restore/purge/size/usernames isolation → `P3-DATA` and `E2E-P3-TENANCY`;
- immediate user/session invalidation and staged-transfer cleanup → `P3-REVOKE`;
- owner share list/invite/remove, bounded existing-account disclosure, invite budgets, 20-member race, and member self-leave → `P4-SHARE`, `P4-RACES`, and both Phase 4 E2E scenarios;
- `vaults` versus `shared`, `share_uid`, owned limit, owner-governed shared `size` capacity, and connection metadata → `P4-INVENTORY` and both Phase 4 E2E scenarios;
- `init.userId`, revision `user`, usernames, rename, removed-author history, and **hide my changes** → `P4-ATTRIBUTION` and both Phase 4 E2E scenarios;
- collaborator content operations and server-pushed convergence → `P4-DATA` and both Phase 4 E2E scenarios;
- removal/leave/disable/delete/migrate races and delayed events → `P4-REVOKE` plus `P4-RACES`;
- custom-password and managed-encryption sharing → `E2E-P4-CUSTOM-E2EE` and `E2E-P4-MANAGED-ENCRYPTION` respectively;
- migration membership transfer, stable share UID, retired old ID, and manual collaborator reconnect → `P4-MIGRATE` plus both Phase 4 E2E scenarios.

Minimum automated commands from `blackglass-server`:

```sh
bun run check
bun test tests/database-migration.integration.test.ts
bun test tests/tenant-isolation.integration.test.ts
bun test tests/user-lifecycle.process.test.ts
bun test tests/collaboration.integration.test.ts
git diff --check
```

Minimum Blackglass client commands from `blackglass`:

```sh
bun run check
bun run analyze:release -- /path/to/verified/obsidian-1.12.7.asar
bun run analyze:release -- /path/to/verified/obsidian-1.13.4.asar
bun run e2e:prepare -- /path/to/run /path/to/verified/obsidian-1.12.7.asar --scenario <scenario>
bun run e2e:prepare -- /path/to/run-1.13.4 /path/to/verified/obsidian-1.13.4.asar --scenario <scenario>
bun run e2e:server -- /path/to/run
bun run e2e:verify -- /path/to/run
git diff --check
```

Extend `prepare-e2e.ts`, `run-e2e-server.ts`, and `verify-e2e.ts` to support the three named scenarios, distinct generated account credentials, three copied profiles, and expected owner/collaborator/outsider identities. Credentials remain in mode-`0600` run directories and are excluded from result manifests.

Each renderer/scenario pair writes one scrubbed result under `docs/validation/`:

- `phase-3-tenancy-obsidian-<renderer-version>-<server-revision>.json`;
- `phase-4-custom-e2ee-obsidian-<renderer-version>-<server-revision>.json`;
- `phase-4-managed-encryption-obsidian-<renderer-version>-<server-revision>.json`.

Every result records scenario ID, exact server revision/artifact digest, exact client asset digest, platform, commands, test counts, start/end timestamps, migration source/destination schema versions, and pass/fail checks. It must not contain credentials, email addresses, encryption values, raw paths, vault content, renderer source, or production identifiers. A release is blocked if any demand above lacks a named passing suite and a scrubbed result.

## Phase 4 production rollout

1. Ship Phase 4 as a separate exact-source release after the Phase 3 soak.
2. Confirm a successful whole-LXC/PBS backup no older than 24 hours and the same maximum 24-hour RPO/four-hour RTO, then copy-migrate schema v5 to v6 offline. Preserve the untouched v5 database and Phase 3 binary only as pre-activation rollback material.
3. Clone the migrated candidate and exercise owner/member/outsider sharing on that disposable clone using isolated loopback test ports. Discard the clone. Verify the real candidate still has no memberships or qualification-only users and no client writes. Before activation, restoring untouched v5 plus the Phase 3 binary is an RPO-0, 15-minute-target rollback.
4. Activate Phase 4 with no memberships and sharing disabled by default, prove single-owner behavior is unchanged, and hold an owner-only one-hour gate with both monitoring backends healthy and no Blackglass alert/error increase. The first accepted client write permanently closes the v5 rollback path.
5. Enable one real shared-vault canary only after that gate. `SELFHOST_SHARING_ENABLED=false` plus a bounded `SELFHOST_SHARING_CANARY_OWNER_IDS` allowlist permits share management and collaborator access only for vaults owned by the listed IDs; all other owners receive the stable sharing-unavailable contract. The list accepts at most eight safe integer IDs, is validated at startup, and is empty by default. Set `SELFHOST_SHARING_ENABLED=true` only after the canary gate, at which point the allowlist is rejected as ambiguous configuration. The canary owner/member accounts and stock-client flow must have already passed the disposable-clone and exact-client qualification gates. Hold the canary for 24 hours before adding another shared vault.
6. Verify primary and recovery Prometheus targets plus all related alerts after each step.
7. After activation, recover forward on schema v6 with a fixed v6-compatible binary or the tenant-safe stale-backup recovery mode. Any restored memberships are cleared and accounts remain disabled until deliberate offline password replacement and re-enrollment. Never restore v5 beneath advanced clients and never run a schema-incompatible binary.

During the canary require `up == 1` on both monitoring backends, zero firing Blackglass alerts, zero unplanned restarts, no unexplained `blackglass_errors_total`, upload-timeout, quota-rejection, invitation-rate-limit, authorization-denial, or SQLite-busy increase, and successful owner↔collaborator text/binary sync at the start and end. Re-run removal, old-token/share-UID denial, and reconnect checks before expansion. Any unauthorized operation, post-revocation delivery, protocol error, integrity failure, or critical alert stops expansion; detach the sharing path or edge as needed, preserve the v6 database/evidence, and repair forward.

## Required review gates

Before each phase merges:

- protocol compatibility review against the verified 1.12.7 floor and current 1.13.4 candidate artifacts;
- schema and rollback review;
- authorization/data-isolation review;
- transfer and WebSocket race review;
- bounded-resource and SQLite contention review;
- secret/log/admin-projection review;
- UI/client E2E review;
- documentation and operator-runbook review.

A reviewer should return only PASS or concrete file-and-line findings. No phase deploys with unresolved high- or medium-severity authorization, migration, protocol, or resource findings.

## Recommended implementation order

1. Merge Workstream 0 contract fixtures and baseline qualification.
2. Implement Phase 3 schema/migration and offline user lifecycle.
3. Implement Phase 3 authentication and control-plane scoping.
4. Implement Phase 3 data-plane scoping, attribution, and revocation.
5. Add Phase 3 admin/metrics projections and adversarial tests.
6. Run exact-client Phase 3 E2E, review, release, migrate, and soak.
7. Implement and qualify the Phase 4 v5-to-v6 migration.
8. Implement the Phase 4 membership schema and centralized access policy.
9. Implement sharing routes and owned/shared inventory.
10. Implement collaborator attribution, event filtering, and immediate revocation.
11. Run Phase 4 race, adversarial, and exact-client collaboration suites.
12. Review, release, migrate, canary one shared vault, verify monitoring, and expand deliberately.

## Definition of done

Phase 3 is done only when multiple accounts use the same server without any observable or actionable cross-tenant path and the legacy owner remains compatible after one documented re-login.

Phase 4 is done only when the stock 1.12.7 and 1.13.4 owner and collaborator flows work end to end, revocation closes all future server paths, revision attribution is correct, encryption limitations are explicit, and an unrelated user remains unable to discover or access collaboration state.
