# Production operations

## Supported production shape

The production target is deliberately narrow: one owner, end-to-end-encrypted
vaults, one Rust process, one SQLite database, and one static node. Publish,
public registration, sharing, high availability, and mobile clients are not
supported in this phase. Both custom-password and managed-encryption vaults are
compatible. Prefer a custom vault password when the server operator must not be
able to derive the vault key; managed mode stores its generated recovery
password in SQLite and backups.

Native installs have two loopback listeners. A TLS reverse proxy is the only
public listener:

```text
Obsidian -> HTTPS control hostname -> Caddy -> 127.0.0.1:3000
Obsidian -> WSS data hostname      -> Caddy -> 127.0.0.1:3003
```

The native binary and OCI image both default to loopback. The qualified Linux
Docker topology uses host networking so the same host Caddy process can reach
those loopback listeners without exposing plaintext ports. A TLS ingress
remains the only client-facing boundary.
SQLite runs in WAL mode with
`synchronous=FULL`, so an acknowledged commit is durable across operating-system
crashes and power loss within SQLite's documented filesystem assumptions.
Connections enable SQLite defensive mode and disable trusted schemas. Encrypted
file bodies are staged in a mode-0600 file and committed with SQLite's
incremental BLOB API. Ciphertext is in `revision_content`, whose BLOB is the
last physical column; this preserves SQLite's zero-BLOB optimization and avoids
a file-sized memory spike. Legacy inline BLOB rows remain readable. The
advertised per-file limit defaults to 200 MiB and is capped at 900 MiB so an
encrypted row remains safely below bundled SQLite's default maximum value
length; larger operator values fail during startup rather than after staging.

## Build and install

For normal Linux deployments, prefer the checksummed static binary matching
the host CPU from a tagged release. The `linux-amd64` archive covers Intel and
AMD hosts; `linux-arm64` covers AArch64 hosts such as Graviton and Ampere. See
[server builds and distribution](distribution.md) for verification and the
minimal multi-architecture container option.

Use the locked dependency graph and run the release gate:

```sh
./ops/build-release.sh
sudo install -d -m 0755 /opt/blackglass-server
sudo install -m 0755 \
  apps/server-rust/target/release/blackglass-server \
  /opt/blackglass-server/
```

Generate the password hash without putting the password in a process argument:

```sh
read -r -s account_password
printf '%s' "$account_password" | \
  /opt/blackglass-server/blackglass-server hash-password
unset account_password
```

Copy `ops/blackglass-server.env.example` to
`/etc/blackglass-server/server.env`, replace
the sample values, and set its owner to root and mode to 0600. The service will
not accept a plaintext production password. Sessions are random 256-bit bearer
tokens; only SHA-256 token digests, expiry, and revocation state are stored.
Imported password hashes must use Argon2id v=19 with bounded work parameters:
`m=19456..65536`, `t=2..5`, and `p=1..4`. Hashes outside those limits are
rejected before password verification to prevent an unsafe operator value from
causing unbounded CPU or memory use.

Install `ops/blackglass-server.service`, run `systemd-analyze security` against it,
then enable it. The supplied sysusers file and unit use a static unprivileged
`blackglass-server` user, a private
state directory, a read-only host filesystem, an empty capability set, and a
restricted syscall/address-family surface.

## TLS and client endpoints

Copy `ops/Caddyfile.example`, replace both names, and set
`SELFHOST_DATA_HOST` to a stable data hostname without a scheme. Generate the
client adapter with the matching HTTPS control origin and data host. Explicit
`:443`, deceptive `localhost*`/`127.0.0.1*` names, IPv6 loopback, and non-exact
127/8 addresses are rejected because Obsidian 1.12.7 would choose the wrong
WebSocket transport. Do not put the control and data services directly on a
public interface.

The control and data services accept only the configured exact renderer origins.
`SELFHOST_ALLOWED_ORIGINS` is a comma-separated list of at most eight origins;
the desktop default is `app://obsidian.md`. Mobile clients are not qualified.
The legacy singular
`SELFHOST_ALLOWED_ORIGIN` remains accepted for one origin, but must not be set at
the same time as the plural variable. Never use wildcard CORS.

One Argon2 password check runs at a time, with at most eight fair queued
waiters. The server also admits six sign-in attempts per real source in a
60-second window and at most four unauthenticated WebSockets per source;
successful owner sign-in refunds its attempt. `SELFHOST_TRUSTED_PROXY` accepts
one exact private or loopback IP, never a CIDR. Only set it when that peer is the
exclusive ingress and overwrites `X-Forwarded-For`; the supplied Caddy example
does both with `127.0.0.1`. Otherwise leave it unset and add equivalent
per-source limits at ingress. `SELFHOST_MAX_WS_CONNECTIONS` defaults to 16 and
is constrained to 1..16 by the qualified memory envelope.

## Read-only admin console

The optional Phase 1 admin console is observation-only: it has no mutation,
backup, configuration, revocation, deletion, purge, or restore controls. Enable
it only by setting `SELFHOST_ADMIN_BIND_HOST`, `SELFHOST_ADMIN_PORT`, and
`SELFHOST_ADMIN_TOKEN_HASH` together. The hash is exactly 64 lowercase SHA-256
hex characters; never put the plaintext admin token in the environment. Use a
random token independent from all Sync sessions.

The admin bind is strictly loopback-only; unspecified addresses are rejected even when external Sync binding is acknowledged. Keep the listener on `127.0.0.1` (for example port `3010`). TLS remains the
responsibility of a private reverse proxy. A safe remote shape is a tailnet-only
hostname whose proxy route forwards `/admin` to `127.0.0.1:3010` and is not
present in public DNS or the public Caddy site. Do not proxy the admin listener
from the public control/data virtual hosts. The shell assets contain no server
data; every `/admin/api/*` request requires `Authorization: Bearer <admin-token>`.
The browser stores it in `sessionStorage`, polls no faster than 30 seconds, and
can forget it with **Forget token**.

The console exposes bounded, explicit projections: readiness/version/schema,
configured limits, vault metadata and encryption mode, recent revision metadata
without encrypted paths, session timestamps without token hashes, storage
counts, staging diagnostics, and a bounded in-memory live-connection view.

## Health, metrics, and logs

- `GET /health` is process liveness.
- `GET /ready` includes a SQLite query and is readiness.
- `GET /metrics` emits counters and the configured storage-quota gauge in
  Prometheus text format.
- JSON logs contain operation/security events but never bearer tokens,
  ciphertext paths, hashes, file contents, passwords, or vault keys.

The example Caddy configuration deliberately does not publish these operations
endpoints. Scrape them over loopback or a private administration network. If you
publish them, add an explicit authentication and network policy first.

Metrics use the `blackglass_` prefix. The equivalent legacy
`obsidian_sync_` names are emitted during the 0.2 compatibility window so
existing dashboards keep working; migrate alerts before those aliases are
removed in a future major release.

Keep all three endpoints behind the control hostname's normal network policy.
Alert on readiness failures, restarts, sign-in failures/rate limits, WebSocket
errors, and backup failures. Disk-free-space monitoring is mandatory because
SQLite and in-progress staging files share the state volume by default.
Alert on `blackglass_upload_timeouts_total`; it indicates a client or network
that stopped making progress during an upload.
Alert on `blackglass_storage_quota_rejections_total` and record
`blackglass_storage_quota_bytes` alongside host disk capacity. A quota
rejection is an expected bounded client error, not a server fault.

## Backup and recovery

Never copy a live `.sqlite`, `-wal`, and `-shm` set independently. The server's
`backup` command uses SQLite's online backup API and verifies the exact
Blackglass tables, columns, indexes, foreign keys, and migration history plus
SQLite integrity and logical row invariants on both its source and result:

```sh
SELFHOST_BACKUP_DIRECTORY=/var/backups/blackglass-server ./ops/backup.sh
```

Copy verified backups to a different failure domain. Encrypt that destination:
the database holds ciphertext and metadata, and managed-encryption deployments
also store their vault recovery passwords.

Run a scheduled restore drill against a disposable path:

```sh
SELFHOST_SERVER_BINARY=/opt/blackglass-server/blackglass-server \
  ./ops/restore-drill.sh /var/backups/blackglass-server/server-TIMESTAMP.sqlite
```

For a real restore, stop the service and preserve the failed database files for
forensics. `restore` accepts only the current schema. First run `migrate` into a
new file when the backup came from an older recognized schema, then restore that
current-schema file into another new path:

```sh
blackglass-server migrate old-backup.sqlite migrated-backup.sqlite
blackglass-server restore migrated-backup.sqlite recovered.sqlite
```

Restore always establishes a new recovery epoch: every remote vault ID rotates
and every session is cleared. Point `SELFHOST_DATABASE` at the recovered file,
start the service, and require `/ready`. Every desktop must then sign in again,
reselect the replacement remote vault, and recover into a fresh empty local
vault. Do not let a pre-restore local profile resume against its retired remote
identity. Complete a fresh-client recovery test before discarding old files.
The recovery response is deliberately narrow: a recorded retired vault ID plus
any 64-character lowercase-hex token receives `Vault not found`, even when a
post-backup token is absent from the restored session table. Other token shapes
and arbitrary missing vault IDs retain the generic authentication error.

If a signed-in device or bearer token may be compromised, stop the service and
revoke every session before restarting it:

```sh
/opt/blackglass-server/blackglass-server \
  revoke-all-sessions /var/lib/blackglass-server/server.sqlite
```

All clients must sign in again. Changing the account password hash should be
paired with this command.

## Upgrade and rollback

Back up and verify before every server upgrade. Install a versioned binary,
stop the service, change the `/opt/blackglass-server/blackglass-server`
symlink, and start it. Startup never mutates an older recognized schema. When a
release requires a schema change, keep the service stopped and create a new,
fully validated copy first:

```sh
blackglass-server migrate server-vOLD.sqlite server-vNEW.sqlite
```

Only after `verify server-vNEW.sqlite` succeeds should configuration point at
the new file. The source stays unchanged. Each migration step validates its
input/output inside the transaction and rolls back on failure. Migration from
the shipped schema v3 to v4 preserves vault IDs and sessions; migrations from
schemas older than v3 establish a new recovery epoch and require the same
fresh-client procedure as restore.

A pre-v4/pre-0.2.2 rollback is safe only before activation, while the untouched
old database has received no client writes. After the new database has served
clients, do not start an older binary or restore the old database under existing
client profiles: revision cursors can be ahead of that history. Roll forward to
a fixed build on the same or newer schema. If data recovery is necessary, use a
current binary to migrate and restore into a new file; vault IDs rotate,
sessions clear, and every client must sign in, reselect, and start from an empty
local vault.

### Changing the public data host

Vault records and existing client profiles persist the returned data host.
Prefer stable DNS so routine server moves need no change. If the domain or port
must change, stop the service and create a verified backup before the
transactional rebind:

```sh
blackglass-server rebind-data-host \
  /var/lib/blackglass-server/server.sqlite \
  new-sync-data.example.com \
  /var/backups/blackglass-server/pre-rebind.sqlite
```

Set `SELFHOST_DATA_HOST` to exactly the same canonical value and restart. The
server refuses mixed or mismatched persisted hosts with an actionable error.
Existing clients still know the old endpoint and must reconnect/reselect the
remote vault through a newly adapted client endpoint. Keep the old DNS route
available during that controlled transition when possible.

### One-time migration from the pre-Blackglass service name

The branding change moved the default database from
`/var/lib/obsidian-sync/server.sqlite` to
`/var/lib/blackglass-server/server.sqlite`. Do not start the new unit against an
empty database and assume that the old vaults were deleted.

Stop both units, retain an off-host backup, and use the offline copy-first SQLite
legacy migration path to create a verified, migrated copy without changing or
deleting the legacy database. Normal `verify`, `backup`, and `restore` commands
require current Blackglass migration metadata; `migrate-legacy` is the only
command that accepts the exact known pre-Rust schema:

```sh
sudo systemctl stop obsidian-sync.service blackglass-server.service
sudo install -d -m 0700 /var/lib/blackglass-server
sudo env SELFHOST_SERVER_BINARY=/opt/blackglass-server/blackglass-server \
  ./ops/migrate-legacy-state.sh \
  /var/lib/obsidian-sync/server.sqlite \
  /var/lib/blackglass-server/server.sqlite
sudo chown blackglass-server:blackglass-server \
  /var/lib/blackglass-server/server.sqlite
sudo systemctl start blackglass-server.service
curl --fail http://127.0.0.1:3000/ready
```

The explicit ownership step is mandatory because copy-first migration creates a
mode-0600 file. Require a fresh-client recovery test before disabling the old
unit or removing its state. Roll back only before the migrated database accepts
client writes; afterward use the roll-forward recovery rule above.

Client releases remain independently versioned. Keep the old client build
disabled from automatic updates, qualify each new Obsidian renderer with the
semantic patch-anchor tests and official-client recovery E2E, then distribute
the newly generated local build. The server URL does not need to change.

## Resource envelope

Each active upload holds at most one WebSocket frame (2 MiB) plus small
metadata in memory and one ciphertext staging file on disk. Upload concurrency
defaults to four and can be reduced, but cannot exceed the qualified limit of
four. A pending upload must finish staging a complete piece within 300 seconds
by default. `SELFHOST_UPLOAD_IDLE_TIMEOUT_SECONDS` can be set from 5 through
3600 seconds; every complete staged piece refreshes that deadline, while expiry
releases the upload slot, removes the partial file, and closes the connection.
WebSocket admission defaults to 16 and cannot exceed 16. One bounded
Argon2 check, an eight-request wait queue, 2 MiB frames, bounded reconnect
pages, a single large JSON response, and bounded database workers stay inside
the supplied 256 MiB service cap under the release workload.
A fair memory-admission pool leaves one authenticated Sync lane available
during password verification. Pulls read SQLite in 2 MiB pieces, with a fixed
limit of two concurrent frames and admission released between pieces. This
keeps memory bounded by concurrency, not vault or attachment size. SQLite is
the correct database while the deployment remains a single writer node; do
not place its files on a network filesystem.

`SELFHOST_STORAGE_QUOTA_BYTES` is a hard, account-wide limit on retained
ciphertext bodies across every vault and historical revision, including copies
created by `restore`. The commit-time check and revision insertion share one
SQLite transaction, so concurrent uploads cannot oversubscribe it. Zero-byte
tombstones remain writable while full; `purge` and vault deletion release
logical quota. If an existing database is already over a newly lowered limit,
the server remains available for reads and cleanup but rejects new non-empty
revisions.

The compatibility default is the previously advertised 1 TiB
(`1099511627776`). Production operators should set it deliberately below the
state volume's usable capacity. Reserve additional space for up to
`SELFHOST_MAX_CONCURRENT_UPLOADS` staging files, SQLite pages/WAL and filesystem
overhead, logs, and any local backups. Purging makes database pages reusable but
does not necessarily shrink the SQLite file; the quota is a stored-ciphertext
guard, not a replacement for disk-free-space monitoring.

Each Linux package job runs its exact exported native binary as UID 65532 in a
server-only cgroup with a 256 MiB memory maximum and swap disabled. The host
workload first drives 11 concurrent large-metadata reconnects. It then holds 16
authenticated WebSockets while overlapping four 64 MiB uploads, eight pulls, a
large history response, and ten sign-in attempts at the maximum accepted
Argon2id work parameters (`m=65536,t=5,p=4`). A separate phase requires that
maximum-cost password work and the reserved Sync lane both complete.

Qualification requires the configured cgroup `memory.max` to remain exactly
256 MiB with swap disabled; startup and final OOM counters to remain zero;
exact artifact, staged, and in-image hashes to match; and a graceful non-OOM
exit. The report records `memory.peak` and `memory.events.max`, but does not
treat successful direct reclaim as an OOM: Linux permits temporary usage above
`memory.max` while reclaim brings it back down. Kernel `VmHWM` remains an
independent gate: peak process RSS must stay below 224 MiB and the measured
idle-to-peak increase below 128 MiB. The 192 MiB `MemoryHigh` threshold remains
an intentional pressure signal rather than a kill boundary. The per-target
report binds all measurements to the binary SHA-256, native target, and source
revision; any rebuild requires a new report.

## Deletion and retention

Sync deletion is logical: the current head becomes a tombstone and historical
encrypted revisions remain available until purged. This is required for the
built-in Deleted and version-history experiences, so it is not secure erasure.
If the Deleted response reaches its bounded wire limit, stop the service and
run the backup-first targeted command shown in the client error:

```sh
blackglass-server purge-deleted \
  /var/lib/blackglass-server/server.sqlite \
  VAULT-ID \
  /var/backups/blackglass-server/pre-purge.sqlite
```

That command removes history only for paths whose current head is a tombstone;
it preserves live-file version history and the tombstone heads. For privacy
retention, separately expire old backups. Use encrypted storage and destroy its
keys when cryptographic erasure is required; SQLite row deletion alone cannot
promise physical erasure from filesystem snapshots or discarded blocks.

Sanitized release summaries suitable for source control are retained under
[`docs/validation`](validation/README.md).
