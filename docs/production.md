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

The native default refuses non-loopback binding. The OCI image makes the
narrowly scoped `0.0.0.0` plus acknowledgement opt-in required for private
bridge/Pod networking; a TLS ingress remains the only client-facing boundary.
SQLite runs in WAL mode with
`synchronous=FULL`, so an acknowledged commit is durable across operating-system
crashes and power loss within SQLite's documented filesystem assumptions.
Connections enable SQLite defensive mode and disable trusted schemas. Encrypted
file bodies are staged in a mode-0600 file and committed with SQLite's
incremental BLOB API. Ciphertext is in `revision_content`, whose BLOB is the
last physical column; this preserves SQLite's zero-BLOB optimization and avoids
a file-sized memory spike. Legacy inline BLOB rows remain readable.

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
then enable it. The supplied unit uses a dynamic unprivileged user, a private
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

At most two Argon2 password checks run concurrently, capping their worst-case
working memory at 128 MiB under the supplied 256 MiB systemd limit. The process
does not apply a global hard login bucket, because one attacker could keep the
owner locked out. The TLS ingress or firewall must instead rate-limit sign-in
per real source address and cap connections; do not trust forwarded client-IP
headers unless the ingress overwrites them and untrusted peers cannot reach the
service. `SELFHOST_MAX_WS_CONNECTIONS` defaults to 16 and is constrained to
1..32 by the same memory envelope.

## Health, metrics, and logs

- `GET /health` is process liveness.
- `GET /ready` includes a SQLite query and is readiness.
- `GET /metrics` emits counters in Prometheus text format.
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

For a real restore, stop the service, preserve the failed database files for
forensics, use `restore <backup> <new-database>` to create a new verified file,
point `SELFHOST_DATABASE` at that new file, start the service, and require both
`/ready` and a fresh-client recovery test before discarding the old files.

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
input/output inside the transaction and rolls back on failure. Rollback means
restoring the pre-upgrade database together with the previous binary, not
running an older binary against a migrated database.

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
sudo systemctl start blackglass-server.service
curl --fail http://127.0.0.1:3000/ready
```

Systemd assigns the new state directory to the dynamic service identity on
start. Require a fresh-client recovery test before disabling the old unit or
removing its state. Roll back by stopping Blackglass Server and restarting the
old unit against the untouched legacy database.

Client releases remain independently versioned. Keep the old client build
disabled from automatic updates, qualify each new Obsidian renderer with the
semantic patch-anchor tests and official-client recovery E2E, then distribute
the newly generated local build. The server URL does not need to change.

## Resource envelope

Each active upload holds at most one WebSocket frame (2 MiB) plus small
metadata in memory and one ciphertext staging file on disk. Upload concurrency
defaults to four and is configurable. WebSocket admission defaults to 16 and
cannot exceed 32; two 64 MiB Argon2 checks, 32 worst-case 2 MiB frames, and 32
MiB of base headroom fit the supplied 256 MiB service cap. Pulls read SQLite in
2 MiB pieces. This keeps memory bounded by concurrency, not vault or attachment
size. SQLite is
the correct database while the deployment remains a single writer node; do
not place its files on a network filesystem.

The release resource gate uploads 64 MiB in 32 pieces and records process RSS
in `.data/validation/rust-resource-report.json`. Treat the report as valid only
for the exact `binarySha256` it records; rebuilds require a new gate.

Sanitized release summaries suitable for source control are retained under
[`docs/validation`](validation/README.md).
