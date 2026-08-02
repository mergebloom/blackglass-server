# Obsidian 1.12.7 Sync protocol notes

## Control plane

The renderer constructs the production base as `https://api.obsidian.md`.
Internal development mode changes it to `http://127.0.0.1:3000`.

Observed account routes:

- `/user/signin`
- `/user/signout`
- `/user/info`
- `/user/authtoken`
- `/user/signup`
- `/user/forgetpass`
- `/user/resendconfirmation`
- `/subscription/list`
- `/subscription/business`

Observed Sync vault routes:

- `/vault/regions`
- `/vault/list`
- `/vault/create`
- `/vault/access`
- `/vault/migrate`
- `/vault/rename`
- `/vault/delete`
- `/vault/share/list`
- `/vault/share/invite`
- `/vault/share/remove`

The server implements sign-in, sign-out, user information, Sync subscription
information, region listing, vault list/create/access/migrate/rename/delete,
and owner/collaborator sharing. Registration, password recovery, and business
subscriptions return explicit JSON errors. Account responses use `license:null`; Sync entitlement
comes only from `/subscription/list.sync`, avoiding unrelated Catalyst/Insider
UI.

The renderer's seven `/publish/*` calls, `/subscription/sync/signup-mobile`,
and `/user/authtoken` are also recognized POST routes. They return explicit
JSON unavailable or administrator-managed errors with the same exact-origin
CORS behavior; no Publish, mobile-signup, or token-exchange functionality is
implemented. Unrecognized paths remain HTTP 404.

## Data plane

The Sync client persists a control-plane-provided `host`. It derives:

- `ws://host` for `localhost` or `127.0.0.1`;
- `wss://host` otherwise.

The unadapted reference client currently accepts `127.0.0.1` or a hostname
ending in `.obsidian.md`. The compatibility adapter replaces this with an exact
configured-host check. Server and Bridge validation share the transport-safe
endpoint rules: exact `127.0.0.1`/`localhost` for plaintext development or a
canonical production host for WSS; explicit `:443`, deceptive loopback
prefixes, IPv6 loopback, and other 127/8 addresses are rejected.

Initial connection message:

```json
{
  "op": "init",
  "token": "account-token",
  "id": "vault-id",
  "keyhash": "client-derived-key-hash",
  "version": 0,
  "initial": true,
  "device": "device-name",
  "encryption_version": 3
}
```

The 1.12.7 client accepts this response:

```json
{
  "res": "ok",
  "userId": 1,
  "perFileMax": 209715200
}
```

For `initial:true`, the server sends only the latest live head for each path;
this avoids resurrecting deleted or renamed files. For `initial:false`, it
replays every revision newer than the requested version. Both terminate with:

```json
{ "op": "ready", "version": 42 }
```

Observed operations:

- `init`
- `ping`
- `push`
- `pull`
- `history`
- `restore`
- `deleted`
- `purge`
- `size`
- `usernames`

`size` returns retained account ciphertext, the current live selected-vault
size, and the exact configured retained-ciphertext limit:

```json
{ "res": "ok", "size": 1024, "limit": 1099511627776, "vault_size": 1024 }
```

The quota counts every retained non-empty revision, not only live heads. A file
upload reserves capacity while its metadata request is still using the client's
checked JSON-response path, before the server returns `next` and accepts binary
pieces. Concurrent uploads and restores share that accounting. Requests that
would exceed the limit receive the bounded `{"err":"Storage limit reached"}`
response; metadata-only deletions remain available so the owner can purge
history and recover capacity.

Obsidian 1.12.7 checks that JSON error only for the initial metadata request.
After sending a binary piece it waits for a response but does not inspect a JSON
body. The reservation makes a final transactional quota conflict unreachable
in ordinary operation; if that invariant is ever violated, the server closes
the WebSocket with code `1008` instead of sending JSON so the client must reject
and retry rather than recording a false upload success.

### Push and pull

A file push begins with encrypted metadata:

```json
{
  "op": "push",
  "path": "encrypted-path",
  "relatedpath": null,
  "extension": "md",
  "hash": "encrypted-hash",
  "ctime": 1700000000000,
  "mtime": 1700000000100,
  "folder": false,
  "deleted": false,
  "size": 1024,
  "pieces": 1
}
```

The server returns `{"res":"next"}` when it needs the body. The client sends
binary frames of at most 2 MiB and expects `next` between pieces and `ok` after
the final piece. Every accepted push becomes a revision; the originating
client receives its `push` notification before the final `ok`.

Every committed change receives a monotonically increasing `uid` and is
announced as an unsolicited `{"op":"push", ...}` notification. Pull uses
`{"op":"pull","uid":42}`; the response declares `size`, `pieces`, `deleted`,
and `hash`, followed by the encrypted binary frames.

The server stores and returns these bytes without decrypting them. It still
observes metadata such as ciphertext size, timestamps, file extension,
device name, and account identity.

### Conformance status

| Area | Status |
| --- | --- |
| `init`, snapshot/resume replay, `ready`, `ping` | Implemented and tested |
| file/folder/deletion `push` | Implemented; file path tested with official clients |
| `pull` | Implemented and opaque-byte round-trip/E2E tested |
| `size`, `usernames` | Implemented and official-client tested |
| `deleted`, `history`, `restore`, `purge` | Implemented and protocol-tested; deleted view live-tested |
| custom-password and managed-encryption vault lifecycle | Implemented and protocol-tested across restart and second-device access |
| destructive encryption upgrade (`/vault/migrate`) | Atomic empty-v3 replacement, old-history removal, old-socket invalidation, and managed/custom recovery tested |
| registration/recovery/business account UI | Explicit administrator-managed JSON errors; no public account lifecycle |
| two-device convergence | Bidirectional byte-identical E2E pass |
| multi-user sharing | Owner invite/list/remove, collaborator inventory/access/leave, attribution, revocation, migration, and resource bounds are implemented and protocol-tested; exact-client qualification is release-specific |

### History response contracts

- `deleted` returns `{items}` oldest-first. Rename-source tombstones are omitted
  when `suppressrenames` is true.
- `history` returns `{items, more}` newest-first and paginates with UID `< last`.
- Every item includes `uid`, server `ts`, encrypted `path`, `relatedpath`, file
  flags/size, and device/user identifiers.
- `restore` creates and broadcasts a new live revision; restoring a tombstone
  uses its most recent prior live content.
- `purge` retains one current head per path, including tombstones, removes
  earlier history, and preserves the monotonic vault version. Retained
  tombstones keep offline clients convergent but no longer appear in Deleted
  because their prior live revision has been purged.

### Encryption upgrade contract

Obsidian 1.12.7 posts `token`, `vault_uid`, new `keyhash`/`salt` (or null managed
credentials), `region`, and `encryption_version:3` to `/vault/migrate`. Success
returns a full replacement vault object. The server serializes this with Sync
commits and atomically creates an empty replacement while deleting the old
remote data and all history. Old idle and mid-upload sockets are invalidated;
the client then reconnects and reuploads its local vault. A failed transaction
leaves the old vault intact. Requests against an already-v3 source are rejected
to prevent replay or manual calls from erasing current history.

## Confirmed local development seams

- control plane: `127.0.0.1:3000`
- Sync WebSocket: `127.0.0.1:3003`

These loopback seams are used for initial protocol work so no installed
application or production service is modified.

## Evidence boundaries

The field names and client behavior above come from the authorized 1.12.7
renderer artifact and the local conformance harness. The push streaming
response value `next` is cross-checked against the public Obsidian Headless
protocol documentation. The project does not treat minified identifier names
or byte offsets as stable contracts.
