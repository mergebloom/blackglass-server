# Obsidian 1.12.7 Sync protocol notes

Status: static client inventory plus loopback server conformance tests.

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

The first milestone implements sign-in, sign-out, user information,
subscription information, region listing, vault list/create/access/rename/
delete, and an empty share list. Share mutations return a clean single-user
error; migration is outside the milestone.

## Data plane

The Sync client persists a control-plane-provided `host`. It derives:

- `ws://host` for `localhost` or `127.0.0.1`;
- `wss://host` otherwise.

The reference client currently accepts `127.0.0.1` or a hostname ending in
`.obsidian.md`. The compatibility adapter will replace this with an exact
configured-origin check.

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
| two-device convergence | Bidirectional byte-identical E2E pass |
| multi-user sharing | Deliberately unsupported |

### History response contracts

- `deleted` returns `{items}` oldest-first. Rename-source tombstones are omitted
  when `suppressrenames` is true.
- `history` returns `{items, more}` newest-first and paginates with UID `< last`.
- Every item includes `uid`, server `ts`, encrypted `path`, `relatedpath`, file
  flags/size, and device/user identifiers.
- `restore` creates and broadcasts a new live revision; restoring a tombstone
  uses its most recent prior live content.
- `purge` retains one current live head per live path, removes tombstoned path
  history, and preserves the monotonic vault version.

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
