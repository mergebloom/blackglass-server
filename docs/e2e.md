# Packaged-client qualification

Blackglass Server owns the automated protocol, migration, recovery, backup,
security-limit, and resource gates for the Rust/SQLite service. The companion
Blackglass Bridge repository owns qualification of an exact macOS client app
against an exact server binary.

This separation keeps server validation reproducible without committing
credentials, vault contents, proprietary client artifacts, screenshots, or a
dated run diary to this repository.

## Required packaged-client result

A client/server pair is qualified only when the Bridge E2E gate proves all of
the following with disposable profiles and vaults:

- the renderer, packaged app, configured HTTPS/WSS endpoints, and server
  `build-info` plus SHA-256 are bound into one evidence chain;
- two isolated clients sign in through the built-in UI and use the same E2EE
  remote vault;
- background Sync transfers files in both directions and propagates a deletion;
- both clients reconnect and transfer new data after a graceful server restart;
- after both local client trees are removed, a new empty client restores a
  mixed vault byte-for-byte from server-held data; and
- captured network evidence contains the intended control requests and data
  WebSocket handshakes, with no development-loopback fallback.

## Running it

Build and qualify the server gates first:

```sh
bun run check
./ops/build-release.sh
bun run server:measure
```

Then follow `docs/e2e.md` in the companion Blackglass Bridge checkout, passing
the exact `blackglass-server` binary produced from the commit being qualified.
That procedure creates the two clients, performs restart and source-loss
recovery, verifies artifact identities, and emits the sanitized validation
record required by the Bridge repository gate.

Historical experimental runs remain available in Git history. They are not
evidence for the current source or release artifacts.
