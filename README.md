# Blackglass Server

Blackglass Server is a lean, self-hosted Sync backend for qualified Obsidian
desktop clients. It preserves the client's built-in Sync and end-to-end
encryption flows while replacing Obsidian's remote control and data services.

Blackglass is independent and is not affiliated with or endorsed by Obsidian.

## Project goal

The intended outcome is to let people host their own Obsidian-compatible Sync
service and keep using the Obsidian desktop app's built-in Sync experience,
without losing Sync functionality. The operator controls the service, encrypted
vault data, backups, retention, and deployment, providing data sovereignty and
privacy without dependence on Obsidian's hosted Sync infrastructure. End-to-end
encryption protects vault contents; as noted in the security model below, the
server can still observe some metadata.

The stable server/client boundary and Blackglass's small, fail-closed
endpoint adaptation are designed to make qualification of future Obsidian
releases repeatable and low-maintenance rather than a continuing fork of the
application.

Blackglass began as a research project exploring how frontier language models
can support protocol analysis, clean-room compatible implementation, release
adaptation, and end-to-end validation. Generated findings remain subject to the
same tests, artifact hashes, and release gates as any other contribution.

## Supported scope

| Area | Current support |
| --- | --- |
| Deployment | One owner, one server node, local SQLite storage |
| Sync | Account, vault, history, upload, download, and recovery |
| Encryption | Client-managed and server-managed encrypted vaults |
| Client target | macOS desktop on Apple Silicon; Obsidian renderer 1.12.7 first |
| Server hosts | 64-bit Linux on amd64 or arm64; native binary or OCI image |

Publish, public registration, sharing, high availability,
mobile clients, Windows servers, and 32-bit hosts are not supported yet.

## Architecture

The server runs one Rust process with separate HTTP control and WebSocket Sync
listeners. Native installs and the OCI image default to loopback. The supported
Linux Docker deployment uses host networking so host Caddy can reach those
listeners without publishing plaintext ports. Caddy is the only public
listener. SQLite stores opaque ciphertext and protocol state behind an atomic
retained-history quota. Blackglass owns the small,
release-specific client endpoint adapter.

See [architecture](docs/architecture.md) for the component and trust boundaries.

## Quick start

Requirement: Rust 1.92 or newer.

```sh
cargo test --locked --manifest-path apps/server-rust/Cargo.toml
```

Start a loopback-only development server:

```sh
printf '%s\n' 'replace-this' | cargo run --release --locked \
  --manifest-path apps/server-rust/Cargo.toml -- \
  user create ./selfhost-sync.sqlite admin@example.test 'Local admin'
cargo run --release --locked \
  --manifest-path apps/server-rust/Cargo.toml -- serve
```

The default listeners are `127.0.0.1:3000` and `127.0.0.1:3003`.
Account passwords are read from standard input by offline user-management
commands and stored only as bounded Argon2id hashes in SQLite. Serving does not
read account credentials from environment variables. Plaintext transport is
for loopback development only.

An optional dependency-free, read-only admin console can run on a third,
independently configured listener. It is disabled unless all three admin
variables are set, is never mounted on either Sync listener, and accepts a
separate 64-character lowercase-hex bearer token whose configuration contains
only a SHA-256 hash. See the production guide; never publish this listener to
the Internet.

## Deploy

Tagged releases produce checksummed static-musl archives and separately
downloadable raw binaries for `linux-amd64` and `linux-arm64`, plus a minimal
non-root multi-architecture OCI image. Archives, raw-binary release assets, and
the image include the applicable project and third-party license notices. Start
with [distribution](docs/distribution.md) to select and verify an artifact, then use
[production operations](docs/production.md) for TLS, systemd, backups,
monitoring, upgrades, and recovery.

The production executable is `blackglass-server`:

```sh
blackglass-server --version
blackglass-server --help
```

## Security model

Clients encrypt content, paths, and hashes before transmission. With a custom
vault password, the server never receives that password and cannot decrypt the
vault; it can still observe metadata and is trusted for availability and
revision ordering. In the built-in managed-encryption mode, the server securely
generates and stores the recovery password, so the operator is additionally in
the confidentiality trust boundary. Account passwords use Argon2id; sessions
are expiring, revocable bearer tokens whose digests are stored. Production
defaults to loopback behind HTTPS/WSS, and memory use is bounded by frame and
concurrency limits. The qualified container topology keeps loopback binding and
uses Linux host networking behind host Caddy.

Read the full [security model](docs/security.md). Report vulnerabilities using
[SECURITY.md](SECURITY.md), not a public issue.

## Validation

Artifact-bound resource reports ship with each tagged release;
[docs/validation](docs/validation/README.md) documents the evidence model.
Rebuilding a binary changes its hash and requires the artifact-level
qualification gates to run again.

## Documentation

| Guide | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Components, persistence, and compatibility boundary |
| [Production](docs/production.md) | Hardened deployment, operations, backup, and rollback |
| [Distribution](docs/distribution.md) | Linux artifacts, containers, checksums, and provenance |
| [Protocol](docs/protocol/obsidian-1.12.7.md) | Observed Sync contract for the qualified renderer |
| [E2E](docs/e2e.md) | Cross-project validation procedure |

Development requirements are in [CONTRIBUTING.md](CONTRIBUTING.md). The
independently written server is licensed under the [MIT License](LICENSE); that
license does not cover Obsidian or any proprietary client artifact.
