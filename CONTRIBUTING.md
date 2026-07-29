# Contributing

Blackglass Server accepts protocol-compatibility, security, operations,
performance, test, and documentation improvements. Do not submit proprietary
client artifacts, credentials, vault content, production databases, or raw E2E
evidence.

## Development gate

Use Rust 1.92 or newer and Bun 1.3 or newer:

```sh
npm ci
bun run check
cargo test --locked --manifest-path apps/server-rust/Cargo.toml
```

All network tests must bind loopback and use temporary databases. Protocol
changes need Rust/Bun parity coverage, migration coverage when persistence is
affected, and an official-client qualification record in Blackglass Bridge.

The Rust service is the production implementation. The Bun service is a
loopback-only protocol oracle and must not be presented as production-ready.

When `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, the release Dockerfile,
or the audited native/runtime notice changes, install exactly `cargo-about
0.9.1` with its `cli` feature, fetch the locked graph, and run `bun run
licenses:generate`. The normal gate rejects notices whose dependency, feature,
toolchain, builder, configuration, template, native-runtime, or output hash is
stale.
