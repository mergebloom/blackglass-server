#!/bin/sh
set -eu

project_root=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/.." && pwd
)
manifest="$project_root/apps/server-rust/Cargo.toml"

cargo test --locked --manifest-path "$manifest"
cargo build --locked --release --manifest-path "$manifest"
binary="$project_root/apps/server-rust/target/release/blackglass-server"
shasum -a 256 "$binary"
