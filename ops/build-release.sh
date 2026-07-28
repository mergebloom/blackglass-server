#!/bin/sh
set -eu

project_root=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/.." && pwd
)
manifest="$project_root/apps/server-rust/Cargo.toml"
source_revision=${SOURCE_REVISION:-unknown}
if command -v git >/dev/null 2>&1 \
    && git -C "$project_root" rev-parse --verify HEAD >/dev/null 2>&1 \
    && test -z "$(git -C "$project_root" status --porcelain --untracked-files=all 2>/dev/null)"; then
    source_revision=$(git -C "$project_root" rev-parse --verify HEAD)
fi

cargo test --locked --manifest-path "$manifest"
BLACKGLASS_SOURCE_REVISION="$source_revision" \
    cargo build --locked --release --manifest-path "$manifest"
binary="$project_root/apps/server-rust/target/release/blackglass-server"
"$binary" build-info
shasum -a 256 "$binary"
