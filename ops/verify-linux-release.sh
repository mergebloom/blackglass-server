#!/bin/sh
set -eu

usage() {
    echo "usage: $0 <linux-amd64|linux-arm64> <archive>" >&2
    exit 2
}

target=${1:-}
archive=${2:-}
case "$target" in
    linux-amd64) file_architecture='x86-64' ;;
    linux-arm64) file_architecture='ARM aarch64' ;;
    *) usage ;;
esac
test -n "$archive" || usage
test -f "$archive"
test -f "$archive.sha256"

sha256_value() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

archive_dir=$(
    unset CDPATH
    cd -- "$(dirname -- "$archive")" && pwd
)
archive_name=$(basename -- "$archive")
case "$archive_name" in
    blackglass-server-v*-$target.tar.gz) ;;
    *)
        echo "archive name does not match target: $archive_name" >&2
        exit 1
        ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$archive_dir" && sha256sum -c "$archive_name.sha256")
else
    (cd "$archive_dir" && shasum -a 256 -c "$archive_name.sha256")
fi

bundle=${archive_name%.tar.gz}
expected=$(printf '%s\n' \
    "$bundle/" \
    "$bundle/INSTALL.md" \
    "$bundle/LICENSE" \
    "$bundle/blackglass-server" \
    "$bundle/manifest.json")
actual=$(tar -tzf "$archive")
test "$actual" = "$expected" || {
    echo "unexpected archive contents" >&2
    printf '%s\n' "$actual" >&2
    exit 1
}

temporary=$(mktemp -d "${TMPDIR:-/tmp}/blackglass-verify.XXXXXX")
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM
tar -xzf "$archive" -C "$temporary"

binary="$temporary/$bundle/blackglass-server"
manifest="$temporary/$bundle/manifest.json"
test -x "$binary"
file "$binary" | grep -q 'ELF 64-bit'
file "$binary" | grep -q "$file_architecture"
file "$binary" | grep -Eq 'static-pie linked|statically linked'

binary_sha=$(sha256_value "$binary")
binary_size=$(wc -c < "$binary" | tr -d ' ')
grep -q '"schemaVersion": 1' "$manifest"
grep -q '"name": "blackglass-server"' "$manifest"
grep -q "\"target\": \"$target\"" "$manifest"
grep -q '"libc": "musl"' "$manifest"
grep -q "\"binarySha256\": \"$binary_sha\"" "$manifest"
grep -q "\"binarySize\": $binary_size" "$manifest"

echo "verified: $archive_name ($target, $binary_size bytes, $binary_sha)"
