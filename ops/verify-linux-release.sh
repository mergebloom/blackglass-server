#!/bin/sh
set -eu

project_root=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/.." && pwd
)
# shellcheck source=ops/release-version.sh
. "$project_root/ops/release-version.sh"

usage() {
    echo "usage: $0 <linux-amd64|linux-arm64> <archive> [raw-binary] [expected-source-revision] [--execute-trusted-binary]" >&2
    exit 2
}

test "$#" -le 5 || usage
target=${1:-}
archive=${2:-}
raw_binary=${3:-}
expected_source_revision=${4:-}
execution_mode=${5:-}
case "$execution_mode" in
    '') execute_trusted_binary=0 ;;
    --execute-trusted-binary) execute_trusted_binary=1 ;;
    *) usage ;;
esac
if test "$execute_trusted_binary" -eq 1 \
    && test -z "$expected_source_revision"; then
    echo "executing a trusted binary requires its expected source revision" >&2
    exit 1
fi
case "$target" in
    linux-amd64)
        architecture=amd64
        file_architecture='x86-64'
        ;;
    linux-arm64)
        architecture=arm64
        file_architecture='ARM aarch64'
        ;;
    *) usage ;;
esac
test -n "$archive" || usage
test -f "$archive"
test -f "$archive.sha256"
command -v jq >/dev/null 2>&1 || {
    echo "jq is required to validate the release manifest" >&2
    exit 1
}
if test -n "$expected_source_revision" \
    && ! blackglass_is_full_source_revision "$expected_source_revision"; then
    echo "expected source revision must be a full lowercase Git commit" >&2
    exit 1
fi

sha256_value() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

archive_name=$(basename -- "$archive")
case "$archive_name" in
    blackglass-server-v*-$target.tar.gz) ;;
    *)
        echo "archive name does not match target: $archive_name" >&2
        exit 1
        ;;
esac
version=${archive_name#blackglass-server-v}
archive_suffix="-$target.tar.gz"
version=${version%"$archive_suffix"}
blackglass_is_supported_release_version "$version" || {
    echo "archive name contains an unsupported release version: $version" >&2
    exit 1
}

archive_sha=$(sha256_value "$archive")
expected_archive_checksum="$archive_sha  $archive_name"
actual_archive_checksum=$(cat "$archive.sha256")
test "$actual_archive_checksum" = "$expected_archive_checksum" || {
    echo "archive checksum record does not match $archive_name" >&2
    exit 1
}

bundle=${archive_name%.tar.gz}
expected=$(printf '%s\n' \
    "$bundle/" \
    "$bundle/INSTALL.md" \
    "$bundle/LICENSE" \
    "$bundle/blackglass-server" \
    "$bundle/blackglass-server.env.example" \
    "$bundle/blackglass-server.service" \
    "$bundle/blackglass-server.sysusers.conf" \
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
bundle_directory="$temporary/$bundle"
test -d "$bundle_directory"
test ! -L "$bundle_directory"
for relative_path in \
    INSTALL.md \
    LICENSE \
    blackglass-server \
    blackglass-server.env.example \
    blackglass-server.service \
    blackglass-server.sysusers.conf \
    manifest.json; do
    test -f "$bundle_directory/$relative_path"
    test ! -L "$bundle_directory/$relative_path"
done
test -x "$binary"
file "$binary" | grep -q 'ELF 64-bit'
file "$binary" | grep -q "$file_architecture"
file "$binary" | grep -Eq 'static-pie linked|statically linked'

binary_sha=$(sha256_value "$binary")
binary_size=$(wc -c < "$binary" | tr -d ' ')
rust_version=$(awk -F '"' '
    /^channel = "[^"]+"$/ { matches++; value = $2 }
    END { if (matches != 1) exit 2; print value }
' "$project_root/rust-toolchain.toml") || {
    echo "could not determine the pinned Rust toolchain" >&2
    exit 1
}
builder_image=$(awk -F '"' '
    /^ARG RUST_BUILDER="[^"]+"$/ { matches++; value = $2 }
    END { if (matches != 1) exit 2; print value }
' "$project_root/ops/Dockerfile.release") || {
    echo "could not determine the pinned Rust builder image" >&2
    exit 1
}

# jq normally resolves duplicate object keys with last-key-wins semantics. Its
# streaming form retains each raw value path, allowing this flat manifest to
# reject parser-ambiguous duplicate keys before ordinary object validation.
jq --stream -s -e '
    [.[] | select(length == 2) | .[0]] as $paths |
    all($paths[]; length == 1) and
    ($paths | map(@json) | length) == ($paths | map(@json) | unique | length)
' "$manifest" >/dev/null || {
    echo "release manifest contains duplicate JSON paths" >&2
    exit 1
}

jq -e \
    --arg version "$version" \
    --arg target "$target" \
    --arg architecture "$architecture" \
    --arg binary_sha "$binary_sha" \
    --argjson binary_size "$binary_size" \
    --arg rust_version "$rust_version" \
    --arg builder_image "$builder_image" \
    --arg expected_source_revision "$expected_source_revision" '
      type == "object" and
      (keys | sort) == ([
        "architecture",
        "binary",
        "binarySha256",
        "binarySize",
        "builderImage",
        "libc",
        "name",
        "os",
        "rustVersion",
        "schemaVersion",
        "sourceRevision",
        "target",
        "version"
      ] | sort) and
      .schemaVersion == 1 and
      .name == "blackglass-server" and
      .version == $version and
      .target == $target and
      .os == "linux" and
      .architecture == $architecture and
      .libc == "musl" and
      .binary == "blackglass-server" and
      .binarySha256 == $binary_sha and
      .binarySize == $binary_size and
      .rustVersion == $rust_version and
      .builderImage == $builder_image and
      (.sourceRevision |
        type == "string" and
        length == 40 and
        test("^[a-f0-9]+$")) and
      ($expected_source_revision == "" or .sourceRevision == $expected_source_revision)
    ' "$manifest" >/dev/null || {
    echo "release manifest does not match the archive, target, or pinned build metadata" >&2
    exit 1
}
source_revision=$(jq -er '.sourceRevision' "$manifest")

host_target=
if test "$(uname -s 2>/dev/null || true)" = Linux; then
    case "$(uname -m 2>/dev/null || true)" in
        x86_64 | amd64) host_target=linux-amd64 ;;
        aarch64 | arm64) host_target=linux-arm64 ;;
    esac
fi
if test "$execute_trusted_binary" -eq 1 && test "$host_target" = "$target"; then
    actual_version=$("$binary" --version)
    test "$actual_version" = "blackglass-server $version" || {
        echo "release binary version does not match its archive: $actual_version" >&2
        exit 1
    }
    build_info="$temporary/build-info.json"
    "$binary" build-info > "$build_info"
    jq -e \
        --arg version "$version" \
        --arg source_revision "$source_revision" '
          type == "object" and
          (keys | sort) == (["name", "sourceRevision", "version"] | sort) and
          .name == "blackglass-server" and
          .version == $version and
          .sourceRevision == $source_revision
        ' "$build_info" >/dev/null || {
        echo "release binary build-info does not match its manifest" >&2
        exit 1
    }
fi

if test -n "$raw_binary"; then
    test -f "$raw_binary"
    test -f "$raw_binary.sha256"
    raw_name=$(basename -- "$raw_binary")
    test "$raw_name" = "$bundle"
    raw_sha=$(sha256_value "$raw_binary")
    expected_raw_checksum="$raw_sha  $raw_name"
    actual_raw_checksum=$(cat "$raw_binary.sha256")
    test "$actual_raw_checksum" = "$expected_raw_checksum" || {
        echo "raw binary checksum record does not match $raw_name" >&2
        exit 1
    }
    cmp "$raw_binary" "$binary"
    test "$raw_sha" = "$binary_sha"
fi

echo "verified: $archive_name ($target, $binary_size bytes, $binary_sha, $source_revision)"
