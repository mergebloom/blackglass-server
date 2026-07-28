#!/bin/sh
set -eu

project_root=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/.." && pwd
)
# shellcheck source=ops/release-version.sh
. "$project_root/ops/release-version.sh"

if test "$#" -ne 3; then
    echo "usage: $0 <binary> <version> <source-revision>" >&2
    exit 2
fi
binary=$1
version=$2
source_revision=$3

blackglass_is_supported_release_version "$version" || {
    echo "expected binary version is not a supported release version" >&2
    exit 1
}
blackglass_is_full_source_revision "$source_revision" || {
    echo "expected binary source revision must be a full lowercase Git commit" >&2
    exit 1
}
command -v jq >/dev/null 2>&1 || {
    echo "jq is required to validate native release build-info" >&2
    exit 1
}
test -f "$binary"
test ! -L "$binary"
test -x "$binary"

actual_version=$("$binary" --version) || {
    echo "native release binary did not report its version" >&2
    exit 1
}
test "$actual_version" = "blackglass-server $version" || {
    echo "native release binary version does not match the source snapshot" >&2
    exit 1
}

temporary=$(mktemp -d "${TMPDIR:-/tmp}/blackglass-native-attestation.XXXXXX")
cleanup() {
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM
build_info="$temporary/build-info.json"
"$binary" build-info > "$build_info" || {
    echo "native release binary did not report build-info" >&2
    exit 1
}
jq --stream -s -e '
    [.[] | select(length == 2) | .[0]] as $paths |
    all($paths[]; length == 1) and
    ($paths | map(@json) | length) == ($paths | map(@json) | unique | length)
' "$build_info" >/dev/null || {
    echo "native release binary build-info contains duplicate JSON paths" >&2
    exit 1
}
jq -e \
    --arg version "$version" \
    --arg source_revision "$source_revision" '
      type == "object" and
      (keys | sort) == (["name", "sourceRevision", "version"] | sort) and
      .name == "blackglass-server" and
      .version == $version and
      .sourceRevision == $source_revision
    ' "$build_info" >/dev/null || {
    echo "native release binary build-info does not match the source snapshot" >&2
    exit 1
}

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$binary" | cut -d ' ' -f 1
else
    shasum -a 256 "$binary" | cut -d ' ' -f 1
fi
