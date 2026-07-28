#!/bin/sh
set -eu

project_root=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/.." && pwd
)
# shellcheck source=ops/release-version.sh
. "$project_root/ops/release-version.sh"

source_revision=${SOURCE_REVISION:-}
if test -n "$source_revision" \
    && ! blackglass_is_full_source_revision "$source_revision"; then
    echo "SOURCE_REVISION must be a full lowercase Git commit" >&2
    exit 1
fi
command -v git >/dev/null 2>&1 || {
    echo "a clean Git checkout is required for a release build" >&2
    exit 1
}
git_revision=$(git -C "$project_root" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || {
    echo "a clean Git checkout is required for a release build" >&2
    exit 1
}
blackglass_is_full_source_revision "$git_revision" || {
    echo "Git HEAD is not a full lowercase commit revision" >&2
    exit 1
}
if ! worktree_status=$(git -C "$project_root" status --porcelain --untracked-files=all 2>/dev/null); then
    echo "could not verify that the release checkout is clean" >&2
    exit 1
fi
test -z "$worktree_status" || {
    echo "refusing a release binary from a dirty worktree; commit the exact source first" >&2
    exit 1
}
if test -n "$source_revision" && test "$source_revision" != "$git_revision"; then
    echo "SOURCE_REVISION does not match the clean checkout HEAD" >&2
    exit 1
fi
source_revision=$git_revision

temporary=$(mktemp -d "${TMPDIR:-/tmp}/blackglass-native-release.XXXXXX")
publish_staging=
cleanup() {
    if test -n "$publish_staging"; then
        rm -f "$publish_staging"
    fi
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM
source_archive="$temporary/source.tar"
source_tree="$temporary/source"
mkdir "$source_tree"
git -C "$project_root" archive \
    --format=tar \
    --output="$source_archive" \
    "$source_revision" || {
    echo "could not export the immutable release source commit" >&2
    exit 1
}
tar -xf "$source_archive" -C "$source_tree"

"$source_tree/ops/verify-release-metadata.sh" "$source_tree"
manifest="$source_tree/apps/server-rust/Cargo.toml"
version=$(jq -er '.version' "$source_tree/package.json")
build_target_directory="$temporary/cargo-target"
(
    unset CDPATH
    cd -- "$source_tree"
    CARGO_TARGET_DIR="$build_target_directory" \
        cargo test --locked --manifest-path "$manifest"
    BLACKGLASS_SOURCE_REVISION="$source_revision" \
        CARGO_TARGET_DIR="$build_target_directory" \
        cargo build --locked --release --manifest-path "$manifest"
)
built_binary="$build_target_directory/release/blackglass-server"
binary_sha=$("$source_tree/ops/verify-native-release-binary.sh" \
    "$built_binary" "$version" "$source_revision")

# Publish only the already-attested bytes. The staging file and destination are
# on the same filesystem, so rename is atomic even when replacing an older
# developer build at the legacy target path.
target_directory="$project_root/apps/server-rust/target"
destination_directory="$target_directory/release"
test ! -L "$target_directory"
mkdir -p "$destination_directory"
test ! -L "$destination_directory"
binary="$destination_directory/blackglass-server"
test ! -L "$binary"
publish_staging=$(mktemp "$destination_directory/.blackglass-server.XXXXXX")
cp "$built_binary" "$publish_staging"
chmod 0755 "$publish_staging"
cmp "$built_binary" "$publish_staging"
staged_sha=$("$source_tree/ops/verify-native-release-binary.sh" \
    "$publish_staging" "$version" "$source_revision")
test "$staged_sha" = "$binary_sha"
mv -f "$publish_staging" "$binary"
publish_staging=
published_sha=$("$source_tree/ops/verify-native-release-binary.sh" \
    "$binary" "$version" "$source_revision")
test "$published_sha" = "$binary_sha"
printf '%s  %s\n' "$binary_sha" "$binary"
