#!/bin/sh
set -eu

project_root=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/.." && pwd
)
dist_dir=${BLACKGLASS_DIST_DIR:-"$project_root/artifacts/releases"}
# shellcheck source=ops/release-version.sh
. "$project_root/ops/release-version.sh"

usage() {
    echo "usage: $0 <linux-amd64|linux-arm64>" >&2
    exit 2
}

target=${1:-}
case "$target" in
    linux-amd64) platform=linux/amd64 ;;
    linux-arm64) platform=linux/arm64 ;;
    *) usage ;;
esac

source_revision=${SOURCE_REVISION:-}
if test -n "$source_revision" \
    && ! blackglass_is_full_source_revision "$source_revision"; then
    echo "SOURCE_REVISION must be a full lowercase Git commit" >&2
    exit 1
fi
command -v git >/dev/null 2>&1 || {
    echo "a clean Git checkout is required for a release archive" >&2
    exit 1
}
git_revision=$(git -C "$project_root" rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || {
    echo "a clean Git checkout is required for a release archive" >&2
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
    echo "refusing a release archive from a dirty worktree; commit the exact source first" >&2
    exit 1
}
if test -n "$source_revision" && test "$source_revision" != "$git_revision"; then
    echo "SOURCE_REVISION does not match the clean checkout HEAD" >&2
    exit 1
fi
source_revision=$git_revision

# Every build input comes from this immutable commit-addressed export. A
# concurrent worktree edit or branch move cannot change the source labeled by
# source_revision after it has been resolved.
temporary=$(mktemp -d "${TMPDIR:-/tmp}/blackglass-release.XXXXXX")
source_archive="$temporary/source.tar"
source_context="$temporary/source"
image=
container=
publish_staging=
cleanup() {
    if test -n "$container"; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    if test -n "$image"; then
        docker image rm -f "$image" >/dev/null 2>&1 || true
    fi
    if test -n "$publish_staging"; then
        rm -rf "$publish_staging"
    fi
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM
mkdir "$source_context"
git -C "$project_root" archive \
    --format=tar \
    --output="$source_archive" \
    "$source_revision" || {
    echo "could not export the immutable release source commit" >&2
    exit 1
}
tar -xf "$source_archive" -C "$source_context"

"$source_context/ops/verify-release-metadata.sh" "$source_context"
cargo_toml="$source_context/apps/server-rust/Cargo.toml"
version=$(awk '
    $0 == "[package]" { in_package = 1; next }
    in_package && /^\[/ { exit }
    in_package && /^version = "/ {
        sub(/^version = "/, "")
        sub(/"$/, "")
        print
        exit
    }
' "$cargo_toml")
test -n "$version" || {
    echo "could not determine blackglass-server version" >&2
    exit 1
}
blackglass_is_supported_release_version "$version" || {
    echo "blackglass-server version is not a supported release version: $version" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || {
    echo "Docker with Buildx is required" >&2
    exit 1
}
command -v curl >/dev/null 2>&1 || {
    echo "curl is required for the container reachability smoke" >&2
    exit 1
}
docker buildx version >/dev/null

mkdir -p "$dist_dir"
image="blackglass-server-smoke:${version}-${target}-$$"

docker buildx build \
    --platform "$platform" \
    --file "$source_context/ops/Dockerfile.release" \
    --target release \
    --build-arg "VERSION=$version" \
    --build-arg "SOURCE_REVISION=$source_revision" \
    --output "type=local,dest=$temporary/out" \
    "$source_context"

archive_name="blackglass-server-v${version}-${target}.tar.gz"
archive="$dist_dir/$archive_name"
checksum="$archive.sha256"
raw_binary_name="blackglass-server-v${version}-${target}"
raw_binary="$dist_dir/$raw_binary_name"
raw_checksum="$raw_binary.sha256"
staged_archive="$temporary/out/$archive_name"
staged_checksum="$staged_archive.sha256"
staged_raw_binary="$temporary/out/$raw_binary_name"
staged_raw_checksum="$staged_raw_binary.sha256"
test -f "$staged_archive"
test -f "$staged_checksum"
test -f "$staged_raw_binary"
test -f "$staged_raw_checksum"
"$source_context/ops/verify-linux-release.sh" \
    "$target" "$staged_archive" "$staged_raw_binary" "$source_revision" \
    --execute-trusted-binary

docker buildx build \
    --platform "$platform" \
    --file "$source_context/ops/Dockerfile.release" \
    --target runtime \
    --build-arg "VERSION=$version" \
    --build-arg "SOURCE_REVISION=$source_revision" \
    --load \
    --tag "$image" \
    "$source_context"

actual_version=$(docker run --rm \
    --platform "$platform" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    "$image" --version)
test "$actual_version" = "blackglass-server $version"

password_hash=$(printf '%s\n' release-runtime-password | docker run --rm -i \
    --platform "$platform" \
    --read-only \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    "$image" hash-password)
container=$(docker run --detach --rm \
    --platform "$platform" \
    --network host \
    --stop-timeout 30 \
    --read-only \
    --memory 256m \
    --pids-limit 64 \
    --ulimit nofile=4096:4096 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --env SELFHOST_EMAIL=release-runtime@example.test \
    --env SELFHOST_BIND_HOST=127.0.0.1 \
    --env SELFHOST_ACKNOWLEDGE_EXTERNAL_BIND= \
    --env SELFHOST_TRUSTED_PROXY=127.0.0.1 \
    --env SELFHOST_DATA_HOST=sync-data.example.test \
    --env "SELFHOST_PASSWORD_HASH=$password_hash" \
    "$image" serve)
control_address=127.0.0.1:3000
data_address=127.0.0.1:3003
started=0
for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    if curl --fail --silent "http://$control_address/health" > "$temporary/container-health.json" \
        && curl --silent --output /dev/null "http://$data_address/" \
        && docker logs "$container" 2>&1 | grep -q '"event":"server_started"'; then
        started=1
        break
    fi
    sleep 1
done
test "$started" -eq 1
grep -q '"service":"blackglass-server"' "$temporary/container-health.json"
docker stop --timeout 30 "$container" >/dev/null
container=

for destination in "$archive" "$checksum" "$raw_binary" "$raw_checksum"; do
    if test -e "$destination" || test -L "$destination"; then
        echo "refusing to overwrite an existing release artifact: $destination" >&2
        exit 1
    fi
done

# Stage on the destination filesystem, then use no-overwrite hard links so a
# failed build can never replace a previously qualified release artifact.
publish_staging=$(mktemp -d "$dist_dir/.blackglass-publish.XXXXXX")
cp "$staged_archive" "$publish_staging/$archive_name"
cp "$staged_checksum" "$publish_staging/$archive_name.sha256"
cp "$staged_raw_binary" "$publish_staging/$raw_binary_name"
cp "$staged_raw_checksum" "$publish_staging/$raw_binary_name.sha256"
for name in "$archive_name" "$archive_name.sha256" "$raw_binary_name" "$raw_binary_name.sha256"; do
    if ! ln "$publish_staging/$name" "$dist_dir/$name"; then
        for candidate in "$archive_name" "$archive_name.sha256" "$raw_binary_name" "$raw_binary_name.sha256"; do
            if test -e "$dist_dir/$candidate" \
                && test "$dist_dir/$candidate" -ef "$publish_staging/$candidate"; then
                rm -f "$dist_dir/$candidate"
            fi
        done
        echo "release publication raced with another writer; no artifacts were retained" >&2
        exit 1
    fi
done
rm -rf "$publish_staging"
publish_staging=
"$source_context/ops/verify-linux-release.sh" \
    "$target" "$archive" "$raw_binary" "$source_revision" \
    --execute-trusted-binary
echo "release ready: $archive and $raw_binary"
