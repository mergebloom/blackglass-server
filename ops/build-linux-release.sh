#!/bin/sh
set -eu

project_root=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/.." && pwd
)
cargo_toml="$project_root/apps/server-rust/Cargo.toml"
dist_dir=${BLACKGLASS_DIST_DIR:-"$project_root/artifacts/releases"}

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

command -v docker >/dev/null 2>&1 || {
    echo "Docker with Buildx is required" >&2
    exit 1
}
command -v curl >/dev/null 2>&1 || {
    echo "curl is required for the container reachability smoke" >&2
    exit 1
}
docker buildx version >/dev/null

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

source_revision=${SOURCE_REVISION:-unknown}
if command -v git >/dev/null 2>&1 && git -C "$project_root" rev-parse --verify HEAD >/dev/null 2>&1; then
    if test -n "$(git -C "$project_root" status --porcelain --untracked-files=all 2>/dev/null)"; then
        echo "refusing a release archive from a dirty worktree; commit the exact source first" >&2
        exit 1
    fi
    git_revision=$(git -C "$project_root" rev-parse --verify HEAD)
    if test "$source_revision" != unknown && test "$source_revision" != "$git_revision"; then
        echo "SOURCE_REVISION does not match the clean checkout HEAD" >&2
        exit 1
    fi
    source_revision=$git_revision
fi
test "$source_revision" != unknown || {
    echo "a verified source revision is required" >&2
    exit 1
}
case "$source_revision" in
    *[!A-Za-z0-9._-]*)
        echo "SOURCE_REVISION contains unsupported characters" >&2
        exit 1
        ;;
esac

mkdir -p "$dist_dir"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/blackglass-release.XXXXXX")
image="blackglass-server-smoke:${version}-${target}-$$"
container=
cleanup() {
    if test -n "$container"; then
        docker rm -f "$container" >/dev/null 2>&1 || true
    fi
    docker image rm -f "$image" >/dev/null 2>&1 || true
    rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM

docker buildx build \
    --platform "$platform" \
    --file "$project_root/ops/Dockerfile.release" \
    --target release \
    --build-arg "VERSION=$version" \
    --build-arg "SOURCE_REVISION=$source_revision" \
    --output "type=local,dest=$temporary/out" \
    "$project_root"

archive_name="blackglass-server-v${version}-${target}.tar.gz"
archive="$dist_dir/$archive_name"
checksum="$archive.sha256"
raw_binary_name="blackglass-server-v${version}-${target}"
raw_binary="$dist_dir/$raw_binary_name"
raw_checksum="$raw_binary.sha256"
test -f "$temporary/out/$archive_name"
test -f "$temporary/out/$archive_name.sha256"
test -f "$temporary/out/$raw_binary_name"
test -f "$temporary/out/$raw_binary_name.sha256"
cp "$temporary/out/$archive_name" "$archive"
cp "$temporary/out/$archive_name.sha256" "$checksum"
cp "$temporary/out/$raw_binary_name" "$raw_binary"
cp "$temporary/out/$raw_binary_name.sha256" "$raw_checksum"

docker buildx build \
    --platform "$platform" \
    --file "$project_root/ops/Dockerfile.release" \
    --target runtime \
    --build-arg "VERSION=$version" \
    --build-arg "SOURCE_REVISION=$source_revision" \
    --load \
    --tag "$image" \
    "$project_root"

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
    --stop-timeout 30 \
    --publish 127.0.0.1::3000 \
    --publish 127.0.0.1::3003 \
    --read-only \
    --memory 256m \
    --pids-limit 64 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777 \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --env SELFHOST_EMAIL=release-runtime@example.test \
    --env SELFHOST_DATA_HOST=sync-data.example.test \
    --env "SELFHOST_PASSWORD_HASH=$password_hash" \
    "$image" serve)
control_address=$(docker port "$container" 3000/tcp)
data_address=$(docker port "$container" 3003/tcp)
test -n "$control_address"
test -n "$data_address"
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
docker stop --time 30 "$container" >/dev/null
container=

"$project_root/ops/verify-linux-release.sh" "$target" "$archive" "$raw_binary"
echo "release ready: $archive and $raw_binary"
