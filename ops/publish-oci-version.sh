#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <version> <image> <source-revision> <release-assets-directory>" >&2
  exit 2
fi

version=$1
image=$2
source_revision=$3
release_assets=$4

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=ops/release-version.sh
. "$script_dir/release-version.sh"

blackglass_is_supported_release_version "$version" || {
  echo "error: invalid image version: $version" >&2
  exit 1
}

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

[[ "$image" == ghcr.io/* ]] || {
  echo "error: image must be in ghcr.io" >&2
  exit 1
}
expected_image="ghcr.io/${GITHUB_REPOSITORY,,}"
[[ "$image" == "$expected_image" ]] || {
  echo "error: image must match this repository exactly: $expected_image" >&2
  exit 1
}
[[ "$source_revision" =~ ^[a-f0-9]{40}$ ]] || {
  echo "error: source revision must be a full lowercase Git commit" >&2
  exit 1
}
[[ -d "$release_assets" ]] || {
  echo "error: release assets directory is missing" >&2
  exit 1
}

source_date_epoch=$(git show -s --format=%ct "$source_revision")
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || {
  echo "error: could not resolve the source commit timestamp" >&2
  exit 1
}
export SOURCE_DATE_EPOCH=$source_date_epoch

work=$(mktemp -d)
candidate_manifest="$work/candidate-manifest.json"
verification_containers=()
cleanup() {
  for container in "${verification_containers[@]}"; do
    docker rm --force --volumes "$container" >/dev/null 2>&1 || true
  done
  rm -rf "$work"
}
trap cleanup EXIT

verify_published_child() {
  local architecture=$1
  local digest=$2
  local raw_binary=$3
  local reference="${image}@${digest}"
  local pulled=0
  local inspect_json="$work/image-inspect-${architecture}.json"
  local container_json="$work/container-inspect-${architecture}.json"
  local copied_binary="$work/image-binary-${architecture}"
  local copied_license="$work/image-license-${architecture}"
  local copied_notices="$work/image-notices-${architecture}"
  local container

  for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    if docker pull --platform "linux/${architecture}" "$reference"; then
      pulled=1
      break
    fi
    sleep 2
  done
  if [[ "$pulled" -ne 1 ]]; then
    echo "error: pushed ${architecture} child digest could not be pulled" >&2
    exit 1
  fi

  docker image inspect "$reference" > "$inspect_json"
  jq -e \
    --arg architecture "$architecture" \
    --arg source "https://github.com/${GITHUB_REPOSITORY}" \
    --arg revision "$source_revision" \
    --arg version "$version" '
      length == 1 and
      .[0].Os == "linux" and
      .[0].Architecture == $architecture and
      .[0].Config.User == "65532:65532" and
      .[0].Config.Entrypoint == ["/usr/local/bin/blackglass-server"] and
      .[0].Config.Cmd == ["serve"] and
      .[0].Config.WorkingDir == "/var/lib/blackglass-server" and
      (.[0].Config.Env | sort) == ([
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "SELFHOST_BIND_HOST=127.0.0.1",
        "SELFHOST_DATABASE=/var/lib/blackglass-server/server.sqlite",
        "SELFHOST_STAGING_DIR=/var/lib/blackglass-server/uploads"
      ] | sort) and
      .[0].Config.Labels["org.opencontainers.image.source"] == $source and
      .[0].Config.Labels["org.opencontainers.image.revision"] == $revision and
      .[0].Config.Labels["org.opencontainers.image.version"] == $version and
      .[0].Config.Labels["org.opencontainers.image.architecture"] == $architecture
    ' "$inspect_json" >/dev/null

  container=$(docker create --platform "linux/${architecture}" "$reference")
  [[ "$container" =~ ^[a-f0-9]{64}$ ]] || {
    echo "error: docker create returned an invalid container ID" >&2
    exit 1
  }
  verification_containers+=("$container")
  docker container inspect "$container" > "$container_json"
  jq -e \
    'length == 1 and .[0].State.Status == "created" and .[0].State.Running == false' \
    "$container_json" >/dev/null
  docker cp "${container}:/usr/local/bin/blackglass-server" "$copied_binary"
  docker cp "${container}:/licenses/LICENSE" "$copied_license"
  docker cp "${container}:/licenses/THIRD_PARTY_NOTICES.md" "$copied_notices"
  cmp -- "$raw_binary" "$copied_binary"
  cmp -- "$release_assets/LICENSE" "$copied_license"
  cmp -- "$release_assets/THIRD_PARTY_NOTICES.md" "$copied_notices"
  docker rm --volumes "$container" >/dev/null
}

declare -A architecture_digests
image_sources=()
for architecture in amd64 arm64; do
  target="linux-${architecture}"
  archive="${release_assets}/blackglass-server-v${version}-${target}.tar.gz"
  raw_binary="${release_assets}/blackglass-server-v${version}-${target}"
  ./ops/verify-linux-release.sh \
    "$target" "$archive" "$raw_binary" "$source_revision" \
    --execute-trusted-binary

  context="$work/context-${architecture}"
  mkdir -p "$context/state"
  cp "$raw_binary" "$context/blackglass-server"
  cp "$release_assets/LICENSE" "$context/LICENSE"
  cp "$release_assets/THIRD_PARTY_NOTICES.md" "$context/THIRD_PARTY_NOTICES.md"
  chmod 0555 "$context/blackglass-server"
  touch "$context/state/.blackglass-state"
  touch -d "@${source_date_epoch}" \
    "$context/blackglass-server" \
    "$context/LICENSE" \
    "$context/THIRD_PARTY_NOTICES.md" \
    "$context/state" \
    "$context/state/.blackglass-state"

  metadata="$work/image-metadata-${architecture}.json"
  docker buildx build \
    --platform "linux/${architecture}" \
    --file ops/Dockerfile.prebuilt \
    --build-arg "TARGETARCH=${architecture}" \
    --build-arg "VERSION=$version" \
    --build-arg "SOURCE_REVISION=$source_revision" \
    --build-arg "SOURCE_URL=https://github.com/${GITHUB_REPOSITORY}" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --provenance=false \
    --metadata-file "$metadata" \
    --output "type=image,name=${image},push-by-digest=true,name-canonical=true,push=true,rewrite-timestamp=true" \
    "$context"
  architecture_digest=$(jq -er '."containerimage.digest"' "$metadata")
  [[ "$architecture_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || {
    echo "error: invalid ${architecture} image digest" >&2
    exit 1
  }
  architecture_digests[$architecture]=$architecture_digest
  image_sources+=("${image}@${architecture_digest}")
  verify_published_child "$architecture" "$architecture_digest" "$raw_binary"
done

docker buildx imagetools create \
  --dry-run \
  --tag "$image:$version" \
  "${image_sources[@]}" > "$candidate_manifest"

# Buildx dry-run writes the exact manifest body followed by one presentation
# newline. The registry digest covers the body only; never reserialize it with
# jq because whitespace is part of the OCI digest.
last_two_bytes=$(tail -c 2 "$candidate_manifest" | od -An -tu1 | xargs)
[[ "$last_two_bytes" == "125 10" ]] || {
  echo "error: Buildx dry-run did not terminate its JSON manifest with one LF" >&2
  exit 1
}
candidate_body=$(<"$candidate_manifest")
printf '%s' "$candidate_body" > "$candidate_manifest"
jq -e \
  --arg amd64 "${architecture_digests[amd64]}" \
  --arg arm64 "${architecture_digests[arm64]}" '
    .schemaVersion == 2 and
    (.manifests | length) == 2 and
    any(.manifests[]; .platform.os == "linux" and .platform.architecture == "amd64" and .digest == $amd64) and
    any(.manifests[]; .platform.os == "linux" and .platform.architecture == "arm64" and .digest == $arm64)
  ' "$candidate_manifest" >/dev/null
candidate_digest="sha256:$(sha256sum "$candidate_manifest" | awk '{print $1}')"
[[ "$candidate_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || {
  echo "error: invalid candidate image-index digest" >&2
  exit 1
}

existing_manifest="$work/existing-manifest.json"
existing_error="$work/existing-manifest.error"
existing_state=unknown
# Repository-scoped Actions tokens can publish GHCR images but cannot reliably
# list every package owned by the user or organization. The registry manifest
# is the authoritative, repository-local state for this immutable tag.
for _attempt in 1 2 3 4 5; do
  if docker buildx imagetools inspect "$image:$version" \
    --format '{{json .Manifest}}' > "$existing_manifest" 2> "$existing_error"; then
    existing_state=present
    break
  fi
  if grep -Eiq 'manifest unknown|not found' "$existing_error"; then
    existing_state=absent
    break
  fi
  sleep 2
done
case "$existing_state" in
  present)
    existing_digest=$(jq -er '.digest' "$existing_manifest")
    if [[ "$existing_digest" != "$candidate_digest" ]]; then
      echo "error: verified image tag ${version} already points to ${existing_digest}, expected ${candidate_digest}" >&2
      exit 1
    fi
    ;;
  absent)
    docker buildx imagetools create \
      --tag "$image:$version" \
      "${image_sources[@]}"
    ;;
  *)
    echo "error: registry state for immutable image tag ${version} could not be determined" >&2
    cat "$existing_error" >&2
    exit 1
    ;;
esac

published_manifest="$work/published-manifest.json"
manifest_visible=0
for _attempt in 1 2 3 4 5 6 7 8 9 10; do
  if docker buildx imagetools inspect "$image:$version" \
    --format '{{json .Manifest}}' > "$published_manifest" &&
    jq -e 'type == "object"' "$published_manifest" >/dev/null; then
    manifest_visible=1
    break
  fi
  sleep 2
done
if [[ "$manifest_visible" -ne 1 ]]; then
  echo "error: published image index was not visible after the bounded retry" >&2
  exit 1
fi
jq -e \
  --arg digest "$candidate_digest" \
  --arg amd64 "${architecture_digests[amd64]}" \
  --arg arm64 "${architecture_digests[arm64]}" '
    .digest == $digest and
    (.manifests | length) == 2 and
    ([.manifests[].platform | select(.os == "linux") | .architecture] | sort) == ["amd64", "arm64"] and
    any(.manifests[]; .platform.os == "linux" and .platform.architecture == "amd64" and .digest == $amd64) and
    any(.manifests[]; .platform.os == "linux" and .platform.architecture == "arm64" and .digest == $arm64)
  ' "$published_manifest" >/dev/null

printf 'IMAGE_DIGEST=%s\n' "$candidate_digest" >> "$GITHUB_ENV"
echo "process-protected OCI image verified: $image:$version@$candidate_digest"
