#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <version> <image> <expected-digest>" >&2
  exit 2
fi

version=$1
image=$2
expected_digest=$3

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || {
  echo "error: invalid image version: $version" >&2
  exit 1
}
[[ "$expected_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || {
  echo "error: invalid expected image digest" >&2
  exit 1
}
expected_image="ghcr.io/${GITHUB_REPOSITORY,,}"
[[ "$image" == "$expected_image" ]] || {
  echo "error: image must match this repository exactly: $expected_image" >&2
  exit 1
}
if [[ "$version" == *-* ]]; then
  echo "prerelease image does not move latest: $version"
  exit 0
fi

owner=${GITHUB_REPOSITORY%%/*}
package=${GITHUB_REPOSITORY#*/}
package=${package,,}
owner_type=$(gh api "repos/${GITHUB_REPOSITORY}" --jq '.owner.type')
case "$owner_type" in
  Organization) packages_endpoint="orgs/${owner}/packages?package_type=container&per_page=100" ;;
  User) packages_endpoint="users/${owner}/packages?package_type=container&per_page=100" ;;
  *)
    echo "error: unsupported GitHub repository owner type: $owner_type" >&2
    exit 1
    ;;
esac

versions_json=$(mktemp)
packages_json="${versions_json}.packages"
manifest_json="${versions_json}.manifest"
release_json="${versions_json}.release"
latest_release_json="${versions_json}.latest-release"
trap 'rm -f "$versions_json" "$packages_json" "$manifest_json" "$release_json" "$latest_release_json"' EXIT

wait_for_registry_digest() {
  local reference=$1
  local expected=$2
  for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    if docker buildx imagetools inspect "$reference" \
      --format '{{json .Manifest}}' > "$manifest_json" 2>/dev/null \
      && [[ "$(jq -er '.digest' "$manifest_json" 2>/dev/null)" == "$expected" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "error: registry reference ${reference} did not resolve to ${expected}" >&2
  return 1
}

wait_for_github_latest_release() {
  local expected_release_id=$1
  for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    if gh api "repos/${GITHUB_REPOSITORY}/releases/latest" > "$latest_release_json" \
      && [[ "$(jq -er '.id' "$latest_release_json")" == "$expected_release_id" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "error: GitHub Latest did not identify release ${expected_release_id}" >&2
  return 1
}

gh api --paginate "$packages_endpoint" --slurp | jq 'add' > "$packages_json"
package_count=$(jq --arg package "$package" '[.[] | select(.name == $package and .package_type == "container")] | length' "$packages_json")
if [[ "$package_count" -ne 1 ]]; then
  echo "error: expected one accessible GitHub container package named ${package}, found ${package_count}" >&2
  exit 1
fi
package_url=$(jq -er --arg package "$package" '.[] | select(.name == $package and .package_type == "container") | .url' "$packages_json")
case "$package_url" in
  https://api.github.com/*) versions_endpoint="${package_url#https://api.github.com/}/versions?per_page=100" ;;
  *)
    echo "error: GitHub returned an unexpected package API URL" >&2
    exit 1
    ;;
esac

load_versions() {
  gh api --paginate "$versions_endpoint" --slurp | jq 'add' > "$versions_json"
  jq -e 'type == "array"' "$versions_json" >/dev/null
}

load_versions
version_count=$(jq --arg tag "$version" '[.[] | select(.metadata.container.tags | index($tag))] | length' "$versions_json")
if [[ "$version_count" -ne 1 ]] ||
  [[ "$(jq -er --arg tag "$version" '.[] | select(.metadata.container.tags | index($tag)) | .name' "$versions_json")" != "$expected_digest" ]]; then
  echo "error: refusing latest promotion without the exact verified version tag" >&2
  exit 1
fi

highest_stable=$(jq -r '[.[].metadata.container.tags[] | select(test("^[0-9]+\\.[0-9]+\\.[0-9]+$"))] | unique[]' "$versions_json" | sort -V | tail -n 1)
if [[ "$highest_stable" != "$version" ]]; then
  highest_count=$(jq --arg tag "$highest_stable" '[.[] | select(.metadata.container.tags | index($tag))] | length' "$versions_json")
  latest_count=$(jq '[.[] | select(.metadata.container.tags | index("latest"))] | length' "$versions_json")
  [[ "$highest_count" -eq 1 && "$latest_count" -eq 1 ]] || {
    echo "error: newer stable version exists without one exact latest alias" >&2
    exit 1
  }
  highest_digest=$(jq -er --arg tag "$highest_stable" '.[] | select(.metadata.container.tags | index($tag)) | .name' "$versions_json")
  latest_digest=$(jq -er '.[] | select(.metadata.container.tags | index("latest")) | .name' "$versions_json")
  [[ "$latest_digest" == "$highest_digest" ]] || {
    echo "error: latest does not point to newer stable version $highest_stable" >&2
    exit 1
  }
  wait_for_registry_digest "$image:latest" "$highest_digest"
  gh api "repos/${GITHUB_REPOSITORY}/releases/tags/v${highest_stable}" > "$release_json"
  highest_release_id=$(jq -er \
    --arg tag "v${highest_stable}" \
    'select(.tag_name == $tag and .draft == false and .prerelease == false) | .id' \
    "$release_json")
  wait_for_github_latest_release "$highest_release_id"
  echo "older stable $version published without moving verified latest $highest_stable"
  exit 0
fi

latest_count=$(jq '[.[] | select(.metadata.container.tags | index("latest"))] | length' "$versions_json")
if [[ "$latest_count" -gt 1 ]]; then
  echo "error: multiple container versions claim latest" >&2
  exit 1
fi
if [[ "$latest_count" -eq 1 ]] &&
  [[ "$(jq -er '.[] | select(.metadata.container.tags | index("latest")) | .name' "$versions_json")" == "$expected_digest" ]]; then
  echo "latest already has the expected Packages API digest; verifying the registry"
else
  docker buildx imagetools create --tag "$image:latest" "$image@$expected_digest"
fi

wait_for_registry_digest "$image:latest" "$expected_digest"

verified=0
for _attempt in 1 2 3 4 5 6 7 8 9 10; do
  load_versions
  latest_count=$(jq '[.[] | select(.metadata.container.tags | index("latest"))] | length' "$versions_json")
  if [[ "$latest_count" -eq 1 ]] &&
    [[ "$(jq -er '.[] | select(.metadata.container.tags | index("latest")) | .name' "$versions_json")" == "$expected_digest" ]]; then
    verified=1
    break
  fi
  sleep 2
done
if [[ "$verified" -ne 1 ]]; then
  echo "error: GitHub Packages did not expose the exact latest alias" >&2
  exit 1
fi

gh api "repos/${GITHUB_REPOSITORY}/releases/tags/v${version}" > "$release_json"
release_id=$(jq -er \
  --arg tag "v${version}" \
  'select(.tag_name == $tag and .draft == false and .prerelease == false) | .id' \
  "$release_json")
gh release edit "v${version}" --latest
wait_for_github_latest_release "$release_id"

echo "latest OCI alias verified: $image:latest@$expected_digest"
echo "GitHub Latest verified: v$version (release $release_id)"
