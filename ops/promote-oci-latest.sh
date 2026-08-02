#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <version> <image> <expected-digest>" >&2
  exit 2
fi

version=$1
image=$2
expected_digest=$3

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=ops/release-version.sh
. "$script_dir/release-version.sh"

blackglass_is_supported_release_version "$version" || {
  echo "error: invalid image version: $version" >&2
  exit 1
}

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

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

release_list_json=$(mktemp)
manifest_json="${release_list_json}.manifest"
release_json="${release_list_json}.release"
latest_release_json="${release_list_json}.latest-release"
trap 'rm -f "$release_list_json" "$manifest_json" "$release_json" "$latest_release_json"' EXIT

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

if ! wait_for_registry_digest "$image:$version" "$expected_digest"; then
  echo "error: refusing latest promotion without the exact verified version tag" >&2
  exit 1
fi

# Stable ordering belongs to this repository's releases, while exact image
# identity belongs to GHCR. Avoid owner-wide Packages endpoints: the release
# job's repository-scoped token is intentionally narrower than that API.
gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" --slurp \
  | jq 'add' > "$release_list_json"
jq -e 'type == "array"' "$release_list_json" >/dev/null
highest_stable=$(jq -r '
  [
    .[]
    | select(.draft == false and .prerelease == false)
    | .tag_name
    | select(test("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"))
    | ltrimstr("v")
  ]
  | unique[]
' "$release_list_json" | sort -V | tail -n 1)
[[ -n "$highest_stable" ]] || {
  echo "error: no stable GitHub release is available for latest promotion" >&2
  exit 1
}
if [[ "$highest_stable" != "$version" ]]; then
  docker buildx imagetools inspect "$image:$highest_stable" \
    --format '{{json .Manifest}}' > "$manifest_json"
  highest_digest=$(jq -er '.digest' "$manifest_json")
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

if docker buildx imagetools inspect "$image:latest" \
  --format '{{json .Manifest}}' > "$manifest_json" 2>/dev/null &&
  [[ "$(jq -er '.digest' "$manifest_json")" == "$expected_digest" ]]; then
  echo "latest already has the expected registry digest"
else
  docker buildx imagetools create --tag "$image:latest" "$image@$expected_digest"
fi

wait_for_registry_digest "$image:latest" "$expected_digest"

gh api "repos/${GITHUB_REPOSITORY}/releases/tags/v${version}" > "$release_json"
release_id=$(jq -er \
  --arg tag "v${version}" \
  'select(.tag_name == $tag and .draft == false and .prerelease == false) | .id' \
  "$release_json")
gh release edit "v${version}" --latest
wait_for_github_latest_release "$release_id"

echo "latest OCI alias verified: $image:latest@$expected_digest"
echo "GitHub Latest verified: v$version (release $release_id)"
