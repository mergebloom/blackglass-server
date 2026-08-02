#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <tag> <title> <asset> [<asset> ...]" >&2
  exit 2
fi

tag=$1
title=$2
shift 2
assets=("$@")

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=ops/release-version.sh
. "$script_dir/release-version.sh"

blackglass_is_supported_release_tag "$tag" || {
  echo "error: release tag is not a supported semantic version: $tag" >&2
  exit 1
}
release_prerelease=false
if [[ "$tag" == *-* ]]; then
  release_prerelease=true
fi

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

tag_commit=$(git rev-parse --verify "${tag}^{commit}")
if [[ "$tag_commit" != "$GITHUB_SHA" ]]; then
  echo "error: ${tag} resolves to ${tag_commit}, not workflow commit ${GITHUB_SHA}" >&2
  exit 1
fi

for asset in "${assets[@]}"; do
  [[ -f "$asset" ]] || {
    echo "error: release asset is missing: $asset" >&2
    exit 1
  }
done

release_json=$(mktemp)
release_pages=$(mktemp)
release_matches=$(mktemp)
assets_json=$(mktemp)
expected_names=$(mktemp)
actual_names=$(mktemp)
trap 'rm -f "$release_json" "$release_pages" "$release_matches" "$assets_json" "$expected_names" "$actual_names"' EXIT

printf '%s\n' "${assets[@]##*/}" | LC_ALL=C sort > "$expected_names"
if [[ "$(wc -l < "$expected_names" | tr -d ' ')" -ne "${#assets[@]}" ]] ||
  [[ -n "$(uniq -d "$expected_names")" ]]; then
  echo "error: release asset basenames must be unique" >&2
  exit 1
fi
if ! awk '/^[A-Za-z0-9._-]+$/ { next } { exit 1 }' "$expected_names"; then
  echo "error: release asset basenames contain unsupported characters" >&2
  exit 1
fi

find_release() {
  local release_count
  if ! gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" --slurp \
    > "$release_pages"; then
    echo "error: unable to list repository releases while locating ${tag}" >&2
    return 2
  fi
  if ! jq -e 'type == "array" and all(.[]; type == "array")' \
    "$release_pages" >/dev/null; then
    echo "error: repository release list has an unexpected shape" >&2
    return 2
  fi
  jq --arg tag "$tag" 'add | map(select(.tag_name == $tag))' \
    "$release_pages" > "$release_matches"
  release_count=$(jq -er 'length' "$release_matches")
  if [[ "$release_count" -eq 0 ]]; then
    return 1
  fi
  if [[ "$release_count" -ne 1 ]]; then
    echo "error: repository contains multiple releases for ${tag}" >&2
    return 2
  fi
  jq '.[0]' "$release_matches" > "$release_json"
}

created_release=false
if find_release; then
  :
else
  find_result=$?
  if [[ "$find_result" -ne 1 ]]; then
    exit "$find_result"
  fi
  create_flags=(--draft --verify-tag --title "$title" --generate-notes --latest=false)
  if [[ "$release_prerelease" == "true" ]]; then
    create_flags+=(--prerelease)
  fi
  gh release create "$tag" "${create_flags[@]}"
  created_release=true
fi

refresh_release() {
  local find_result
  if find_release; then
    :
  else
    find_result=$?
    if [[ "$find_result" -eq 1 ]]; then
      echo "error: release ${tag} is not visible in the repository release list" >&2
    fi
    return "$find_result"
  fi
  jq -e \
    --arg tag "$tag" \
    --arg title "$title" \
    --argjson prerelease "$release_prerelease" \
    '(.tag_name == $tag) and (.name == $title) and (.prerelease == $prerelease) and (.draft | type == "boolean")' \
    "$release_json" >/dev/null
  release_id=$(jq -er '.id' "$release_json")
  published=$(jq -r '.draft == false' "$release_json")
}

wait_for_release_state() {
  local expected_published=$1
  local description=$2
  for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    if refresh_release >/dev/null 2>&1 \
      && [[ "$published" == "$expected_published" ]]; then
      return 0
    fi
    sleep 2
  done
  echo "error: release ${tag} did not become ${description}" >&2
  refresh_release || true
  return 1
}

require_draft() {
  refresh_release
  if [[ "$published" == "true" ]]; then
    echo "error: release ${tag} was published while assets were being assembled" >&2
    exit 1
  fi
}

refresh_assets() {
  gh api --paginate "repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets?per_page=100" \
    --slurp | jq 'add' > "$assets_json"
}

verify_asset() {
  local asset=$1
  local name digest size count
  name=$(basename "$asset")
  digest="sha256:$(sha256sum "$asset" | awk '{print $1}')"
  size=$(stat --format='%s' "$asset")
  count=$(jq --arg name "$name" '[.[] | select(.name == $name)] | length' "$assets_json")
  [[ "$count" -le 1 ]] || {
    echo "error: duplicate release assets named ${name}" >&2
    exit 1
  }
  jq -e \
    --arg name "$name" \
    --arg digest "$digest" \
    --argjson size "$size" \
    '.[] | select(.name == $name and .state == "uploaded" and .digest == $digest and .size == $size)' \
    "$assets_json" >/dev/null
}

wait_for_asset() {
  local asset=$1
  for _attempt in 1 2 3 4 5 6 7 8 9 10; do
    refresh_assets
    if verify_asset "$asset"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

if [[ "$created_release" == "true" ]]; then
  wait_for_release_state false "a visible matching draft"
else
  refresh_release
fi
refresh_assets
actual_existing=$(jq -r '.[].name' "$assets_json" | LC_ALL=C sort)
unexpected_existing=$(comm -23 <(printf '%s\n' "$actual_existing") "$expected_names")
if [[ -n "$unexpected_existing" ]]; then
  echo "error: release contains unexpected existing assets" >&2
  printf '%s\n' "$unexpected_existing" >&2
  exit 1
fi

for asset in "${assets[@]}"; do
  name=$(basename "$asset")
  count=$(jq --arg name "$name" '[.[] | select(.name == $name)] | length' "$assets_json")
  if [[ "$count" -eq 1 ]] && wait_for_asset "$asset"; then
    echo "release asset already verified: $name"
    continue
  fi
  refresh_assets
  count=$(jq --arg name "$name" '[.[] | select(.name == $name)] | length' "$assets_json")
  if [[ "$published" == "true" ]]; then
    echo "error: published release has a missing or mismatched asset: $name" >&2
    exit 1
  fi
  if [[ "$count" -eq 1 ]]; then
    state=$(jq -r --arg name "$name" '.[] | select(.name == $name) | .state' "$assets_json")
    size=$(jq -r --arg name "$name" '.[] | select(.name == $name) | .size' "$assets_json")
    asset_id=$(jq -r --arg name "$name" '.[] | select(.name == $name) | .id' "$assets_json")
    if [[ "$state" == "starter" && "$size" == "0" ]]; then
      require_draft
      gh api --method DELETE "repos/${GITHUB_REPOSITORY}/releases/assets/${asset_id}"
      refresh_assets
    else
      echo "error: draft release has a mismatched asset: $name" >&2
      exit 1
    fi
  fi
  require_draft
  gh release upload "$tag" "$asset"
  if ! wait_for_asset "$asset"; then
    echo "error: uploaded release asset did not become verifiably available: $name" >&2
    exit 1
  fi
done

jq -r '.[].name' "$assets_json" | LC_ALL=C sort > "$actual_names"
if ! cmp -s "$expected_names" "$actual_names"; then
  echo "error: draft release contains unexpected or missing assets" >&2
  diff -u "$expected_names" "$actual_names" >&2 || true
  exit 1
fi

if [[ "$published" == "false" ]]; then
  require_draft
  edit_flags=(--draft=false --verify-tag --title "$title" --latest=false)
  if [[ "$release_prerelease" == "true" ]]; then
    edit_flags+=(--prerelease)
  fi
  gh release edit "$tag" "${edit_flags[@]}"
fi

wait_for_release_state true "a visible matching published release"
refresh_assets
jq -r '.[].name' "$assets_json" | LC_ALL=C sort > "$actual_names"
if ! cmp -s "$expected_names" "$actual_names"; then
  echo "error: published release contains unexpected or missing assets" >&2
  diff -u "$expected_names" "$actual_names" >&2 || true
  exit 1
fi
for asset in "${assets[@]}"; do
  verify_asset "$asset"
done
