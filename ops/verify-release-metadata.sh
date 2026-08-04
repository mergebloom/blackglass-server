#!/bin/sh
set -eu

script_dir=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")" && pwd
)
default_project_root=$(
    unset CDPATH
    cd -- "$script_dir/.." && pwd
)

if test "$#" -gt 1; then
    echo "usage: $0 [project-root]" >&2
    exit 2
fi
project_root=${1:-"$default_project_root"}

# shellcheck source=ops/release-version.sh
. "$script_dir/release-version.sh"

command -v jq >/dev/null 2>&1 || {
    echo "jq is required to validate release metadata" >&2
    exit 1
}

package_json_version=$(jq -er '
    if type == "object" and
       .name == "blackglass-server" and
       (.version | type) == "string"
    then .version
    else error("invalid root package.json release metadata")
    end
' "$project_root/package.json")

package_lock_version=$(jq -er '
    if type == "object" and
       .name == "blackglass-server" and
       (.version | type) == "string" and
       .lockfileVersion == 3 and
       (.packages | type) == "object" and
       (.packages[""] | type) == "object" and
       .packages[""].name == "blackglass-server" and
       (.packages[""].version | type) == "string" and
       .version == .packages[""].version
    then .version
    else error("invalid root package-lock.json release metadata")
    end
' "$project_root/package-lock.json")

cargo_toml_version=$(awk '
    $0 == "[package]" {
        if (seen_package) exit 2
        seen_package = 1
        in_package = 1
        next
    }
    in_package && /^\[/ { in_package = 0 }
    in_package && /^version = "[^"]+"$/ {
        if (version != "") exit 2
        version = $0
        sub(/^version = "/, "", version)
        sub(/"$/, "", version)
    }
    END {
        if (!seen_package || version == "") exit 2
        print version
    }
' "$project_root/apps/server-rust/Cargo.toml") || {
    echo "could not determine one package version from apps/server-rust/Cargo.toml" >&2
    exit 1
}

cargo_lock_version=$(awk '
    function finish_package() {
        if (package_name == "blackglass-server") {
            matches++
            matched_version = package_version
        }
        package_name = ""
        package_version = ""
    }
    $0 == "[[package]]" {
        finish_package()
        in_package = 1
        next
    }
    in_package && /^name = "[^"]+"$/ {
        package_name = $0
        sub(/^name = "/, "", package_name)
        sub(/"$/, "", package_name)
        next
    }
    in_package && /^version = "[^"]+"$/ {
        package_version = $0
        sub(/^version = "/, "", package_version)
        sub(/"$/, "", package_version)
        next
    }
    END {
        finish_package()
        if (matches != 1 || matched_version == "") exit 2
        print matched_version
    }
' "$project_root/apps/server-rust/Cargo.lock") || {
    echo "could not determine one blackglass-server version from apps/server-rust/Cargo.lock" >&2
    exit 1
}

blackglass_is_supported_release_version "$package_json_version" || {
    echo "package.json contains an unsupported release version: $package_json_version" >&2
    exit 1
}

for candidate in \
    "$package_lock_version" \
    "$cargo_toml_version" \
    "$cargo_lock_version"; do
    if test "$candidate" != "$package_json_version"; then
        echo "release versions do not match: package.json=$package_json_version package-lock.json=$package_lock_version Cargo.toml=$cargo_toml_version Cargo.lock=$cargo_lock_version" >&2
        exit 1
    fi
done

schema_version=$(awk '
    /^const CURRENT_SCHEMA_VERSION: i64 = [0-9]+;$/ {
        matches++
        value = $0
        sub(/^const CURRENT_SCHEMA_VERSION: i64 = /, "", value)
        sub(/;$/, "", value)
    }
    END { if (matches != 1) exit 2; print value }
' "$project_root/apps/server-rust/src/db.rs") || {
    echo "could not determine the database schema version" >&2
    exit 1
}

release_contract="$project_root/ops/release/release-contract.json"
jq -e \
    --arg version "$package_json_version" \
    --argjson schema "$schema_version" '
      type == "object" and
      (keys | sort) == ([
        "clientToolingRevision",
        "database",
        "monitoring",
        "rollback",
        "qualifiedRenderers",
        "schemaVersion",
        "serverVersion",
        "sharingEnabled"
      ] | sort) and
      .schemaVersion == 3 and
      .serverVersion == $version and
      .database.destinationSchema == $schema and
      .database.supportedSourceSchemas == [4, 5] and
      .rollback == {
        "previousPublishedTag": "v0.5.0",
        "previousPublishedSchema": 6,
        "directRollbackTag": "v0.5.0",
        "directRollbackSupported": true
      } and
      (.clientToolingRevision | test("^[a-f0-9]{40}$")) and
      (.qualifiedRenderers | map(.version)) == ["1.12.7", "1.13.4"] and
      all(.qualifiedRenderers[]; .baselineSha256 | test("^[a-f0-9]{64}$")) and
      .monitoring.prometheusJobSelector == "job=\"blackglass-server\"" and
      .monitoring.requiredBackends == ["primary", "recovery"] and
      .sharingEnabled == true
    ' "$release_contract" >/dev/null || {
    echo "release contract does not match the package and schema boundary" >&2
    exit 1
}

echo "release metadata verified: blackglass-server $package_json_version"
