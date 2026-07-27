#!/bin/sh
set -eu

project_root=$(
    unset CDPATH
    cd -- "$(dirname -- "$0")/.." && pwd
)

"$project_root/ops/build-linux-release.sh" linux-amd64
"$project_root/ops/build-linux-release.sh" linux-arm64
