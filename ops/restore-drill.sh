#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: restore-drill.sh /path/to/backup.sqlite" >&2
    exit 2
fi

server_binary=${SELFHOST_SERVER_BINARY:-/opt/blackglass-server/blackglass-server}
drill_directory=$(mktemp -d "${TMPDIR:-/tmp}/blackglass-server-restore.XXXXXX")
trap 'rm -rf "$drill_directory"' EXIT HUP INT TERM
restored="$drill_directory/restored.sqlite"

"$server_binary" verify "$1"
"$server_binary" restore "$1" "$restored"
"$server_binary" verify "$restored"
printf 'restore drill passed: %s\n' "$1"
