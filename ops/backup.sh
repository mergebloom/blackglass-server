#!/bin/sh
set -eu

server_binary=${SELFHOST_SERVER_BINARY:-/opt/blackglass-server/blackglass-server}
database=${SELFHOST_DATABASE:-/var/lib/blackglass-server/server.sqlite}
backup_directory=${SELFHOST_BACKUP_DIRECTORY:-/var/backups/blackglass-server}
timestamp=$(date -u +%Y%m%dT%H%M%SZ)

umask 077
mkdir -p "$backup_directory"
output="$backup_directory/server-$timestamp.sqlite"
"$server_binary" backup "$database" "$output"
"$server_binary" verify "$output"
printf '%s\n' "$output"
