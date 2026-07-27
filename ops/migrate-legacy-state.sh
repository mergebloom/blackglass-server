#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: migrate-legacy-state.sh <legacy-database> <new-database>" >&2
    exit 2
fi

server_binary=${SELFHOST_SERVER_BINARY:-/opt/blackglass-server/blackglass-server}
legacy_database=$1
new_database=$2

if [ ! -f "$legacy_database" ]; then
    echo "legacy database does not exist: $legacy_database" >&2
    exit 1
fi
if [ -e "$new_database" ]; then
    echo "refusing to overwrite destination: $new_database" >&2
    exit 1
fi
if [ "$legacy_database" = "$new_database" ]; then
    echo "legacy and destination databases must differ" >&2
    exit 1
fi

umask 077
mkdir -p "$(dirname -- "$new_database")"
"$server_binary" verify "$legacy_database"
"$server_binary" restore "$legacy_database" "$new_database"
"$server_binary" verify "$new_database"

printf 'legacy state copied and verified: %s -> %s\n' "$legacy_database" "$new_database"
printf '%s\n' 'The legacy database was not changed or removed.'
