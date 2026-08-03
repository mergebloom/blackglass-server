#!/bin/sh
set -eu

compose_file=${BLACKGLASS_COMPOSE_FILE:-compose.yaml}
env_file=${BLACKGLASS_ENV_FILE:-.env}

compose() {
    docker compose --env-file "$env_file" -f "$compose_file" "$@"
}

usage() {
    cat >&2 <<'EOF'
usage: ./ops/compose-ops.sh <command> [arguments]

commands:
  config                         validate the deployment configuration
  init <email> <display-name>    create the first account; reads password from stdin
  up                             start Server and Caddy
  health                         require the running Server to be ready
  backup <output.sqlite>         export an online verified SQLite backup
  verify-backup <backup.sqlite>  verify a local backup in an isolated container
  restore-drill <backup.sqlite>  restore and verify into disposable container state
EOF
    exit 2
}

require_regular_backup() {
    backup=$1
    [ -f "$backup" ] || {
        echo "backup is not a regular file: $backup" >&2
        exit 1
    }
    [ ! -L "$backup" ] || {
        echo "backup must not be a symbolic link: $backup" >&2
        exit 1
    }
    backup=$(cd -- "$(dirname -- "$backup")" && pwd -P)/$(basename -- "$backup")
}

command=${1:-}
case "$command" in
    config)
        [ "$#" -eq 1 ] || usage
        compose config --quiet
        ;;
    init)
        [ "$#" -eq 3 ] || usage
        [ ! -t 0 ] || {
            echo "pipe the new account password on standard input; it is never accepted as an argument" >&2
            exit 2
        }
        compose run --rm --no-deps -T server \
            user create /var/lib/blackglass-server/server.sqlite "$2" "$3"
        ;;
    up)
        [ "$#" -eq 1 ] || usage
        compose up -d
        ;;
    health)
        [ "$#" -eq 1 ] || usage
        compose exec -T server healthcheck
        ;;
    backup)
        [ "$#" -eq 2 ] || usage
        output=$2
        [ ! -e "$output" ] && [ ! -L "$output" ] || {
            echo "refusing to overwrite backup output: $output" >&2
            exit 1
        }
        output_parent=$(cd -- "$(dirname -- "$output")" && pwd -P)
        output="$output_parent/$(basename -- "$output")"
        temporary="$output.partial.$$"
        checksum="$output.sha256"
        [ ! -e "$temporary" ] && [ ! -L "$temporary" ] || {
            echo "backup staging path already exists: $temporary" >&2
            exit 1
        }
        [ ! -e "$checksum" ] && [ ! -L "$checksum" ] || {
            echo "refusing to overwrite backup checksum: $checksum" >&2
            exit 1
        }
        umask 077
        trap 'rm -f -- "$temporary"' EXIT HUP INT TERM
        compose exec -T server backup-stdout \
            /var/lib/blackglass-server/server.sqlite > "$temporary"
        [ -s "$temporary" ] || {
            echo "backup stream was empty" >&2
            exit 1
        }
        mv -- "$temporary" "$output"
        trap - EXIT HUP INT TERM
        if command -v sha256sum >/dev/null 2>&1; then
            (cd -- "$output_parent" && sha256sum "$(basename -- "$output")" > "$(basename -- "$checksum")")
        else
            (cd -- "$output_parent" && shasum -a 256 "$(basename -- "$output")" > "$(basename -- "$checksum")")
        fi
        printf '%s\n%s\n' "$output" "$checksum"
        ;;
    verify-backup|restore-drill)
        [ "$#" -eq 2 ] || usage
        require_regular_backup "$2"
        if [ -f "$backup.sha256" ]; then
            if command -v sha256sum >/dev/null 2>&1; then
                (cd -- "$(dirname -- "$backup")" && sha256sum -c "$(basename -- "$backup.sha256")")
            else
                (cd -- "$(dirname -- "$backup")" && shasum -a 256 -c "$(basename -- "$backup.sha256")")
            fi
        fi
        if [ "$command" = verify-backup ]; then
            compose run --rm --no-deps -T --user 0:0 \
                --volume "$backup:/backup.sqlite:ro" server verify /backup.sqlite
        else
            compose run --rm --no-deps -T --user 0:0 \
                --volume "$backup:/backup.sqlite:ro" server \
                restore /backup.sqlite /tmp/restored.sqlite
            compose run --rm --no-deps -T --user 0:0 \
                --volume "$backup:/backup.sqlite:ro" server verify /backup.sqlite
        fi
        ;;
    *) usage ;;
esac
