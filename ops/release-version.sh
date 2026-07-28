#!/bin/sh

# This file is sourced by release scripts written for both POSIX sh and Bash.
# Keep the validator side-effect free so sourcing it cannot alter caller state.
blackglass_is_supported_release_version() (
    test "$#" -eq 1 || return 1
    candidate=$1
    LC_ALL=C
    export LC_ALL

    # Reject every character outside the supported alphabet before invoking
    # line-oriented grep, including whitespace and embedded newlines.
    case "$candidate" in
        ''|*[!0-9A-Za-z.-]*) return 1 ;;
    esac

    # Blackglass release versions are SemVer without build metadata. The first
    # expression enforces canonical core numbers and nonempty prerelease IDs.
    printf '%s\n' "$candidate" | grep -Eq \
        '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$' \
        || return 1

    case "$candidate" in
        *-*) prerelease=${candidate#*-} ;;
        *) return 0 ;;
    esac

    # SemVer additionally forbids leading zeroes in numeric prerelease IDs.
    while :; do
        case "$prerelease" in
            *.*)
                identifier=${prerelease%%.*}
                prerelease=${prerelease#*.}
                ;;
            *)
                identifier=$prerelease
                prerelease=
                ;;
        esac
        case "$identifier" in
            *[!0-9]*) ;;
            0|[1-9]|[1-9][0-9]*) ;;
            *) return 1 ;;
        esac
        test -n "$prerelease" || break
    done
)

blackglass_is_supported_release_tag() (
    test "$#" -eq 1 || return 1
    case "$1" in
        v*) blackglass_is_supported_release_version "${1#v}" ;;
        *) return 1 ;;
    esac
)

blackglass_is_full_source_revision() (
    test "$#" -eq 1 || return 1
    test "${#1}" -eq 40 || return 1
    case "$1" in
        *[!0-9a-f]*) return 1 ;;
        *) return 0 ;;
    esac
)
