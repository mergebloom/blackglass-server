#!/bin/sh
# Run from the CI checkout root. Preserve every original commit and ref; only
# generate a test-only integration commit, never fetch the platform merge ref.
set -eu
export LC_ALL=C

fail() {
    printf '%s\n' "$1" >&2
    exit 1
}

is_revision() {
    case "$1" in
        ''|*[!0-9a-f]*) return 1 ;;
    esac
    test "${#1}" -eq 40
}

event_name=${CI_EVENT_NAME:-}
head_sha=${CI_HEAD_SHA:-}
base_sha=${CI_BASE_SHA:-}
case "$event_name" in
    push|pull_request) ;;
    *) fail "CI_EVENT_NAME must be push or pull_request" ;;
esac
is_revision "$head_sha" || fail "CI_HEAD_SHA must be a full lowercase Git commit"
if test "$event_name" = pull_request; then
    is_revision "$base_sha" || fail "CI_BASE_SHA must be a full lowercase Git commit"
fi

actual_head=$(git rev-parse --verify HEAD) || fail "a Git checkout is required"
test "$actual_head" = "$head_sha" || fail "checkout HEAD does not match CI_HEAD_SHA"
test "$(git rev-parse --is-shallow-repository)" = false \
    || fail "full Git history is required (checkout fetch-depth: 0)"
worktree_status=$(git status --porcelain --untracked-files=all) \
    || fail "could not inspect the checkout"
test -z "$worktree_status" || fail "a clean checkout is required"

if test "$event_name" = pull_request; then
    # fetch-depth: 0 provides all branch/tag history. The event's immutable base
    # may no longer be a branch tip, so fetch that exact object if absent. Never
    # substitute a moving branch name, trim history, or remove existing refs.
    if ! git cat-file -e "$base_sha" 2>/dev/null; then
        git fetch --no-tags origin "$base_sha" \
            || fail "could not fetch exact CI_BASE_SHA"
    fi
    test "$(git cat-file -t "$base_sha")" = commit \
        || fail "CI_BASE_SHA must identify a commit object"
    test "$(git rev-parse --is-shallow-repository)" = false \
        || fail "full Git history is required after fetching CI_BASE_SHA"

    if ! git merge-base --is-ancestor "$base_sha" "$head_sha"; then
        # Scope identity to this generated commit, overriding ambient author and
        # committer variables without rewriting or sanitizing original history.
        # --no-ff retains PR head as first parent even if base has advanced past it.
        if ! GIT_AUTHOR_NAME='Blackglass CI' \
            GIT_AUTHOR_EMAIL='blackglass-ci@users.noreply.github.com' \
            GIT_COMMITTER_NAME='Blackglass CI' \
            GIT_COMMITTER_EMAIL='blackglass-ci@users.noreply.github.com' \
            git -c core.hooksPath=/dev/null merge \
                --no-ff --no-edit --no-gpg-sign \
                -m 'CI integration merge (test only)' "$base_sha"; then
            git merge --abort >/dev/null 2>&1 || true
            fail "CI integration merge failed; refusing to test PR head alone"
        fi
    fi
    if ! git merge-base --is-ancestor "$head_sha" HEAD \
        || ! git merge-base --is-ancestor "$base_sha" HEAD; then
        fail "prepared source does not contain both PR head and base"
    fi
fi

printf 'CI source prepared: %s\n' "$(git rev-parse --verify HEAD)"
