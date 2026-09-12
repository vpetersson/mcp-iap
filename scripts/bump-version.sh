#!/usr/bin/env bash
# Write today's CalVer into Cargo.toml and Cargo.lock.
#
# The scheme is YYYY.MM.PATCH (README.md § Versioning). Deriving the next
# version by hand is where the mistakes are: the patch resets when the month
# rolls over, and the month is not zero-padded. Pass a version explicitly to
# override, for a backport or to correct a bad bump.
set -euo pipefail

cd "$(dirname "$0")/.."

current=$(
    awk '
        /^\[package\]/ { in_package = 1; next }
        /^\[/          { in_package = 0 }
        in_package && /^version[[:space:]]*=/ { gsub(/"/, ""); print $3; exit }
    ' Cargo.toml
)

if [ $# -gt 0 ]; then
    next=$1
else
    year=$(date -u +%Y)
    # `%-m` is a GNU extension that BSD date does not have; strip the pad here
    # so this behaves the same on a maintainer's Mac.
    month=$(date -u +%m)
    month=${month#0}
    # Another release in the same month continues the count; a new month starts
    # over at .0.
    if [[ $current == "$year.$month."* ]]; then
        next="$year.$month.$(( ${current##*.} + 1 ))"
    else
        next="$year.$month.0"
    fi
fi

if [ "$next" = "$current" ]; then
    echo "bump-version: already $current" >&2
    exit 1
fi

backup_toml=$(mktemp) && cp Cargo.toml "$backup_toml"
backup_lock=$(mktemp) && cp Cargo.lock "$backup_lock"
trap 'rm -f "$backup_toml" "$backup_lock"' EXIT

# Only the [package] version, and only the first one, so a dependency pinned to
# the same string is left alone.
awk -v v="$next" '
    /^\[package\]/ { in_package = 1 }
    /^\[/ && !/^\[package\]/ { in_package = 0 }
    in_package && !done && /^version[[:space:]]*=/ {
        print "version = \"" v "\""
        done = 1
        next
    }
    { print }
' Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml

# The lock records the workspace member's own version too, and CI builds with
# `--locked`, so it has to move in the same commit.
awk -v v="$next" '
    /^name = "mcp-iap"$/ && !done {
        print
        getline
        print "version = \"" v "\""
        done = 1
        next
    }
    { print }
' Cargo.lock > Cargo.lock.tmp && mv Cargo.lock.tmp Cargo.lock

# Validation happens after the write because it reads the files, so leave the
# tree as it was found if the result is not a version this project accepts.
if ! scripts/check-version.sh; then
    mv "$backup_toml" Cargo.toml
    mv "$backup_lock" Cargo.lock
    exit 1
fi

cat <<EOF

  git commit -am "chore: release $next"
  git tag v$next
  git push && git push --tags
EOF
