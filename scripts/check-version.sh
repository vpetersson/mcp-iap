#!/usr/bin/env bash
# Enforce the CalVer scheme described in README.md § Versioning.
#
# CalVer is a convention until something rejects a version that is not one.
# This runs in CI on every push and pull request, and additionally proves that
# a `v…` tag and Cargo.toml agree — the mismatch that otherwise ships a binary
# reporting a version nobody can find in the history.
set -euo pipefail

cd "$(dirname "$0")/.."

# The version key of the [package] table specifically: dependency versions live
# in inline tables and never start a line, but be exact rather than lucky.
package_version=$(
    awk '
        /^\[package\]/ { in_package = 1; next }
        /^\[/          { in_package = 0 }
        in_package && /^version[[:space:]]*=/ { gsub(/"/, ""); print $3; exit }
    ' Cargo.toml
)

if [ -z "$package_version" ]; then
    echo "check-version: no version in the [package] table of Cargo.toml" >&2
    exit 1
fi

if ! [[ $package_version =~ ^([0-9]{4})\.([0-9]{1,2})\.([0-9]+)$ ]]; then
    echo "check-version: \`$package_version\` is not CalVer — expected YYYY.MM.PATCH, e.g. 2026.9.0" >&2
    exit 1
fi
year=${BASH_REMATCH[1]}
month=${BASH_REMATCH[2]}
patch=${BASH_REMATCH[3]}

# Cargo requires a semver-shaped version and semver forbids leading zeros, so
# September is `9`. Catching `2026.09.0` here is friendlier than catching it as
# a manifest parse error.
if [ "$month" != "$((10#$month))" ] || [ "$patch" != "$((10#$patch))" ]; then
    echo "check-version: \`$package_version\` has a zero-padded field — semver forbids leading zeros, use ${year}.$((10#$month)).$((10#$patch))" >&2
    exit 1
fi

if [ "$month" -lt 1 ] || [ "$month" -gt 12 ]; then
    echo "check-version: \`$package_version\` has month $month" >&2
    exit 1
fi

# A version dated in a future year is a typo. CalVer dates the cut, so a
# release made on 31 December is that December's, never January's.
this_year=$(date -u +%Y)
if [ "$year" -lt 2026 ] || [ "$year" -gt "$this_year" ]; then
    echo "check-version: \`$package_version\` is dated $year, and it is $this_year" >&2
    exit 1
fi

# `--locked` elsewhere in CI already fails on a stale lock, but with a message
# about the whole manifest rather than about the one line that moved.
lock_version=$(
    awk '/^name = "mcp-iap"$/ { getline; gsub(/"/, ""); print $3; exit }' Cargo.lock
)
if [ "$lock_version" != "$package_version" ]; then
    echo "check-version: Cargo.lock says \`$lock_version\`, Cargo.toml says \`$package_version\` — run \`cargo check\` and commit the lock" >&2
    exit 1
fi

# On a tag, the tag is the claim everyone downstream reads.
ref=${GITHUB_REF:-}
if [ "${ref#refs/tags/}" != "$ref" ]; then
    tag=${ref#refs/tags/}
    if [ "${tag#v}" != "$package_version" ]; then
        echo "check-version: tag \`$tag\` does not match Cargo.toml's \`$package_version\`" >&2
        exit 1
    fi
    echo "check-version: $package_version, tagged $tag."
    exit 0
fi

echo "check-version: $package_version."
