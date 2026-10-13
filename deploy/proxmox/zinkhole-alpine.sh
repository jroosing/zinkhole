#!/usr/bin/env bash
# Creates a Proxmox LXC container with zinkhole on Alpine. Run on a Proxmox node, as root:
#
#   bash -c "$(curl -fsSL https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads/zinkhole-alpine.sh)"
#
# It asks a few questions (or reads ZINKHOLE_* environment variables: lib.sh lists
# them), then creates and sets up the container. Inside it, `update` upgrades the
# OS packages and zinkhole. See docs/adr/0003 and the README.
set -Eeuo pipefail

# These are read by lib.sh.
# shellcheck disable=SC2034
OS_NAME="Alpine"
# shellcheck disable=SC2034
TEMPLATE_REGEX='^alpine-3\.[0-9]+-default_.*_@ARCH@\.tar\.xz$'
# shellcheck disable=SC2034
NESTING=0
# shellcheck disable=SC2034
SCRIPT_NAME=zinkhole-alpine.sh
# Set to this script's own version when the release is built, so that it fetches
# lib.sh and everything else from the same release. A copy from the repository
# needs ZINKHOLE_BASE_URL (a URL with the release files).
BASE_URL=${ZINKHOLE_BASE_URL:-https://gitlab.com/kyura4k/zinkhole/-/releases/v@VERSION@/downloads}

here=${BASH_SOURCE[0]:-}
if [[ -n $here && -f $(dirname -- "$here")/lib.sh ]]; then
	# Run from a checkout of the repository.
	# shellcheck source=lib.sh source-path=SCRIPTDIR
	source "$(dirname -- "$here")/lib.sh"
else
	[[ $BASE_URL != *@VERSION@* ]] || {
		echo "error: this copy is not a release; set ZINKHOLE_BASE_URL to where the release files are" >&2
		exit 1
	}
	tmp=$(mktemp -d)
	curl -fsSL -o "$tmp/lib.sh" "$BASE_URL/lib.sh"
	curl -fsSL -o "$tmp/SHA256SUMS" "$BASE_URL/SHA256SUMS"
	(cd "$tmp" && grep ' lib.sh$' SHA256SUMS | sha256sum -c - >/dev/null) || {
		echo "error: lib.sh does not match SHA256SUMS" >&2
		exit 1
	}
	# shellcheck source=lib.sh source-path=SCRIPTDIR
	source "$tmp/lib.sh"
	rm -rf "$tmp"
fi
main
