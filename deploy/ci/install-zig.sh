#!/bin/sh
# Installs the pinned Zig compiler into /opt/zig (symlinked as /usr/local/bin/zig),
# verifying the official tarball's SHA-256. Used by the GitLab CI jobs; also
# runs in any Alpine container:  sh deploy/ci/install-zig.sh
#
# Keep the version and checksums in step with the Dockerfile.
set -eu

ZIG_VERSION=0.17.0
SHA256_X86_64=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026
SHA256_AARCH64=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8

case "$(uname -m)" in
x86_64) arch=x86_64 sha256=$SHA256_X86_64 ;;
aarch64 | arm64) arch=aarch64 sha256=$SHA256_AARCH64 ;;
*) echo "error: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

if command -v apk >/dev/null 2>&1; then
	apk add --no-cache xz curl >/dev/null
fi

tarball="zig-$arch-linux-$ZIG_VERSION.tar.xz"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/$tarball" "https://ziglang.org/download/$ZIG_VERSION/$tarball"
echo "$sha256  $work/$tarball" | sha256sum -c - >/dev/null
mkdir -p /opt/zig
tar -xJf "$work/$tarball" -C /opt/zig --strip-components=1
ln -sf /opt/zig/zig /usr/local/bin/zig
echo "installed zig $(zig version)"
