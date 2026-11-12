#!/bin/sh
# The zinkhole updater, run inside the container by `update` (which fetches it
# from a release and checks it against SHA256SUMS first): the community-scripts
# `update` (ct/zinkhole.sh, docs/adr/0001), with --skip-os, as it upgrades the
# OS packages itself. In order:
#
#   1. upgrade the OS packages (apt or apk), unless --skip-os,
#   2. download the latest zinkhole release and check it against SHA256SUMS,
#   3. stop here if it is not newer than the installed version,
#   4. check that the new binary accepts the current config (check),
#   5. keep the old binary as zinkhole.old, install the new one and restart,
#   6. if zinkhole does not answer within 15 seconds, restore the old binary
#      (deploy/install.sh does steps 5 and 6).
#
# Installing, restarting and waiting for an answer are deploy/install.sh's
# (from the release's bundle). Downloading is written here and in the
# Proxmox install script: neither has the bundle before it downloads it.
set -eu

skip_os=no
[ "${1:-}" = "--skip-os" ] && skip_os=yes

base=${ZINKHOLE_BASE_URL:-https://github.com/jroosing/zinkhole/releases/latest/download}
config=/etc/zinkhole/config.toml
installed=/usr/local/bin/zinkhole

die() {
	echo "error: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "run this as root"
[ -x "$installed" ] || die "zinkhole is not installed in this container"
case "$(uname -m)" in
x86_64) arch=x86_64 ;;
aarch64 | arm64) arch=aarch64 ;;
*) die "unsupported architecture $(uname -m)" ;;
esac
bin_name=zinkhole-$arch-linux-musl

# A newer origin may send settings that an older replica does not know yet.
if grep -Eq '^role[[:space:]]*=[[:space:]]*"origin"' "$config" 2>/dev/null; then
	echo "note: this node is the sync origin. Update the replicas first, so none of them"
	echo "      is older than the origin (a replica that is too old refuses the origin's settings)."
fi

if [ "$skip_os" = yes ]; then
	:
elif command -v apt-get >/dev/null 2>&1; then
	echo "==> Upgrading the OS packages"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null
	apt-get -y -qq -o Dpkg::Options::=--force-confold full-upgrade >/dev/null
elif command -v apk >/dev/null 2>&1; then
	echo "==> Upgrading the OS packages"
	apk update -q >/dev/null
	apk upgrade -q >/dev/null
else
	die "neither apt-get nor apk found"
fi

echo "==> Checking for a new zinkhole"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
for file in "$bin_name" zinkhole-deploy.tar.gz; do
	curl -fsSL -o "$tmp/$file" "$base/$file"
	(cd "$tmp" && grep " $file\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "$file does not match SHA256SUMS; nothing was changed"
done
chmod 755 "$tmp/$bin_name"
new=$("$tmp/$bin_name" --version | cut -d' ' -f2)
old=$("$installed" --version | cut -d' ' -f2)
# A pipeline's status is cut's: an empty version means the binary did not
# run (a noexec /tmp, a broken download), not that it is older.
[ -n "$new" ] || die "the downloaded zinkhole does not run; nothing was changed"
[ -n "$old" ] || die "the installed zinkhole does not run; reinstall it"

if [ "$new" = "$old" ]; then
	echo "zinkhole $old is up to date"
	exit 0
fi
if [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n 1)" = "$old" ]; then
	echo "the installed zinkhole $old is newer than the latest release $new; not downgrading"
	exit 0
fi

echo "==> Updating zinkhole $old -> $new"
"$tmp/$bin_name" check -c "$config" || die "zinkhole $new rejects the current configuration; nothing was changed"

cp -p "$installed" "$installed.old"
mkdir "$tmp/pkg"
tar -xzf "$tmp/zinkhole-deploy.tar.gz" -C "$tmp/pkg"
# Installs the binary and the service file, restarts the service and waits
# until it answers; if it does not, it puts zinkhole $old back and says so
# (deploy/install.sh).
sh "$tmp/pkg/deploy/install.sh" --binary "$tmp/$bin_name" >/dev/null || exit 1
echo "zinkhole is updated to $new (the previous binary is kept as $installed.old)"
