#!/bin/sh
# The zinkhole updater, run by /usr/local/bin/update inside the container (which
# fetches it from the latest release and checks it against SHA256SUMS first).
# See docs/adr/0003. In order:
#
#   1. upgrade the OS packages (apt or apk),
#   2. download the latest zinkhole release and check it against SHA256SUMS,
#   3. stop here if it is not newer than the installed version,
#   4. check that the new binary accepts the current config (--check),
#   5. keep the old binary as zinkhole.old, install the new one and restart,
#   6. if zinkhole does not answer within 15 seconds, restore the old binary.
set -eu

base=${ZINKHOLE_BASE_URL:-https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads}
config=/etc/zinkhole/config.yaml
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
if grep -Eq '^[[:space:]]+serve:' "$config" 2>/dev/null; then
	echo "note: this node is the sync origin. Update the replicas first, so none of them"
	echo "      is older than the origin (a replica that is too old refuses the origin's settings)."
fi

echo "==> Upgrading the OS packages"
if command -v apt-get >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq >/dev/null
	apt-get -y -qq -o Dpkg::Options::=--force-confold full-upgrade >/dev/null
elif command -v apk >/dev/null 2>&1; then
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

if [ "$new" = "$old" ]; then
	echo "zinkhole $old is up to date"
	exit 0
fi
if [ "$(printf '%s\n%s\n' "$old" "$new" | sort -V | tail -n 1)" = "$old" ]; then
	echo "the installed zinkhole $old is newer than the latest release $new; not downgrading"
	exit 0
fi

echo "==> Updating zinkhole $old -> $new"
"$tmp/$bin_name" --check -c "$config" || die "zinkhole $new rejects the current configuration; nothing was changed"

restart_service() {
	if [ -d /run/systemd/system ]; then
		systemctl restart zinkhole
	else
		rc-service zinkhole restart
	fi
}

# Answers on loopback or on one of this container's own addresses (the config
# may listen on a single address).
healthy() {
	n=0
	while [ "$n" -lt 15 ]; do
		for target in 127.0.0.1:53 $(ip -o -4 addr show scope global 2>/dev/null | awk '{sub("/.*", "", $4); print $4 ":53"}'); do
			"$installed" --healthcheck "$target" >/dev/null 2>&1 && return 0
		done
		n=$((n + 1))
		sleep 1
	done
	return 1
}

rollback() {
	echo "error: zinkhole $new did not answer; restoring $old" >&2
	install -m 755 "$installed.old" "$installed"
	restart_service || true
	if healthy; then
		echo "zinkhole $old is running again. The log may say why $new failed." >&2
	else
		echo "error: the restored zinkhole $old does not answer either; check the log" >&2
	fi
	exit 1
}

cp -p "$installed" "$installed.old"
mkdir "$tmp/pkg"
tar -xzf "$tmp/zinkhole-deploy.tar.gz" -C "$tmp/pkg"
# Installs the binary and the service file, and restarts the service.
sh "$tmp/pkg/deploy/install.sh" --binary "$tmp/$bin_name" >/dev/null || rollback
healthy || rollback
echo "zinkhole is updated to $new (the previous binary is kept as $installed.old)"
