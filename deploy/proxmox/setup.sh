#!/bin/sh
# Runs INSIDE a new container: lib.sh pushes this script, the zinkhole binary,
# zinkhole-deploy.tar.gz and a setup.env file here (all verified on the Proxmox
# node), then runs it. See docs/adr/0003. It
#
#   * upgrades the OS packages and installs curl and the CA certificates,
#   * installs zinkhole as a service (deploy/install.sh),
#   * writes /etc/zinkhole/config.yaml for the chosen role,
#   * starts the service and waits until it answers,
#   * installs the `update` command.
#
# setup.env (shell syntax) holds ZINKHOLE_ROLE (standalone, origin or replica),
# ZINKHOLE_IPV6 (on or off: whether zinkhole listens on IPv6), ZINKHOLE_SERVE
# and ZINKHOLE_SECRET (origin), ZINKHOLE_ORIGIN and ZINKHOLE_SECRET (replica),
# and optionally ZINKHOLE_BASE_URL (a download location for `update` other than
# the project's latest release).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck disable=SC1091
. "$here/setup.env"
rm -f "$here/setup.env" # holds the secret
: "${ZINKHOLE_ROLE:?}"
ZINKHOLE_IPV6=${ZINKHOLE_IPV6:-off}

say() { echo "==> $*"; }
die() {
	echo "error: $*" >&2
	exit 1
}

install_packages() {
	if command -v apt-get >/dev/null 2>&1; then
		export DEBIAN_FRONTEND=noninteractive
		apt-get update -qq >/dev/null
		apt-get -y -qq -o Dpkg::Options::=--force-confold full-upgrade >/dev/null
		apt-get -y -qq install curl ca-certificates >/dev/null
	elif command -v apk >/dev/null 2>&1; then
		apk update -q >/dev/null
		apk upgrade -q >/dev/null
		apk add -q curl ca-certificates >/dev/null
	else
		die "neither apt-get nor apk found"
	fi
}

# The container's global IPv6 networks, such as 2001:db8:1:2::/64, one per line.
# (From the routes, which show the prefix however the address was configured.)
ipv6_networks() {
	ip -6 -o route show 2>/dev/null |
		awk '$1 ~ /\// && $1 !~ /^(fe80|ff)/ && $1 != "default" {print $1}' | sort -u
}

# IPv6 addresses can arrive a few seconds after the container starts.
wait_for_ipv6_network() {
	n=0
	while [ "$n" -lt 20 ]; do
		[ -n "$(ipv6_networks)" ] && return 0
		n=$((n + 1))
		sleep 1
	done
	return 1
}

# The server section. zinkhole answers only clients in server.allow_clients,
# whose default covers private addresses but not a global IPv6 prefix: with
# IPv6 on, this container's own IPv6 networks are added to that default list.
write_server_section() {
	echo
	echo "server:"
	echo "  listen:"
	echo "    - 0.0.0.0:53"
	[ "$ZINKHOLE_IPV6" = on ] || return 0
	echo '    - "[::]:53"'
	networks=$(ipv6_networks)
	if [ -z "$networks" ]; then
		echo "warning: no global IPv6 network found; add yours to server.allow_clients" >&2
		return 0
	fi
	# The defaults come from the example config shipped in the same release.
	defaults=$(awk '/^  allow_clients:/ {f = 1; next} f && /^    - / {print; next} f {exit}' "$here/pkg/config.example.yaml")
	if [ -z "$defaults" ]; then
		echo "warning: cannot read the default allow_clients; add your IPv6 network to server.allow_clients" >&2
		return 0
	fi
	echo "  allow_clients:"
	echo "$defaults"
	for network in $networks; do
		echo "    - $network"
	done
}

write_config() {
	tmp=$(mktemp)
	{
		cat <<'YAML'
# zinkhole configuration, written by the Proxmox installer. Every setting is
# documented in config.example.yaml of the zinkhole repository:
#   https://gitlab.com/kyura4k/zinkhole
upstream:
  servers:
    - tls://9.9.9.9#dns.quad9.net
    - tls://149.112.112.112#dns.quad9.net
YAML
		write_server_section
		if [ "$ZINKHOLE_ROLE" = replica ]; then
			printf '\n# blocking and local come from the origin (see sync below).\n'
		else
			cat <<'YAML'

blocking:
  lists:
    - https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts

local:
  records:
    # Names for your own devices, e.g.
    #   nas.lan: 192.168.1.10
YAML
		fi
		case "$ZINKHOLE_ROLE" in
		origin)
			printf '\nsync:\n  serve: ["%s:5380"]\n  secret: "%s"\n' "${ZINKHOLE_SERVE:?}" "${ZINKHOLE_SECRET:?}"
			;;
		replica)
			printf '\nsync:\n  origin: %s\n  secret: "%s"\n' "${ZINKHOLE_ORIGIN:?}" "${ZINKHOLE_SECRET:?}"
			;;
		esac
	} >"$tmp"
	install -d -m 755 /etc/zinkhole
	install -m 644 "$tmp" /etc/zinkhole/config.yaml
	rm -f "$tmp"
}

restart_service() {
	if [ -d /run/systemd/system ]; then
		systemctl restart zinkhole
	else
		rc-service zinkhole restart
	fi
}

wait_healthy() {
	n=0
	while [ "$n" -lt 15 ]; do
		/usr/local/bin/zinkhole --healthcheck 127.0.0.1:53 >/dev/null 2>&1 && return 0
		n=$((n + 1))
		sleep 1
	done
	return 1
}

install_update_command() {
	if [ -n "${ZINKHOLE_BASE_URL:-}" ]; then
		printf 'ZINKHOLE_BASE_URL=%s\n' "$ZINKHOLE_BASE_URL" >/etc/zinkhole/update.env
	fi
	install -m 755 /dev/stdin /usr/local/bin/update <<'STUB'
#!/bin/sh
# Updates this container's OS packages and zinkhole. It fetches the updater of
# the latest zinkhole release, checks it against that release's SHA256SUMS, and
# runs it (see docs/adr/0003).
set -eu
[ -r /etc/zinkhole/update.env ] && . /etc/zinkhole/update.env
base=${ZINKHOLE_BASE_URL:-https://gitlab.com/kyura4k/zinkhole/-/releases/permalink/latest/downloads}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
curl -fsSL -o "$tmp/update.sh" "$base/update.sh"
(cd "$tmp" && grep ' update.sh$' SHA256SUMS | sha256sum -c - >/dev/null) || {
	echo "error: update.sh does not match SHA256SUMS; not running it" >&2
	exit 1
}
ZINKHOLE_BASE_URL=$base sh "$tmp/update.sh" "$@"
STUB
}

say "Upgrading the OS packages"
install_packages
if [ "$ZINKHOLE_IPV6" = on ]; then
	say "Waiting for an IPv6 network"
	wait_for_ipv6_network || true
fi
say "Installing zinkhole"
mkdir -p "$here/pkg"
tar -xzf "$here/zinkhole-deploy.tar.gz" -C "$here/pkg"
sh "$here/pkg/deploy/install.sh" --binary "$here/zinkhole" >/dev/null
write_config
/usr/local/bin/zinkhole --check -c /etc/zinkhole/config.yaml >/dev/null || die "the generated configuration is invalid"
say "Starting zinkhole"
restart_service
if ! wait_healthy; then
	echo "error: zinkhole did not answer within 15 seconds" >&2
	if [ -d /run/systemd/system ]; then journalctl -u zinkhole -n 20 --no-pager >&2 || true; fi
	exit 1
fi
install_update_command
say "zinkhole $(/usr/local/bin/zinkhole --version | cut -d' ' -f2) is running"
