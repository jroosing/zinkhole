#!/bin/sh
# Installs zinkhole as a system service, using systemd (Debian, Ubuntu, ...)
# or OpenRC (Alpine). Run as root from the repository or release directory:
#
#   ./deploy/install.sh                  # detect the init system
#   ./deploy/install.sh --init openrc    # or choose one: systemd, openrc
#   ./deploy/install.sh --uninstall      # remove service and binary, keep the config
#
# Options:
#   --binary PATH   the zinkhole binary (default: target/release/zinkhole)
#   --init NAME     systemd or openrc (default: detected)
#   --config FILE   check FILE with the new binary, then install it as
#                   /etc/zinkhole/config.toml, replacing any
#   --start         start the service even with a fresh example config
#
# Running it again upgrades the binary and service file. The config in place
# (kept as it is, unless --config) is checked with the new binary first, and
# nothing changes if it is rejected. The service is then restarted, and the
# installer waits until it answers; if it does not within 15 seconds, the
# previous binary is put back.
# The Proxmox installer and `update` (deploy/proxmox/) install through this
# script, so starting and checking the service is written here only.

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
binary="$root/target/release/zinkhole"
init=""
config_file=""
start_anyway=no
action=install

die() {
	echo "error: $*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--binary)
		[ $# -ge 2 ] || die "--binary needs a path"
		binary=$2
		shift 2
		;;
	--init)
		[ $# -ge 2 ] || die "--init needs systemd or openrc"
		init=$2
		shift 2
		;;
	--config)
		[ $# -ge 2 ] || die "--config needs a file"
		config_file=$2
		shift 2
		;;
	--start)
		start_anyway=yes
		shift
		;;
	--uninstall)
		action=uninstall
		shift
		;;
	-h | --help)
		sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) die "unknown option '$1' (see --help)" ;;
	esac
done

[ "$(id -u)" -eq 0 ] || die "run this as root"

if [ -z "$init" ]; then
	if [ -d /run/systemd/system ]; then
		init=systemd
	elif command -v openrc-run >/dev/null 2>&1; then
		init=openrc
	else
		die "found neither systemd nor OpenRC; choose one with --init"
	fi
fi
case "$init" in
systemd)
	init_name=systemd
	start="systemctl start zinkhole"
	restart="systemctl restart zinkhole"
	logs="journalctl -u zinkhole -f"
	;;
openrc)
	init_name=OpenRC
	start="rc-service zinkhole start"
	restart="rc-service zinkhole restart"
	logs="tail -f /var/log/messages"
	;;
*) die "--init must be systemd or openrc" ;;
esac

# True once zinkhole answers where its config says it listens (the first
# server.listen address, loopback for a wildcard), within 15 seconds.
answers() {
	deadline=$(($(date +%s) + 15))
	while [ "$(date +%s)" -lt "$deadline" ]; do
		/usr/local/bin/zinkhole healthcheck -c /etc/zinkhole/config.toml >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}

restart_and_wait() {
	$restart
	answers || return 1
	echo "zinkhole $(/usr/local/bin/zinkhole --version | cut -d' ' -f2) is running"
}

# The binary that was installed before this run, while it runs.
previous=""

# The new binary did not answer: back to the previous one, if there was one.
roll_back() {
	if [ -z "$previous" ]; then
		die "zinkhole did not answer within 15 seconds; the log may say why ($logs)"
	fi
	echo "error: the new zinkhole did not answer within 15 seconds; putting the previous one back" >&2
	install -m 755 "$previous" /usr/local/bin/zinkhole
	if restart_and_wait >&2; then
		die "the new zinkhole did not start; the previous one is running again (the log may say why: $logs)"
	fi
	die "neither the new nor the previous zinkhole answers; check the log ($logs)"
}

install_zinkhole() {
	[ -x "$binary" ] || die "$binary not found; build it first: cargo build --release"
	# The config the new binary will run with must suit it.
	checked=${config_file:-/etc/zinkhole/config.toml}
	if [ -e "$checked" ]; then
		"$binary" check -c "$checked" || die "the new zinkhole rejects $checked; nothing was changed"
	fi
	if [ -x /usr/local/bin/zinkhole ]; then
		previous=$(mktemp)
		trap 'rm -f "$previous"' EXIT
		cp -p /usr/local/bin/zinkhole "$previous"
	fi
	# The binary carries its own root certificates: no CA bundle needed.
	install -m 755 "$binary" /usr/local/bin/zinkhole

	fresh_config=no
	install -d -m 755 /etc/zinkhole
	if [ -n "$config_file" ]; then
		# Readable by the service's unprivileged user.
		install -m 644 "$config_file" /etc/zinkhole/config.toml
	elif [ ! -e /etc/zinkhole/config.toml ]; then
		install -m 644 "$root/config.example.toml" /etc/zinkhole/config.toml
		fresh_config=yes
	fi

	case "$init" in
	systemd)
		install -m 644 "$root/deploy/zinkhole.service" /etc/systemd/system/zinkhole.service
		systemctl daemon-reload
		systemctl enable zinkhole
		;;
	openrc)
		install -m 755 "$root/deploy/openrc/zinkhole" /etc/init.d/zinkhole
		rc-update add zinkhole default
		;;
	esac

	if [ "$fresh_config" = yes ] && [ "$start_anyway" = no ]; then
		cat <<EOF

zinkhole is installed as a service ($init_name) and starts at boot. Next:
  1. Edit /etc/zinkhole/config.toml: upstream servers, lists, local hostnames.
  2. Check it:  zinkhole check --lists
  3. Start it:  $start
  Logs:         $logs
EOF
		return 0
	fi
	restart_and_wait || roll_back
}

uninstall_zinkhole() {
	case "$init" in
	systemd)
		systemctl disable --now zinkhole 2>/dev/null || true
		rm -f /etc/systemd/system/zinkhole.service
		systemctl daemon-reload
		;;
	openrc)
		rc-service zinkhole stop 2>/dev/null || true
		rc-update del zinkhole default 2>/dev/null || true
		rm -f /etc/init.d/zinkhole
		;;
	esac
	rm -f /usr/local/bin/zinkhole
	echo "Removed the zinkhole service and binary. Your configuration in /etc/zinkhole was kept."
}

case "$action" in
install) install_zinkhole ;;
uninstall) uninstall_zinkhole ;;
esac
