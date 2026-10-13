#!/bin/sh
# Installs zinkhole as a system service, using systemd (Debian, Ubuntu, ...)
# or OpenRC (Alpine). Run as root from the repository or release directory:
#
#   ./deploy/install.sh                  # detect the init system
#   ./deploy/install.sh --init openrc    # or choose one: systemd, openrc
#   ./deploy/install.sh --uninstall      # remove service and binary, keep the config
#
# Options:
#   --binary PATH   the zinkhole binary (default: zig-out/bin/zinkhole)
#   --init NAME     systemd or openrc (default: detected)
#
# Running it again upgrades the binary and service file and restarts the
# service. An existing /etc/zinkhole/config.yaml is never overwritten.

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
binary="$root/zig-out/bin/zinkhole"
init=""
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
	--uninstall)
		action=uninstall
		shift
		;;
	-h | --help)
		sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
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

# DNS over TLS and https:// blocklists need the system's CA certificates.
install_ca_certificates() {
	if [ -e /etc/ssl/certs/ca-certificates.crt ] || [ -e /etc/ssl/cert.pem ]; then
		return 0
	fi
	echo "Installing CA certificates (for DNS over TLS and https:// lists)"
	if command -v apk >/dev/null 2>&1; then
		apk add --no-cache ca-certificates
	elif command -v apt-get >/dev/null 2>&1; then
		apt-get install -y ca-certificates || { apt-get update && apt-get install -y ca-certificates; }
	else
		echo "warning: install your distribution's CA certificates package" >&2
	fi
}

install_zinkhole() {
	[ -x "$binary" ] || die "$binary not found; build it first: zig build --release -Dstrip=true"
	install_ca_certificates
	install -m 755 "$binary" /usr/local/bin/zinkhole

	fresh_config=no
	if [ ! -e /etc/zinkhole/config.yaml ]; then
		install -d -m 755 /etc/zinkhole
		install -m 644 "$root/config.example.yaml" /etc/zinkhole/config.yaml
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

	if [ "$fresh_config" = yes ]; then
		cat <<EOF

zinkhole is installed as a service ($init_name) and starts at boot. Next:
  1. Edit /etc/zinkhole/config.yaml: upstream servers, lists, local hostnames.
  2. Check it:  zinkhole --test -c /etc/zinkhole/config.yaml
  3. Start it:  $start
  Logs:         $logs
EOF
	else
		echo "Kept the existing /etc/zinkhole/config.yaml; restarting with the new binary."
		$restart
	fi
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
