#!/bin/sh
# Installs dnsblock as a system service, using systemd (Debian, Ubuntu, ...)
# or OpenRC (Alpine). Run as root from the repository or release directory:
#
#   ./deploy/install.sh                  # detect the init system
#   ./deploy/install.sh --init openrc    # or choose one: systemd, openrc
#   ./deploy/install.sh --uninstall      # remove service and binary, keep the config
#
# Options:
#   --binary PATH   the dnsblock binary (default: zig-out/bin/dnsblock)
#   --init NAME     systemd or openrc (default: detected)
#
# Running it again upgrades the binary and service file and restarts the
# service. An existing /etc/dnsblock/config.yaml is never overwritten.

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
binary="$root/zig-out/bin/dnsblock"
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
	start="systemctl start dnsblock"
	restart="systemctl restart dnsblock"
	logs="journalctl -u dnsblock -f"
	;;
openrc)
	init_name=OpenRC
	start="rc-service dnsblock start"
	restart="rc-service dnsblock restart"
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

install_dnsblock() {
	[ -x "$binary" ] || die "$binary not found; build it first: zig build --release -Dstrip=true"
	install_ca_certificates
	install -m 755 "$binary" /usr/local/bin/dnsblock

	fresh_config=no
	if [ ! -e /etc/dnsblock/config.yaml ]; then
		install -d -m 755 /etc/dnsblock
		install -m 644 "$root/config.example.yaml" /etc/dnsblock/config.yaml
		fresh_config=yes
	fi

	case "$init" in
	systemd)
		install -m 644 "$root/deploy/dnsblock.service" /etc/systemd/system/dnsblock.service
		systemctl daemon-reload
		systemctl enable dnsblock
		;;
	openrc)
		install -m 755 "$root/deploy/openrc/dnsblock" /etc/init.d/dnsblock
		rc-update add dnsblock default
		;;
	esac

	if [ "$fresh_config" = yes ]; then
		cat <<EOF

dnsblock is installed as a service ($init_name) and starts at boot. Next:
  1. Edit /etc/dnsblock/config.yaml: upstream servers, lists, local hostnames.
  2. Check it:  dnsblock --test -c /etc/dnsblock/config.yaml
  3. Start it:  $start
  Logs:         $logs
EOF
	else
		echo "Kept the existing /etc/dnsblock/config.yaml; restarting with the new binary."
		$restart
	fi
}

uninstall_dnsblock() {
	case "$init" in
	systemd)
		systemctl disable --now dnsblock 2>/dev/null || true
		rm -f /etc/systemd/system/dnsblock.service
		systemctl daemon-reload
		;;
	openrc)
		rc-service dnsblock stop 2>/dev/null || true
		rc-update del dnsblock default 2>/dev/null || true
		rm -f /etc/init.d/dnsblock
		;;
	esac
	rm -f /usr/local/bin/dnsblock
	echo "Removed the dnsblock service and binary. Your configuration in /etc/dnsblock was kept."
}

case "$action" in
install) install_dnsblock ;;
uninstall) uninstall_dnsblock ;;
esac
