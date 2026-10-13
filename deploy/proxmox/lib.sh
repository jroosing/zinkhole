# shellcheck shell=bash
# The shared work of the Proxmox installers (docs/adr/0003). Sourced by
# zinkhole-debian.sh and zinkhole-alpine.sh, which set OS_NAME, TEMPLATE_REGEX
# (@ARCH@ stands for amd64 or arm64), NESTING, SCRIPT_NAME and BASE_URL first.
#
# Creates an unprivileged LXC container, installs zinkhole in it, and sets it
# up as a standalone instance, a sync origin or a sync replica. Every question
# can be answered by an environment variable:
#
#   ZINKHOLE_CTID          container ID (default: next free)
#   ZINKHOLE_HOSTNAME      default zinkhole-<node>
#   ZINKHOLE_IP            dhcp, or a static address with prefix, e.g. 192.168.1.5/24
#   ZINKHOLE_GATEWAY       static only; default: this node's default gateway
#   ZINKHOLE_IP6           off (default), auto (SLAAC), dhcp, or a static
#                          address with prefix, e.g. fd00::5/64
#   ZINKHOLE_GATEWAY6      static IPv6 only, optional
#   ZINKHOLE_ROLE          standalone (default), origin or replica
#   ZINKHOLE_ORIGIN        replica: the origin's URL, e.g. http://192.168.1.5:5380
#   ZINKHOLE_SECRET        replica: the origin's secret (origin: generated)
#   ZINKHOLE_BRIDGE        default vmbr0           ZINKHOLE_VLAN  optional tag
#   ZINKHOLE_NAMESERVER    for the container itself; default: the gateway (static)
#                          or what DHCP hands out
#   ZINKHOLE_STORAGE       container disk storage; ZINKHOLE_TEMPLATE_STORAGE
#   ZINKHOLE_CORES (1)  ZINKHOLE_MEMORY (128, MB)  ZINKHOLE_DISK (1, GB)
#   ZINKHOLE_YES=1         do not ask for confirmation
#   ZINKHOLE_KEEP_ON_FAIL=1  keep the container if the installation fails
#   ZINKHOLE_BASE_URL      download location (default: this script's release)
set -Eeuo pipefail

SYNC_PORT=5380
WORK=""
CREATED=0

info() { printf '==> %s\n' "$*"; }
die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}
interactive() { [[ -t 0 && -t 1 ]]; }

# ask VAR QUESTION [DEFAULT]: keeps $VAR if it is set (for example from the
# environment), otherwise asks, otherwise takes the default.
ask() {
	local var=$1 question=$2 default=${3:-} answer
	if [[ -z ${!var:-} ]]; then
		if interactive; then
			read -r -p "$question${default:+ [$default]}: " answer
			printf -v "$var" '%s' "${answer:-$default}"
		else
			printf -v "$var" '%s' "$default"
		fi
	fi
	[[ -n ${!var} ]] || die "$question: no value (set $var)"
}

ask_secret() {
	local var=$1 question=$2 answer
	if [[ -z ${!var:-} ]]; then
		interactive || die "$question: no value (set $var)"
		read -r -s -p "$question: " answer
		echo
		printf -v "$var" '%s' "$answer"
	fi
}

check_host() {
	[[ $EUID -eq 0 ]] || die "run this as root on a Proxmox node"
	local tool
	for tool in pct pveam pvesm pvesh curl sha256sum; do
		command -v "$tool" >/dev/null 2>&1 || die "$tool not found: this must run on a Proxmox VE node"
	done
	case "$(uname -m)" in
	x86_64) ARCH=x86_64 TEMPLATE_ARCH=amd64 ;;
	aarch64) ARCH=aarch64 TEMPLATE_ARCH=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
	esac
	[[ $BASE_URL != *@VERSION@* ]] || die "this copy is not a release; set ZINKHOLE_BASE_URL to where the release files are"
}

default_storage() { pvesm status --content "$1" 2>/dev/null | awk 'NR > 1 && $3 == "active" {print $1; exit}'; }
default_gateway() { ip -4 route show default 2>/dev/null | awk '{print $3; exit}'; }

valid_ipv4() {
	local a b c d
	[[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	a=${BASH_REMATCH[1]} b=${BASH_REMATCH[2]} c=${BASH_REMATCH[3]} d=${BASH_REMATCH[4]}
	((a < 256 && b < 256 && c < 256 && d < 256))
}

collect_settings() {
	local next_id
	next_id=$(pvesh get /cluster/nextid 2>/dev/null | tr -d '"' || true)
	ask ZINKHOLE_CTID "Container ID" "$next_id"
	ask ZINKHOLE_HOSTNAME "Hostname" "zinkhole-$(hostname -s)"
	ask ZINKHOLE_IP "IPv4 address: dhcp, or static with prefix length (for example 192.168.1.5/24)"
	ZINKHOLE_IP=${ZINKHOLE_IP,,}
	if [[ $ZINKHOLE_IP != dhcp ]]; then
		ask ZINKHOLE_GATEWAY "IPv4 gateway" "$(default_gateway || true)"
	fi
	ZINKHOLE_GATEWAY=${ZINKHOLE_GATEWAY:-}
	ask ZINKHOLE_IP6 "IPv6: off, auto (SLAAC), dhcp, or static with prefix length (for example fd00::5/64)" off
	ZINKHOLE_IP6=${ZINKHOLE_IP6,,}
	ZINKHOLE_GATEWAY6=${ZINKHOLE_GATEWAY6:-}
	if [[ $ZINKHOLE_IP6 == *:* && -z $ZINKHOLE_GATEWAY6 ]] && interactive; then
		read -r -p "IPv6 gateway (optional): " ZINKHOLE_GATEWAY6
	fi
	ask ZINKHOLE_ROLE "Role: standalone, origin or replica" standalone
	ZINKHOLE_BRIDGE=${ZINKHOLE_BRIDGE:-vmbr0}
	ZINKHOLE_VLAN=${ZINKHOLE_VLAN:-}
	# A DHCP container gets its name server from DHCP, unless one is given.
	if [[ -z ${ZINKHOLE_NAMESERVER:-} && $ZINKHOLE_IP != dhcp ]]; then ZINKHOLE_NAMESERVER=$ZINKHOLE_GATEWAY; fi
	ZINKHOLE_NAMESERVER=${ZINKHOLE_NAMESERVER:-}
	ZINKHOLE_STORAGE=${ZINKHOLE_STORAGE:-$(default_storage rootdir)}
	ZINKHOLE_TEMPLATE_STORAGE=${ZINKHOLE_TEMPLATE_STORAGE:-$(default_storage vztmpl)}
	ZINKHOLE_CORES=${ZINKHOLE_CORES:-1}
	ZINKHOLE_MEMORY=${ZINKHOLE_MEMORY:-128}
	ZINKHOLE_DISK=${ZINKHOLE_DISK:-1}
	ZINKHOLE_ORIGIN=${ZINKHOLE_ORIGIN:-}
	ZINKHOLE_SECRET=${ZINKHOLE_SECRET:-}

	case "$ZINKHOLE_ROLE" in
	standalone) ;;
	origin)
		if [[ -z $ZINKHOLE_SECRET ]]; then
			ZINKHOLE_SECRET=$(openssl rand -hex 32 2>/dev/null || od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
		fi
		;;
	replica)
		ask ZINKHOLE_ORIGIN "The origin's URL (for example http://192.168.1.5:$SYNC_PORT)"
		ask_secret ZINKHOLE_SECRET "The origin's secret"
		;;
	*) die "the role must be standalone, origin or replica" ;;
	esac

	[[ $ZINKHOLE_CTID =~ ^[0-9]+$ ]] || die "invalid container ID '$ZINKHOLE_CTID'"
	if pct status "$ZINKHOLE_CTID" >/dev/null 2>&1; then die "container $ZINKHOLE_CTID already exists"; fi
	[[ $ZINKHOLE_HOSTNAME =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] || die "invalid hostname '$ZINKHOLE_HOSTNAME'"
	if [[ $ZINKHOLE_IP != dhcp ]]; then
		[[ $ZINKHOLE_IP =~ ^([0-9.]+)/([0-9]{1,2})$ ]] || die "the IPv4 address must be 'dhcp' or have a prefix length, like 192.168.1.5/24"
		local prefix=${BASH_REMATCH[2]}
		if ! valid_ipv4 "${BASH_REMATCH[1]}" || ((prefix > 32)); then die "invalid IPv4 address '$ZINKHOLE_IP'"; fi
		valid_ipv4 "$ZINKHOLE_GATEWAY" || die "invalid IPv4 gateway '$ZINKHOLE_GATEWAY'"
	fi
	if [[ -n $ZINKHOLE_NAMESERVER ]]; then valid_ipv4 "$ZINKHOLE_NAMESERVER" || die "invalid name server '$ZINKHOLE_NAMESERVER'"; fi
	case "$ZINKHOLE_IP6" in
	off | auto | dhcp) ;;
	*)
		local v6_re='^[0-9a-f:]+/([0-9]{1,3})$'
		[[ $ZINKHOLE_IP6 =~ $v6_re && $ZINKHOLE_IP6 == *:* ]] || die "IPv6 must be off, auto, dhcp, or an address with prefix length, like fd00::5/64"
		local v6_prefix=${BASH_REMATCH[1]}
		if ((v6_prefix > 128)); then die "invalid IPv6 address '$ZINKHOLE_IP6'"; fi
		;;
	esac
	if [[ -n $ZINKHOLE_GATEWAY6 ]]; then
		[[ $ZINKHOLE_IP6 == *:* ]] || die "ZINKHOLE_GATEWAY6 only applies to a static IPv6 address"
		local gw6_re='^[0-9a-f:]+$'
		[[ ${ZINKHOLE_GATEWAY6,,} =~ $gw6_re && $ZINKHOLE_GATEWAY6 == *:* ]] || die "invalid IPv6 gateway '$ZINKHOLE_GATEWAY6'"
	fi
	[[ -z $ZINKHOLE_VLAN || $ZINKHOLE_VLAN =~ ^[0-9]{1,4}$ ]] || die "invalid VLAN '$ZINKHOLE_VLAN'"
	[[ $ZINKHOLE_BRIDGE =~ ^[a-zA-Z0-9_.-]+$ ]] || die "invalid bridge '$ZINKHOLE_BRIDGE'"
	[[ -n $ZINKHOLE_STORAGE ]] || die "no storage for container disks found; set ZINKHOLE_STORAGE"
	[[ -n $ZINKHOLE_TEMPLATE_STORAGE ]] || die "no storage for templates found; set ZINKHOLE_TEMPLATE_STORAGE"
	[[ $ZINKHOLE_CORES =~ ^[0-9]+$ && $ZINKHOLE_MEMORY =~ ^[0-9]+$ && $ZINKHOLE_DISK =~ ^[0-9]+$ ]] || die "cores, memory and disk must be numbers"
	if [[ $ZINKHOLE_ROLE != standalone ]]; then
		# The secret goes into a YAML file and a shell file: keep it plain.
		[[ $ZINKHOLE_SECRET =~ ^[A-Za-z0-9._~+=/-]{32,}$ ]] || die "the secret needs at least 32 characters from A-Z a-z 0-9 . _ ~ + = / -"
	fi
	if [[ $ZINKHOLE_ROLE == replica ]]; then
		# In a bracket expression, ] must come first to be a literal.
		local url_re='^https?://[][A-Za-z0-9._:/-]+$'
		[[ $ZINKHOLE_ORIGIN =~ $url_re ]] || die "the origin must be a URL like http://192.168.1.5:$SYNC_PORT"
	fi
}

confirm() {
	cat <<EOF

  $OS_NAME container $ZINKHOLE_CTID "$ZINKHOLE_HOSTNAME", $ZINKHOLE_CORES core(s), $ZINKHOLE_MEMORY MB RAM, $ZINKHOLE_DISK GB on $ZINKHOLE_STORAGE
  IPv4 $ZINKHOLE_IP${ZINKHOLE_GATEWAY:+ via $ZINKHOLE_GATEWAY} on $ZINKHOLE_BRIDGE${ZINKHOLE_VLAN:+ (VLAN $ZINKHOLE_VLAN)}, IPv6 $ZINKHOLE_IP6
  role: $ZINKHOLE_ROLE${ZINKHOLE_ORIGIN:+ of $ZINKHOLE_ORIGIN}

EOF
	if interactive && [[ -z ${ZINKHOLE_YES:-} ]]; then
		local answer
		read -r -p "Create it? [Y/n] " answer
		[[ ${answer:-y} =~ ^[Yy] ]] || die "cancelled"
	fi
}

# Downloads the release files and checks them against SHA256SUMS.
fetch_release() {
	local file
	WORK=$(mktemp -d)
	info "Downloading zinkhole from $BASE_URL"
	curl -fsSL -o "$WORK/SHA256SUMS" "$BASE_URL/SHA256SUMS"
	for file in "zinkhole-$ARCH-linux-musl" zinkhole-deploy.tar.gz setup.sh; do
		curl -fsSL -o "$WORK/$file" "$BASE_URL/$file"
		(cd "$WORK" && grep " $file\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "$file does not match SHA256SUMS"
	done
	chmod 755 "$WORK/zinkhole-$ARCH-linux-musl"
	VERSION=$("$WORK/zinkhole-$ARCH-linux-musl" --version | cut -d' ' -f2)
}

ensure_template() {
	local regex=${TEMPLATE_REGEX//@ARCH@/$TEMPLATE_ARCH}
	info "Looking for the $OS_NAME template"
	pveam update >/dev/null 2>&1 || true
	TEMPLATE=$(pveam available --section system | awk '{print $2}' | grep -E "$regex" | sort -V | tail -n 1 || true)
	[[ -n $TEMPLATE ]] || die "no $OS_NAME template found with 'pveam available' (pattern: $regex)"
	if ! pveam list "$ZINKHOLE_TEMPLATE_STORAGE" | awk 'NR > 1 {print $1}' | grep -qx "$ZINKHOLE_TEMPLATE_STORAGE:vztmpl/$TEMPLATE"; then
		info "Downloading $TEMPLATE"
		pveam download "$ZINKHOLE_TEMPLATE_STORAGE" "$TEMPLATE"
	fi
}

create_container() {
	local net="name=eth0,bridge=$ZINKHOLE_BRIDGE,ip=$ZINKHOLE_IP"
	if [[ $ZINKHOLE_IP != dhcp ]]; then net+=",gw=$ZINKHOLE_GATEWAY"; fi
	# Without ip6, Proxmox configures no IPv6 address for the container.
	if [[ $ZINKHOLE_IP6 != off ]]; then net+=",ip6=$ZINKHOLE_IP6"; fi
	if [[ -n $ZINKHOLE_GATEWAY6 ]]; then net+=",gw6=$ZINKHOLE_GATEWAY6"; fi
	if [[ -n $ZINKHOLE_VLAN ]]; then net+=",tag=$ZINKHOLE_VLAN"; fi
	local features=() nameserver=()
	# systemd's sandboxing needs nesting; OpenRC (Alpine) does not.
	if [[ ${NESTING:-0} == 1 ]]; then features=(--features nesting=1); fi
	# Without --nameserver, a DHCP container uses what DHCP hands out.
	if [[ -n $ZINKHOLE_NAMESERVER ]]; then nameserver=(--nameserver "$ZINKHOLE_NAMESERVER"); fi
	info "Creating container $ZINKHOLE_CTID"
	pct create "$ZINKHOLE_CTID" "$ZINKHOLE_TEMPLATE_STORAGE:vztmpl/$TEMPLATE" \
		--hostname "$ZINKHOLE_HOSTNAME" --unprivileged 1 "${features[@]}" \
		--cores "$ZINKHOLE_CORES" --memory "$ZINKHOLE_MEMORY" --swap 0 \
		--rootfs "$ZINKHOLE_STORAGE:$ZINKHOLE_DISK" --net0 "$net" \
		"${nameserver[@]}" --onboot 1 --tags zinkhole \
		--description "zinkhole DNS blocker ($ZINKHOLE_ROLE), installed by the zinkhole Proxmox script"
	CREATED=1
	pct start "$ZINKHOLE_CTID"
	info "Waiting for the container's network"
	local _
	for _ in $(seq 60); do
		if pct exec "$ZINKHOLE_CTID" -- getent hosts gitlab.com >/dev/null 2>&1; then return 0; fi
		sleep 1
	done
	die "the container has no network or DNS; check the address, gateway and name server (and that DHCP answers on $ZINKHOLE_BRIDGE)"
}

install_in_container() {
	local ct=$ZINKHOLE_CTID dir=/root/zinkhole-setup
	{
		echo "ZINKHOLE_ROLE='$ZINKHOLE_ROLE'"
		# A DHCP address can change, so an origin then serves on every address
		# (still only to ZINKHOLE allow_clients).
		if [[ $ZINKHOLE_IP == dhcp ]]; then echo "ZINKHOLE_SERVE='0.0.0.0'"; else echo "ZINKHOLE_SERVE='${ZINKHOLE_IP%/*}'"; fi
		if [[ $ZINKHOLE_IP6 == off ]]; then echo "ZINKHOLE_IPV6='off'"; else echo "ZINKHOLE_IPV6='on'"; fi
		echo "ZINKHOLE_ORIGIN='$ZINKHOLE_ORIGIN'"
		echo "ZINKHOLE_SECRET='$ZINKHOLE_SECRET'"
		# Only a download location that is not the project's own is remembered.
		if [[ -n ${ZINKHOLE_BASE_URL:-} ]]; then echo "ZINKHOLE_BASE_URL='$ZINKHOLE_BASE_URL'"; fi
	} >"$WORK/setup.env"
	chmod 600 "$WORK/setup.env"

	info "Installing zinkhole $VERSION in the container"
	pct exec "$ct" -- mkdir -p "$dir"
	pct push "$ct" "$WORK/zinkhole-$ARCH-linux-musl" "$dir/zinkhole" --perms 0755
	pct push "$ct" "$WORK/zinkhole-deploy.tar.gz" "$dir/zinkhole-deploy.tar.gz"
	pct push "$ct" "$WORK/setup.sh" "$dir/setup.sh" --perms 0755
	pct push "$ct" "$WORK/setup.env" "$dir/setup.env" --perms 0600
	pct exec "$ct" -- sh "$dir/setup.sh"
	pct exec "$ct" -- rm -rf "$dir"
}

# The container's global addresses of one family (4 or 6), one per line.
container_addresses() {
	pct exec "$ZINKHOLE_CTID" -- ip -o -"$1" addr show scope global 2>/dev/null | awk '{sub("/.*", "", $4); print $4}' || true
}

summary() {
	local ip ip6
	ip=$(container_addresses 4 | sed -n 1p)
	ip6=$(container_addresses 6 | sed -n 1p)
	if [[ -z $ip ]]; then
		if [[ $ZINKHOLE_IP == dhcp ]]; then
			ip="<the DHCP address: see 'pct exec $ZINKHOLE_CTID -- ip a'>"
		else
			ip=${ZINKHOLE_IP%/*}
		fi
	fi
	cat <<EOF

zinkhole $VERSION runs in container $ZINKHOLE_CTID ($ZINKHOLE_HOSTNAME) at $ip${ip6:+ and $ip6}.

  Try it:      dig @$ip example.com
  Use it:      hand out $ip${ip6:+ (and $ip6)} as the DNS server (usually in your router's DHCP settings)
  Edit config: pct enter $ZINKHOLE_CTID    then edit /etc/zinkhole/config.yaml
               apply with: systemctl reload zinkhole   (Alpine: rc-service zinkhole reload)
  Update:      pct exec $ZINKHOLE_CTID -- update       (OS packages and zinkhole)
EOF
	if [[ $ZINKHOLE_IP == dhcp ]]; then
		cat <<EOF

The IPv4 address came from DHCP and can change. Clients need a DNS server whose
address stays the same: give this container (MAC address in 'pct config
$ZINKHOLE_CTID') a fixed lease on your DHCP server.
EOF
	fi
	if [[ $ZINKHOLE_IP6 != off && -z $ip6 ]]; then
		cat <<EOF

No global IPv6 address yet (ZINKHOLE_IP6=$ZINKHOLE_IP6). Check again later with
'pct exec $ZINKHOLE_CTID -- ip -6 a'; zinkhole answers IPv6 clients only from
networks in server.allow_clients (add your IPv6 prefix there if it is not found).
EOF
	fi
	if [[ $ZINKHOLE_ROLE == origin ]]; then
		cat <<EOF

This is the sync origin. Its secret, shown once (it is also in /etc/zinkhole/config.yaml):

  $ZINKHOLE_SECRET

Create a replica on another node with:

  ZINKHOLE_ROLE=replica ZINKHOLE_ORIGIN=http://$ip:$SYNC_PORT ZINKHOLE_SECRET=<the secret> \\
    bash -c "\$(curl -fsSL $BASE_URL/${SCRIPT_NAME:-zinkhole-debian.sh})"

Update the replicas before the origin.
EOF
	fi
	echo
}

cleanup() {
	local status=$?
	if [[ -n $WORK ]]; then rm -rf "$WORK"; fi
	if ((status != 0 && CREATED)); then
		if [[ -n ${ZINKHOLE_KEEP_ON_FAIL:-} ]]; then
			echo "The installation failed; container $ZINKHOLE_CTID was kept: pct enter $ZINKHOLE_CTID" >&2
		else
			echo "The installation failed; removing container $ZINKHOLE_CTID (ZINKHOLE_KEEP_ON_FAIL=1 keeps it)." >&2
			pct stop "$ZINKHOLE_CTID" >/dev/null 2>&1 || true
			pct destroy "$ZINKHOLE_CTID" --purge >/dev/null 2>&1 || true
		fi
	fi
}

main() {
	trap cleanup EXIT
	check_host
	collect_settings
	confirm
	fetch_release
	ensure_template
	create_container
	install_in_container
	summary
}
