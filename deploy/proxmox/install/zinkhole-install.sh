#!/usr/bin/env bash

# Copyright (c) 2026 jroosing
# License: MIT | https://github.com/jroosing/zinkhole/raw/main/LICENSE
# Source: https://github.com/jroosing/zinkhole
#
# Runs inside the new container, started by ct/zinkhole.sh through the
# community scripts' engine. Installs the latest zinkhole release (checked
# against its SHA256SUMS) as a standalone instance, a sync origin or a sync
# replica (docs/adr/0002, 0003), with metrics on the HTTP port, 5380 (docs/adr/0006),
# which an origin also serves its settings on. The role can be given
# up front: ZINKHOLE_ROLE, and for a replica ZINKHOLE_ORIGIN and
# ZINKHOLE_SECRET (an origin's secret is generated with `zinkhole secret`
# unless ZINKHOLE_SECRET is set).
# The engine defines the colors, messages and $STD used below.
# shellcheck disable=SC2154

# shellcheck source=/dev/null
source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

RELEASES="https://github.com/jroosing/zinkhole/releases"
HTTP_PORT=5380

setup_deb_based() {
  msg_info "Installing Dependencies"
  $STD apt install -y ca-certificates curl
  msg_ok "Installed Dependencies"
}

setup_alpine() {
  msg_info "Installing Dependencies"
  $STD apk add ca-certificates curl
  msg_ok "Installed Dependencies"
}

run_os_setup

# ── Role ──────────────────────────────────────────────────────────────────────
ROLE="${ZINKHOLE_ROLE:-}"
ORIGIN="${ZINKHOLE_ORIGIN:-}"
SECRET="${ZINKHOLE_SECRET:-}"
if [[ -z "$ROLE" && -t 0 ]]; then
  read -r -p "${TAB3}Role: standalone, origin (serves its settings to replicas) or replica? <standalone> " ROLE
fi
ROLE="${ROLE:-standalone}"
ROLE="${ROLE,,}"
case "$ROLE" in
standalone | origin | replica) ;;
*)
  msg_error "Unknown role '${ROLE}': choose standalone, origin or replica"
  exit 64
  ;;
esac
if [[ "$ROLE" == replica ]]; then
  if [[ -z "$ORIGIN" && -t 0 ]]; then
    read -r -p "${TAB3}The origin's URL, e.g. http://192.168.1.5:${HTTP_PORT}: " ORIGIN
  fi
  if [[ -z "$SECRET" && -t 0 ]]; then
    read -r -s -p "${TAB3}The origin's secret: " SECRET
    echo
  fi
  if [[ ! "$ORIGIN" =~ ^https?://[][A-Za-z0-9._:/-]+$ ]]; then
    msg_error "The origin must be a URL like http://192.168.1.5:${HTTP_PORT}"
    exit 64
  fi
fi
# An origin's secret is made below, with `zinkhole secret`; a replica needs
# its origin's.
if [[ "$ROLE" == replica && -z "$SECRET" ]]; then
  msg_error "A replica needs the origin's secret (ZINKHOLE_SECRET)"
  exit 64
fi
if [[ -n "$SECRET" && ! "$SECRET" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  msg_error "The secret must be 64 hex digits, as \`zinkhole secret\` prints"
  exit 64
fi

# ── zinkhole ──────────────────────────────────────────────────────────────────
# Downloading is written here and in update.sh (from the release): neither
# has the bundle before it downloads it.
msg_info "Downloading zinkhole"
BIN="zinkhole-$(arch_resolve x86_64 aarch64)-linux-musl"
WORK=$(mktemp -d)
curl -fsSL -o "$WORK/SHA256SUMS" "$RELEASES/latest/download/SHA256SUMS"
for file in "$BIN" zinkhole-deploy.tar.gz; do
  curl -fsSL -o "$WORK/$file" "$RELEASES/latest/download/$file"
  if ! (cd "$WORK" && grep " ${file}\$" SHA256SUMS | sha256sum -c - >/dev/null); then
    msg_error "${file} does not match SHA256SUMS"
    exit 1
  fi
done
chmod 755 "$WORK/$BIN"
VERSION=$("$WORK/$BIN" --version | cut -d' ' -f2)
msg_ok "Downloaded zinkhole ${VERSION} (checked against SHA256SUMS)"

mkdir -p "$WORK/pkg"
tar -xzf "$WORK/zinkhole-deploy.tar.gz" -C "$WORK/pkg"
if [[ "$ROLE" == origin && -z "$SECRET" ]]; then
  SECRET=$("$WORK/$BIN" secret)
fi

# The container's global IPv6 networks, one per line.
ipv6_networks() {
  ip -6 -o route show 2>/dev/null |
    awk '$1 ~ /\// && $1 !~ /^(fe80|ff)/ && $1 != "default" {print $1}' | sort -u
}

IPV6=off
case "${IPV6_METHOD:-none}" in
auto | dhcp | static) IPV6=on ;;
esac
if [[ "$IPV6" == on ]]; then
  # Addresses can arrive a few seconds after the container started.
  for _ in $(seq 20); do
    [[ -n "$(ipv6_networks)" ]] && break
    sleep 1
  done
fi

# zinkhole answers only clients in server.allow_clients, whose default covers
# private addresses but no global IPv6 prefix: with IPv6, this container's own
# IPv6 networks are added to that default.
write_server_section() {
  echo
  echo "[server]"
  if [[ "$IPV6" != on ]]; then
    echo 'listen = ["0.0.0.0:53"]'
    return 0
  fi
  echo 'listen = ["0.0.0.0:53", "[::]:53"]'
  local networks network
  networks=$(ipv6_networks)
  if [[ -z "$networks" ]]; then
    msg_warn "No global IPv6 network found; add yours to server.allow_clients" >&2
    return 0
  fi
  echo "allow_clients = ["
  # The default list, from the example config's [server] section.
  awk '/^allow_clients = \[/ {f = 1; next} f && /^\]/ {exit} f {print}' "$WORK/pkg/config.example.toml"
  for network in $networks; do echo "  \"$network\","; done
  echo "]"
}

msg_info "Configuring zinkhole (${ROLE})"
{
  cat <<'TOML'
# zinkhole configuration, written by the Proxmox installer. Every setting is
# documented in config.example.toml of the zinkhole repository:
#   https://github.com/jroosing/zinkhole
# Check it with `zinkhole check`, apply changes with `systemctl reload
# zinkhole` (Debian) or `rc-service zinkhole reload` (Alpine).
TOML
  write_server_section
  cat <<'TOML'

[upstream]
servers = [
  { url = "https://dns.quad9.net/dns-query", address = "9.9.9.9" },
  { url = "https://dns.quad9.net/dns-query", address = "149.112.112.112" },
  { url = "https://cloudflare-dns.com/dns-query", address = "1.0.0.1" },
]
TOML
  if [[ "$ROLE" == replica ]]; then
    printf '\n# [blocking] and [local] come from the origin (see [sync] below).\n'
  else
    cat <<'TOML'

[blocking]
lists = ["https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt"]

[local.records]
# Names for your own devices, e.g.
# "nas.lan" = "192.168.1.10"
TOML
  fi
  # One port for the metrics and an origin's settings, on every address, so
  # a changed (DHCP) address keeps working; only clients in
  # server.allow_clients are answered (docs/adr/0006).
  printf '\n[http]\nlisten = ["0.0.0.0:%s"]\n' "$HTTP_PORT"
  case "$ROLE" in
  origin) printf '\n[sync]\nrole = "origin"\nsecret = "%s"\n' "$SECRET" ;;
  replica) printf '\n[sync]\nrole = "replica"\norigin = "%s"\nsecret = "%s"\n' "$ORIGIN" "$SECRET" ;;
  esac
} >"$WORK/config.toml"
msg_ok "Configured zinkhole (${ROLE})"

# The binary, the config (checked first; readable by the service's
# unprivileged user, as this container runs nothing else) and the service
# (systemd or OpenRC), which is started; fails unless it answers.
msg_info "Installing and starting zinkhole"
$STD sh "$WORK/pkg/deploy/install.sh" --binary "$WORK/$BIN" --config "$WORK/config.toml" --start
echo "$VERSION" >~/.zinkhole
rm -rf "$WORK"
msg_ok "Installed and started zinkhole ${VERSION}"

motd_ssh
customize
cleanup_lxc
