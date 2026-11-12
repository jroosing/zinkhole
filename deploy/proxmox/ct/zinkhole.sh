#!/usr/bin/env bash
# The scripts (this ct/ script and install/zinkhole-install.sh) come from this
# repository; the engine that runs them is the Proxmox VE community scripts'
# own (github.com/community-scripts/core). See docs/adr/0001.
COMMUNITY_SCRIPTS_URL="${COMMUNITY_SCRIPTS_URL:-https://raw.githubusercontent.com/jroosing/zinkhole/main/deploy/proxmox}"
export COMMUNITY_SCRIPTS_URL
_cs_boot="${COMMUNITY_SCRIPTS_CORE_DIR:-$(dirname "${BASH_SOURCE[0]}")/../../core}/core/build.func"
# shellcheck source=/dev/null
source "$_cs_boot" 2>/dev/null || source <(curl -fsSL "${COMMUNITY_SCRIPTS_CORE_URL:-https://raw.githubusercontent.com/community-scripts/core/main}/core/build.func")
# Copyright (c) 2026 jroosing
# License: MIT | https://github.com/jroosing/zinkhole/raw/main/LICENSE
# Source: https://github.com/jroosing/zinkhole
# The engine defines the colors, messages and settings used below.
# shellcheck disable=SC2034,SC2154

APP="zinkhole"
var_tags="${var_tags:-adblock;dns}"
var_cpu="${var_cpu:-1}"
var_arm64="${var_arm64:-yes}"
var_unprivileged="${var_unprivileged:-1}"
if [[ -z "${var_os:-}" ]] && command -v pveversion >/dev/null 2>&1; then
  var_os=$(msg_menu "Choose the container OS" \
    "debian" "Debian 13" \
    "alpine" "Alpine (smaller footprint)")
fi

if [[ "${var_os:-}" == "alpine" ]]; then
  var_ram="${var_ram:-128}"
  var_disk="${var_disk:-1}"
  var_version="${var_version:-3.24}"
else
  var_ram="${var_ram:-256}"
  var_disk="${var_disk:-2}"
  var_version="${var_version:-13}"
fi

# The engine shows banners generated for its own catalogue; zinkhole's goes
# where it caches those, so `header_info` shows it the usual way.
_cs_header_dir="$(community_scripts_dir 2>/dev/null || echo /usr/local/community-scripts)/headers/ct"
if mkdir -p "$_cs_header_dir" 2>/dev/null; then
  cat >"$_cs_header_dir/zinkhole" 2>/dev/null <<'BANNER' || true
         _       _     _           _
    ____(_)_ __ | | __| |__   ___ | | ___
   |_  /| | '_ \| |/ /| '_ \ / _ \| |/ _ \
    / / | | | | |   < | | | | (_) | |  __/
   /___||_|_| |_|_|\_\|_| |_|\___/|_|\___|
BANNER
fi
header_info "$APP"
variables
color
catch_errors

RELEASES="https://github.com/jroosing/zinkhole/releases"
# The HTTP port, as the install script writes it (install/zinkhole-install.sh).
HTTP_PORT=5380

# Updates zinkhole to the latest release with that release's own updater
# (update.sh, checked against its SHA256SUMS): it checks the new binary
# against the current config first and puts the old one back if it does not
# answer.
require_zinkhole() {
  if [[ ! -x /usr/local/bin/zinkhole ]]; then
    msg_error "No ${APP} Installation Found!"
    exit
  fi
}

update_zinkhole() {
  if grep -Eq '^role[[:space:]]*=[[:space:]]*"origin"' /etc/zinkhole/config.toml 2>/dev/null; then
    msg_warn "This is the sync origin: update its replicas first."
  fi
  if check_for_gh_release "zinkhole" "jroosing/zinkhole"; then
    msg_info "Updating ${APP} to ${CHECK_UPDATE_RELEASE}"
    local base="${RELEASES}/download/${CHECK_UPDATE_RELEASE}" tmp
    tmp=$(mktemp -d)
    curl -fsSL -o "$tmp/SHA256SUMS" "$base/SHA256SUMS"
    curl -fsSL -o "$tmp/update.sh" "$base/update.sh"
    if ! (cd "$tmp" && grep ' update.sh$' SHA256SUMS | sha256sum -c - >/dev/null); then
      rm -rf "$tmp"
      msg_error "update.sh does not match SHA256SUMS; nothing was changed"
      exit 1
    fi
    $STD env ZINKHOLE_BASE_URL="$base" sh "$tmp/update.sh" --skip-os
    rm -rf "$tmp"
    # What is installed now: the update may have changed nothing.
    /usr/local/bin/zinkhole --version | cut -d' ' -f2 >~/.zinkhole
    msg_ok "Updated ${APP} to ${CHECK_UPDATE_RELEASE}"
  fi
  msg_ok "Updated successfully!"
}

update_deb_based() {
  require_zinkhole
  msg_info "Updating Debian Packages"
  export DEBIAN_FRONTEND=noninteractive
  $STD apt update
  $STD apt -o Dpkg::Options::=--force-confold -y full-upgrade
  msg_ok "Updated Debian Packages"
  update_zinkhole
}

update_alpine() {
  require_zinkhole
  msg_info "Updating Alpine Packages"
  $STD apk -U upgrade
  msg_ok "Updated Alpine Packages"
  update_zinkhole
}

function update_script() {
  header_info
  check_container_storage
  check_container_resources
  run_os_update
}

start
build_container
description

msg_ok "Completed successfully!\n"
echo -e "${CREATING}${GN}${APP} setup has been successfully initialized!${CL}"
echo -e "${INFO}${YW}Use ${IP} as the DNS server (usually in your router's DHCP settings). Try it:${CL}"
echo -e "${TAB}${GATEWAY}${BGN}dig @${IP} example.com${CL}"
echo -e "${INFO}${YW}Metrics:${CL}"
echo -e "${TAB}${GATEWAY}${BGN}http://${IP}:${HTTP_PORT}/metrics${CL}"
echo -e "${INFO}${YW}Config: /etc/zinkhole/config.toml (pct enter ${CTID}); update with: pct exec ${CTID} -- update${CL}"
if pct exec "$CTID" -- grep -Eq '^role[[:space:]]*=[[:space:]]*"origin"' /etc/zinkhole/config.toml 2>/dev/null; then
  # shellcheck disable=SC2016 # awk's $2, not the shell's
  secret=$(pct exec "$CTID" -- awk -F'"' '/^secret[[:space:]]*=/ {print $2}' /etc/zinkhole/config.toml)
  echo -e "${INFO}${YW}This is the sync origin. Its secret (also in the config):${CL}"
  echo -e "${TAB}${BGN}${secret}${CL}"
  echo -e "${INFO}${YW}Create a replica on another node with:${CL}"
  echo -e "${TAB}${BGN}ZINKHOLE_ROLE=replica ZINKHOLE_ORIGIN=http://${IP}:${HTTP_PORT} ZINKHOLE_SECRET=<the secret> bash -c \"\$(curl -fsSL ${COMMUNITY_SCRIPTS_URL}/ct/zinkhole.sh)\"${CL}"
fi
