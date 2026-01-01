#!/usr/bin/env bash
set -euo pipefail

# =========================
# Fresh Debian Trixie Pi setup (headless-friendly)
# Focus: stable networking + sane logging + basic tooling
# =========================

# ---- Tunables (edit if you want) ----
INSTALL_HARDENED_APP=1
APP_NAME="it-army"
APP_EXECSTART="/bin/bash /usr/local/bin/start-it-army.sh"
APP_USER="root"
START_SCRIPT="start-it-army.sh"
APP_WORKDIR="/"
APP_CPU_QUOTA="85%"
APP_MEM_MAX="256M"
APP_NICE="5"
APP_DEADMAN_EVERY="6h"
APP_HEARTBEAT_EVERY="5m"
APP_DEB_URL="${APP_DEB_URL:-https://github.com/it-army-ua-scripts/itarmykit/releases/latest/download/itarmykit-linux-arm64.deb}"
IFACE="${IFACE:-wlan0}"
COOLDOWN_S="${COOLDOWN_S:-180}"       # reconnect cooldown
TIMER_SEC="${TIMER_SEC:-60}"          # watchdog cadence
JOURNAL_MAX="${JOURNAL_MAX:-200M}"     # journald disk cap 
JOURNAL_MAX_FILE="${JOURNAL_MAX_FILE:-20M}"
INSTALL_TOOLS="${INSTALL_TOOLS:-1}"   # 1=yes, 0=no
GW_MISS_MAX="${GW_MISS_MAX:-3}"
# ---- Reachability reboot watchdog defaults (Step 11) ----
REACH_NAME="${REACH_NAME:-net-reach}"
REACH_HOST1="${REACH_HOST1:-1.1.1.1}"
REACH_HOST2="${REACH_HOST2:-8.8.8.8}"
REACH_EVERY="${REACH_EVERY:-5m}"
REACH_FAIL_MAX="${REACH_FAIL_MAX:-12}"


need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

backup_if_exists() {
  local f="$1"
  if [[ -e "$f" ]]; then
    local b="${f}.BACKUP.$(date +%Y%m%d-%H%M%S)"
    cp -a "$f" "$b"
    echo "Backed up $f -> $b"
  fi
}

cat_as_root() { tee "$1" >/dev/null; chmod "${2:-0644}" "$1"; }

need_root

echo "==> 1) Base packages / updates"
export DEBIAN_FRONTEND=noninteractive

PKGS=(
  ca-certificates curl wget git nano htop lsof net-tools
  iproute2 iputils-ping tcpdump
  network-manager rfkill wireless-tools iw
  systemd-timesyncd unzip xz-utils
  bind9-dnsutils jq iftop iotop tmux vim
)

apt-get update -y
apt-get upgrade -y

if [[ "$INSTALL_TOOLS" == "1" ]]; then
   apt-get install -y "${PKGS[@]}"
fi

echo "==> 2) Ensure NetworkManager is enabled (Debian headless sometimes varies)"
systemctl enable --now NetworkManager

echo "==> 3) Disable Wi-Fi power saving via NetworkManager (prevents brcmfmac weirdness)"
mkdir -p /etc/NetworkManager/conf.d
backup_if_exists /etc/NetworkManager/conf.d/10-wifi-powersave.conf
cat <<'EOF' | cat_as_root /etc/NetworkManager/conf.d/10-wifi-powersave.conf 0644
[connection]
wifi.powersave = 2
EOF

echo "==> 4) Make journald persistent + cap disk usage (prevents runaway logs on flapping links)"
mkdir -p /etc/systemd/journald.conf.d
tee /etc/systemd/journald.conf.d/50-force-persistent.conf >/dev/null <<EOF
[Journal]
Storage=persistent
SystemMaxUse=${JOURNAL_MAX}
SystemMaxFileSize=${JOURNAL_MAX_FILE}
MaxRetentionSec=7day
Compress=yes
EOF

mkdir -p /var/log/journal
systemctl restart systemd-journald

echo "==> 5) Install congestion-aware network watchdog (no reconnect churn on upstream blips)"
backup_if_exists /usr/local/bin/net-watchdog.sh

cat <<'EOF' | cat_as_root /usr/local/bin/net-watchdog.sh 0755
#!/usr/bin/env bash
set -euo pipefail

TAG="net-watchdog"
IFACE="${IFACE:-wlan0}"

# Cooldown: avoid reconnect churn if we already reconnected recently
COOLDOWN_S="${COOLDOWN_S:-180}"
STATE_DIR="/run/net-watchdog"
LAST_RECONNECT_FILE="${STATE_DIR}/last_reconnect_epoch"

# GW miss tracking (avoid reconnect on a single transient “no default route”)
GW_MISS_FILE="${STATE_DIR}/gw_miss_count"
GW_MISS_MAX="${GW_MISS_MAX:-3}"

log() { logger -t "$TAG" "$*"; }
ts() { date -Is; }

get_gw() {
  ip -4 route show default dev "$IFACE" 2>/dev/null | awk '{print $3; exit}' || true
}

neigh_state() {
  local gw="$1"
  ip neigh show dev "$IFACE" to "$gw" 2>/dev/null | awk '{print $NF; exit}' || true
}

tcp_check() {
  local host="${1:-1.1.1.1}" port="${2:-443}" timeout_s="${3:-2}"
  timeout "$timeout_s" bash -lc "exec 3<>/dev/tcp/$host/$port" >/dev/null 2>&1
}

should_reconnect_now() {
  mkdir -p "$STATE_DIR"
  local now last=0
  now="$(date +%s)"
  if [[ -f "$LAST_RECONNECT_FILE" ]]; then
    last="$(cat "$LAST_RECONNECT_FILE" 2>/dev/null || echo 0)"
  fi
  [[ "$last" =~ ^[0-9]+$ ]] || last=0
  (( now - last >= COOLDOWN_S ))
}

mark_reconnect() {
  mkdir -p "$STATE_DIR"
  date +%s >"$LAST_RECONNECT_FILE" 2>/dev/null || true
}

nm_reconnect() {
  if ! should_reconnect_now; then
    log "$(ts) SKIP: reconnect cooldown active (${COOLDOWN_S}s)."
    return 0
  fi

  log "$(ts) ACTION: nmcli reconnect ${IFACE}"
  nmcli -t dev disconnect "$IFACE" >/dev/null 2>&1 || true
  sleep 2
  nmcli -t dev connect "$IFACE" >/dev/null 2>&1 || true
  mark_reconnect
}

nm_state() { 
  nmcli -t -f DEVICE,STATE dev status 2>/dev/null | 
    awk -F: -v d="$IFACE" '$1==d{print $2; exit}' 
}

inc_gw_miss() {
  mkdir -p "$STATE_DIR"
  local n=0
  [[ -f "$GW_MISS_FILE" ]] && n="$(cat "$GW_MISS_FILE" 2>/dev/null || echo 0)"
  [[ "$n" =~ ^[0-9]+$ ]] || n=0
  n=$((n+1))
  echo "$n" >"$GW_MISS_FILE" 2>/dev/null || true
  echo "$n"
}

reset_gw_miss() {
  rm -f "$GW_MISS_FILE" 2>/dev/null || true
}

main() {
  local gw gw_state GW_OK=0 EXT_OK=0 state=""

  state="$(nm_state || true)"
  if [[ "$state" == "connecting" || "$state" == "connected (getting IP configuration)" ]]; then
    log "$(ts) INFO: NM state=${state}; skipping checks this cycle."
    exit 0
  fi

  # NEW: If the interface isn't connected, don't do GW/neigh/tcp logic this cycle
  if ! nmcli -t -f DEVICE,STATE dev status 2>/dev/null | grep -q "^${IFACE}:connected"; then
    log "$(ts) INFO: ${IFACE} not connected; skipping."
    exit 0
  fi

  gw="$(get_gw)"
  if [[ -z "${gw}" ]]; then
    local misses
    misses="$(inc_gw_miss)"
    log "$(ts) WARN: no default gateway on ${IFACE} (miss ${misses}/${GW_MISS_MAX})."

    if (( misses >= GW_MISS_MAX )); then
      if ! tcp_check 1.1.1.1 443 2 && ! tcp_check 8.8.8.8 443 2; then
        log "$(ts) ACTION: gw missing ${misses}x and external check failing; reconnecting."
        nm_reconnect
      else
        log "$(ts) INFO: gw missing ${misses}x but external works; skipping reconnect."
      fi
    fi
    exit 0
  else
    reset_gw_miss
  fi

  gw_state="$(neigh_state "$gw")"

# NEW: If neighbor state is blank (e.g., transient ip neigh output), don't reconnect—just wait for next cycle
  if [[ -z "$gw_state" ]]; then
    log "$(ts) INFO: gw=${gw} neigh=NONE; deferring (no reconnect) this cycle."
    exit 0
  fi

  if [[ "$gw_state" == "REACHABLE" || "$gw_state" == "STALE" || "$gw_state" == "DELAY" || "$gw_state" == "PROBE" ]]; then
    GW_OK=1
  fi

  if tcp_check 1.1.1.1 443 2 || tcp_check 8.8.8.8 443 2; then
    EXT_OK=1
  fi

  if [[ "$GW_OK" -eq 0 ]]; then
    log "$(ts) FAIL: gw=${gw} neigh=${gw_state:-NONE} tcp=443 (GW_OK=0 EXT_OK=${EXT_OK})."
    nm_reconnect
    exit 0
  fi

  if [[ "$EXT_OK" -eq 0 ]]; then
    log "$(ts) CONGESTED: gw=${gw} neigh=${gw_state:-NONE} tcp=443 (GW_OK=1 EXT_OK=0). Action: none"
    exit 0
  fi

  log "$(ts) OK: gw=${gw} neigh=${gw_state:-NONE} tcp=443 (GW_OK=1 EXT_OK=1)"
}

main "$@"
EOF


echo "==> 6) systemd unit + timer for watchdog"
mkdir -p /etc/systemd/system

backup_if_exists /etc/systemd/system/net-watchdog.service
cat <<EOF | cat_as_root /etc/systemd/system/net-watchdog.service 0644
[Unit]
Description=Network watchdog (GW neighbor + external TCP check; congestion-aware)
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
Type=oneshot
TimeoutStartSec=15
Environment=IFACE=${IFACE}
Environment=COOLDOWN_S=${COOLDOWN_S}
Environment=GW_MISS_MAX=${GW_MISS_MAX}
ExecStart=/usr/local/bin/net-watchdog.sh
EOF

backup_if_exists /etc/systemd/system/net-watchdog.timer
cat <<EOF | cat_as_root /etc/systemd/system/net-watchdog.timer 0644
[Unit]
Description=Run network watchdog every ${TIMER_SEC}s

[Timer]
OnBootSec=30s
OnUnitActiveSec=${TIMER_SEC}s
AccuracySec=5s
Unit=net-watchdog.service

[Install]
WantedBy=timers.target
EOF

echo "==> 7) Apply changes"
systemctl daemon-reload
systemctl restart systemd-journald
# Restart NM so the powersave setting takes effect
systemctl restart NetworkManager
sleep 5
# Enable watchdog timer
systemctl enable --now net-watchdog.timer
systemctl start net-watchdog.service

echo "==> 8) Quick status snapshot"
echo "---- nmcli dev status ----"
nmcli -f DEVICE,TYPE,STATE,CONNECTION dev status || true
systemctl list-timers --all | grep -F net-watchdog || true
echo
echo "---- routes ----"
ip route || true
echo
echo "---- watchdog timer ----"
systemctl status net-watchdog.timer --no-pager || true
echo
echo "---- last watchdog logs (20) ----"
journalctl -t net-watchdog -n 20 --no-pager || true

echo
echo "DONE."
echo "Tip: watch live with: journalctl -f -t net-watchdog -u NetworkManager"

echo "==> 9) Install hardened service framework (/usr/local/lib/service-hardened.sh)"
mkdir -p /usr/local/lib /usr/local/bin
backup_if_exists /usr/local/lib/service-hardened.sh

cat <<'EOF' | cat_as_root /usr/local/lib/service-hardened.sh 0755
#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# service-hardened.sh
# Reusable framework to install hardened systemd services + timers
# Consistent with your setup style: backups, clean writes, journald logs
# ============================================================

backup_if_exists() {
  local f="$1"
  if [[ -e "$f" ]]; then
    local b="${f}.BACKUP.$(date +%Y%m%d-%H%M%S)"
    cp -a "$f" "$b"
    echo "Backed up $f -> $b"
  fi
}

cat_as_root() {
  local path="$1" mode="${2:-0644}"
  tee "$path" >/dev/null
  chmod "$mode" "$path"
}

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run as root: sudo $0 ..."; exit 1; }
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

DEFAULT_NICE="${DEFAULT_NICE:-5}"
DEFAULT_CPU_QUOTA="${DEFAULT_CPU_QUOTA:-30%}"
DEFAULT_MEM_MAX="${DEFAULT_MEM_MAX:-256M}"
DEFAULT_RESTART_SEC="${DEFAULT_RESTART_SEC:-10}"
DEFAULT_TIMEOUT_START="${DEFAULT_TIMEOUT_START:-20}"

install_hardened_service() {
  local app="${1:?APP_NAME required}"
  local execstart="${2:?ExecStart required}"

  local run_as="${RUN_AS:-root}"
  local workdir="${WORKDIR:-/}"
  local env_file="${ENV_FILE:-}"
  local cpu_quota="${CPU_QUOTA:-$DEFAULT_CPU_QUOTA}"
  local mem_max="${MEM_MAX:-$DEFAULT_MEM_MAX}"
  local nice="${NICE:-$DEFAULT_NICE}"
  local restart_sec="${RESTART_SEC:-$DEFAULT_RESTART_SEC}"
  local timeout_start="${TIMEOUT_START:-$DEFAULT_TIMEOUT_START}"

  local unit="/etc/systemd/system/${app}.service"
  backup_if_exists "$unit"

  {
    echo "[Unit]"
    echo "Description=${app} (hardened generic service)"
    echo "After=network-online.target NetworkManager.service"
    echo "Wants=network-online.target"
    echo "StartLimitIntervalSec=10min"
    echo "StartLimitBurst=5" 
    echo
    echo "[Service]"
    echo "Type=simple"
    echo "User=${run_as}"
    echo "StateDirectory=${app}"
    echo "StateDirectoryMode=0755"
    echo "WorkingDirectory=/var/lib/${app}"
    [[ -n "$env_file" ]] && echo "EnvironmentFile=${env_file}"
    echo "ExecStartPre=/usr/bin/test -x /bin/bash"
    echo "ExecStart=${execstart}"
    echo "Restart=on-failure"
    echo "RestartSec=${restart_sec}"
    echo "TimeoutStartSec=${timeout_start}"
    echo "TimeoutStopSec=30s" 
    echo
    echo "# Resource hardening"
    echo "Nice=${nice}"
    echo "CPUQuota=${cpu_quota}"
    echo "MemoryMax=${mem_max}"
    echo
    echo "# Safer defaults"
    echo "NoNewPrivileges=yes"
    echo "PrivateTmp=yes"
    echo "ProtectSystem=strict"
    echo "ProtectHome=true"
    echo "ProtectKernelTunables=yes"
    echo "ProtectKernelModules=yes"
    echo "ProtectControlGroups=yes"
    echo "LockPersonality=yes"
    echo "RestrictSUIDSGID=yes"
    echo "RestrictRealtime=yes"
    echo "RestrictNamespaces=yes"
    echo "SystemCallArchitectures=native"
    echo "SystemCallFilter=@system-service"
    echo
    echo "# Journald logging"
    echo "StandardOutput=journal"
    echo "StandardError=journal"
    echo "SyslogIdentifier=${app}"
    echo
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } | cat_as_root "$unit" 0644

  systemctl daemon-reload
  systemctl enable --now "${app}.service"
  systemctl restart "${app}.service" || true
  echo "Installed and enabled: ${app}.service"
}

install_periodic_restart_timer() {
  local app="${1:?APP_NAME required}"
  local every="${RESTART_EVERY:-6h}"

  # Keep existing naming convention for your worker node:
  # it-army-restart.service + it-army-restart.timer
  local svc="/etc/systemd/system/${app}-restart.service"
  local tmr="/etc/systemd/system/${app}-restart.timer"

  backup_if_exists "$svc"
  {
    echo "[Unit]"
    echo "Description=Controlled restart for ${app} (only if inactive)"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo "StartLimitIntervalSec=10min"
    echo "StartLimitBurst=3"
    echo
    echo "[Service]"
    echo "Type=oneshot"
    # Only restart if the service is not active -> avoids flapping a healthy worker
    echo "ExecStart=/bin/sh -c 'systemctl is-active --quiet ${app}.service || systemctl restart ${app}.service'"
  } | cat_as_root "$svc" 0644

  backup_if_exists "$tmr"
  {
    echo "[Unit]"
    echo "Description=Deadman check for ${app} every ${every} (restart only if inactive)"
    echo
    echo "[Timer]"
    echo "OnBootSec=${every}"
    echo "OnUnitActiveSec=${every}"
    echo "AccuracySec=1min"
    echo "RandomizedDelaySec=10min"
    echo "Unit=${app}-restart.service"
    echo
    echo "[Install]"
    echo "WantedBy=timers.target"
  } | cat_as_root "$tmr" 0644

  systemctl daemon-reload
  systemctl enable --now "${app}-restart.timer"
  echo "Enabled: ${app}-restart.timer"
}

install_heartbeat_timer() {
  local app="${1:?APP_NAME required}"
  local every="${HEARTBEAT_EVERY:-5m}"

  local svc="/etc/systemd/system/${app}-heartbeat.service"
  local tmr="/etc/systemd/system/${app}-heartbeat.timer"

  backup_if_exists "$svc"
  {
    echo "[Unit]"
    echo "Description=Heartbeat log for ${app}"
    echo
    echo "[Service]"
    echo "Type=oneshot"
    echo "ExecStart=/usr/bin/logger -t ${app} \"HEARTBEAT: alive (service=${app}.service)\""
  } | cat_as_root "$svc" 0644

  backup_if_exists "$tmr"
  {
    echo "[Unit]"
    echo "Description=Heartbeat for ${app} every ${every}"
    echo
    echo "[Timer]"
    echo "OnBootSec=${every}"
    echo "OnUnitActiveSec=${every}"
    echo "AccuracySec=30s"
    echo "Unit=${app}-heartbeat.service"
    echo
    echo "[Install]"
    echo "WantedBy=timers.target"
  } | cat_as_root "$tmr" 0644

  systemctl daemon-reload
  systemctl enable --now "${app}-heartbeat.timer"
  echo "Enabled: ${app}-heartbeat.timer"
}

enable_watchdog_stack() {
  local dev="${WATCHDOG_DEVICE:-/dev/watchdog}"
  local timeout="${WATCHDOG_TIMEOUT:-15}"

  if ! dpkg -s watchdog >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y watchdog
  fi

  backup_if_exists /etc/watchdog.conf
  {
    echo "# /etc/watchdog.conf - generated by service-hardened.sh"
    echo "watchdog-device = ${dev}"
    echo "watchdog-timeout = ${timeout}"
    echo
    echo "load-average = 24"
    echo "max-load-1 = 24"
    echo "max-load-5 = 16"
    echo "max-load-15 = 12"
    echo
    echo "ping = 1.1.1.1"
    echo "ping = 8.8.8.8"
    echo "ping-count = 3"
    echo "interface = wlan0"
  } | cat_as_root /etc/watchdog.conf 0644

  local cfg=""
  if [[ -f /boot/firmware/config.txt ]]; then
    cfg="/boot/firmware/config.txt"
  elif [[ -f /boot/config.txt ]]; then
    cfg="/boot/config.txt"
  fi

  if [[ -n "$cfg" ]]; then
    backup_if_exists "$cfg"
    if ! grep -qE '^\s*dtparam=watchdog=on\s*$' "$cfg"; then
      echo "" >>"$cfg"
      echo "# added by service-hardened.sh" >>"$cfg"
      echo "dtparam=watchdog=on" >>"$cfg"
    fi
  fi

  systemctl daemon-reload
  systemctl enable --now watchdog.service || true
  systemctl reset-failed watchdog.service || true
  systemctl try-restart watchdog.service || true
}

install_reachability_reboot_watchdog() {
  local name="${1:-net-reach}"
  local host1="${REACH_HOST1:-1.1.1.1}"
  local host2="${REACH_HOST2:-8.8.8.8}"
  local fail_max="${REACH_FAIL_MAX:-12}"
  local every="${REACH_EVERY:-5m}"

  local script="/usr/local/bin/${name}-watch.sh"
  local state_dir="/run/${name}"
  local fail_file="${state_dir}/failcount"

  backup_if_exists "$script"
  {
    echo "#!/usr/bin/env bash"
    echo "set -euo pipefail"
    echo "TAG=\"${name}\""
    echo "STATE_DIR=\"${state_dir}\""
    echo "FAIL_FILE=\"${fail_file}\""
    echo "FAIL_MAX=\"${fail_max}\""
    echo "H1=\"${host1}\""
    echo "H2=\"${host2}\""
    echo "mkdir -p \"\$STATE_DIR\""
    echo
    echo "ok=0"
    echo "ping -c1 -W2 \"\$H1\" >/dev/null 2>&1 && ok=1"
    echo "ping -c1 -W2 \"\$H2\" >/dev/null 2>&1 && ok=1"
    echo
    echo "if [[ \"\$ok\" -eq 1 ]]; then"
    echo "  rm -f \"\$FAIL_FILE\" 2>/dev/null || true"
    echo "  logger -t \"\$TAG\" \"OK: reachability good\""
    echo "  exit 0"
    echo "fi"
    echo
    echo "n=0"
    echo "[[ -f \"\$FAIL_FILE\" ]] && n=\$(cat \"\$FAIL_FILE\" 2>/dev/null || echo 0)"
    echo "[[ \"\$n\" =~ ^[0-9]+$ ]] || n=0"
    echo "n=\$((n+1))"
    echo "echo \"\$n\" >\"\$FAIL_FILE\" 2>/dev/null || true"
    echo "logger -t \"\$TAG\" \"FAIL: reachability down (count=\${n}/\${FAIL_MAX})\""
    echo
    echo "if (( n >= FAIL_MAX )); then"
    echo "  logger -t \"\$TAG\" \"ACTION: rebooting due to sustained reachability failure\""
    echo "  /sbin/reboot"
    echo "fi"
  } | cat_as_root "$script" 0755

  local svc="/etc/systemd/system/${name}.service"
  local tmr="/etc/systemd/system/${name}.timer"

  backup_if_exists "$svc"
  {
    echo "[Unit]"
    echo "Description=Network reachability reboot watchdog (${name})"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo
    echo "[Service]"
    echo "Type=oneshot"
    echo "ExecStart=${script}"
  } | cat_as_root "$svc" 0644

  backup_if_exists "$tmr"
  {
    echo "[Unit]"
    echo "Description=Run ${name} every ${every}"
    echo
    echo "[Timer]"
    echo "OnBootSec=${every}"
    echo "OnUnitActiveSec=${every}"
    echo "AccuracySec=30s"
    echo "Unit=${name}.service"
    echo
    echo "[Install]"
    echo "WantedBy=timers.target"
  } | cat_as_root "$tmr" 0644

  systemctl daemon-reload
  systemctl enable --now "${name}.timer"
}

enable_linger_for_user() {
  local user="${1:?username required}"
  if have_cmd loginctl; then
    loginctl enable-linger "$user"
  fi
}

usage() {
  cat <<USAGE
Usage:
  sudo service-hardened.sh install-service APP_NAME "ExecStart..."
  sudo service-hardened.sh install-restart-timer APP_NAME
  sudo service-hardened.sh install-heartbeat APP_NAME
  sudo service-hardened.sh enable-watchdog
  sudo service-hardened.sh install-reachability [NAME]
  sudo service-hardened.sh enable-linger USER
USAGE
}

main() {
  need_root
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    install-service) install_hardened_service "$@" ;;
    install-restart-timer) install_periodic_restart_timer "$@" ;;
    install-heartbeat) install_heartbeat_timer "$@" ;;
    enable-watchdog) enable_watchdog_stack ;;
    install-reachability) install_reachability_reboot_watchdog "${1:-net-reach}" ;;
    enable-linger) enable_linger_for_user "$@" ;;
    ""|help|-h|--help) usage ;;
    *) echo "Unknown command: $cmd"; usage; exit 2 ;;
  esac
}
main "$@"
EOF

ln -sf /usr/local/lib/service-hardened.sh /usr/local/bin/service-hardened.sh

echo "==> 10) Enable kernel watchdog stack (firmware + watchdog daemon + config)"
WATCHDOG_DEVICE="${WATCHDOG_DEVICE:-/dev/watchdog}" WATCHDOG_TIMEOUT="${WATCHDOG_TIMEOUT:-15}" \
  /usr/local/bin/service-hardened.sh enable-watchdog

echo "==> 11) Install network reachability reboot watchdog (timer-based)"
REACH_NAME="${REACH_NAME:-net-reach}" REACH_HOST1="${REACH_HOST1:-1.1.1.1}" REACH_HOST2="${REACH_HOST2:-8.8.8.8}" \
REACH_FAIL_MAX="${REACH_FAIL_MAX:-12}" REACH_EVERY="${REACH_EVERY:-5m}" \
  /usr/local/bin/service-hardened.sh install-reachability "${REACH_NAME}"

echo "==> 12) Install app package (optional .deb)"

if [[ -n "${APP_DEB_URL:-}" ]]; then
  tmp_deb="/tmp/$(basename "$APP_DEB_URL")"
  rm -f "$tmp_deb"
  curl -fsSL "$APP_DEB_URL" -o "$tmp_deb"
  dpkg -i "$tmp_deb" || apt-get -y -f install
else
  echo "Skipping .deb install (APP_DEB_URL not set)"
fi


echo "==> 13) Create start-it-army.sh"

cat <<'EOF' | cat_as_root /usr/local/bin/${START_SCRIPT} 0755
#!/usr/bin/env bash
set -euo pipefail

exec /etc/alternatives/itarmykit \
  --no-updates \
  --copies 1 \
  --threads 4032 \
  --lang en \
  --user-id 5272237815 \
  --disable-gpu \
  --no-sandbox
EOF

echo "==> 14) Install hardened app service (${APP_NAME})"
if [[ "${INSTALL_HARDENED_APP:-0}" == "1" ]]; then
  if [[ -z "${APP_NAME:-}" || -z "${APP_EXECSTART:-}" ]]; then
    echo "ERROR: INSTALL_HARDENED_APP=1 but APP_NAME or APP_EXECSTART is empty."
    exit 1
  fi
  RUN_AS="${APP_USER:-root}" WORKDIR="${APP_WORKDIR:-/}" \
  CPU_QUOTA="${APP_CPU_QUOTA:-30%}" MEM_MAX="${APP_MEM_MAX:-256M}" NICE="${APP_NICE:-5}" \
    /usr/local/bin/service-hardened.sh install-service "${APP_NAME}" "${APP_EXECSTART}"
else
  echo "Skipping hardened app service (INSTALL_HARDENED_APP=0)"
fi

echo "==> 15) Deadman restart ${APP_NAME} if inactive every 6 hours (timer)"
if [[ "${INSTALL_HARDENED_APP:-0}" == "1" ]]; then
  RESTART_EVERY="${APP_DEADMAN_EVERY:-6h}" \
    /usr/local/bin/service-hardened.sh install-restart-timer "${APP_NAME}"
fi

echo "==> 16) Heartbeat log for ${APP_NAME} every 5 minutes (timer)"
if [[ "${INSTALL_HARDENED_APP:-0}" == "1" ]]; then
  HEARTBEAT_EVERY="${APP_HEARTBEAT_EVERY:-5m}" \
    /usr/local/bin/service-hardened.sh install-heartbeat "${APP_NAME}"
fi

echo "==> 17) Restart it-army service now that ${START_SCRIPT} exists"
systemctl daemon-reload
systemctl restart it-army.service || true
systemctl status it-army.service --no-pager || true

