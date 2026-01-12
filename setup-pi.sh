#!/usr/bin/env bash
set -euo pipefail

teardown_previous_install() {
  echo "==> Teardown: stop/disable/remove prior units (if present)"

  # 1) Stop active units (won't error if not running)
  sudo systemctl stop mhddos_proxy_linux.service 2>/dev/null || true
  sudo systemctl stop mhddos_proxy_linux-heartbeat.timer mhddos_proxy_linux-restart.timer 2>/dev/null || true
  sudo systemctl stop mhddos_proxy_linux-heartbeat.service mhddos_proxy_linux-restart.service 2>/dev/null || true
  sudo systemctl stop net-watchdog.timer net-watchdog.service 2>/dev/null || true
  sudo systemctl disable net-watchdog.timer 2>/dev/null || true
  sudo rm -f /etc/systemd/system/net-watchdog.service /etc/systemd/system/net-watchdog.timer
  sudo rm -f /usr/local/bin/net-watchdog.sh

  sudo systemctl list-unit-files | awk '{print $1}' \
    | grep -Ei '^mhddos_proxy_linux(\.|-).*(service|timer)$|^mhddos_proxy_linux\.service$' \
    | while read -r u; do                                                                                                                    
        sudo systemctl stop "$u" 2>/dev/null || true                                                                                         
        sudo systemctl disable "$u" 2>/dev/null || true                                                                                      
      done                                                                                                                                   
                                                                                                                                             
  # 2) Disable autostart                                                                                                                     
  sudo systemctl disable mhddos_proxy_linux.service 2>/dev/null || true                                                                      
  sudo systemctl disable mhddos_proxy_linux-heartbeat.timer mhddos_proxy_linux-restart.timer 2>/dev/null || true                             
                                                                                                                                             
  # 3) Mask to prevent manual start while we’re removing files                                                                               
  sudo systemctl mask mhddos_proxy_linux.service 2>/dev/null || true                                                                         
  sudo systemctl mask mhddos_proxy_linux-heartbeat.timer mhddos_proxy_linux-restart.timer 2>/dev/null || true

  # 4) Remove unit files + drop-ins (yours are in /etc/systemd/system)
  sudo rm -f /etc/systemd/system/mhddos_proxy_linux.service
  sudo rm -rf /etc/systemd/system/mhddos_proxy_linux.service.d

  sudo rm -f /etc/systemd/system/mhddos_proxy_linux-heartbeat.service
  sudo rm -f /etc/systemd/system/mhddos_proxy_linux-restart.service
  sudo rm -f /etc/systemd/system/mhddos_proxy_linux-heartbeat.timer
  sudo rm -f /etc/systemd/system/mhddos_proxy_linux-restart.timer

  # 5) Reload systemd and clear fail counters
  sudo systemctl daemon-reload
  sudo systemctl reset-failed

  # 6) Unmask (optional) if you want future installs to be able to recreate/start cleanly
  sudo systemctl unmask mhddos_proxy_linux.service 2>/dev/null || true
  sudo systemctl unmask mhddos_proxy_linux-heartbeat.timer mhddos_proxy_linux-restart.timer 2>/dev/null || true
  sudo systemctl daemon-reload
  
  # 7) Remove env file (optional). Keeping it is usually fine, but stale values can bite you.
  if [[ "${WIPE_ENV:-0}" == "1" ]]; then
    echo "WIPE_ENV=1 set; deleting /etc//mhddos_proxy_linux"
    sudo rm -f /etc/default/mhddos_proxy_linux
  else
    echo "Keeping env file /etc//mhddos_proxy_linux (WIPE_ENV=0)"
  fi

  # 8) Remove state/log/runtime directories if YOU created them and it’s safe to wipe
  # (StateDirectory=mhddos_proxy_linux => /var/lib/mhddos_proxy_linux)
  # Keep state by  (often includes useful history).
  # If you want a true clean wipe, run with WIPE_STATE=1
  if [[ "${WIPE_STATE:-0}" == "1" ]]; then
    echo "WIPE_STATE=1 set; deleting /var/lib/mhddos_proxy_linux"
    sudo rm -rf /var/lib/mhddos_proxy_linux
  else
    echo "Keeping state in /var/lib/mhddos_proxy_linux (WIPE_STATE=0)"
  fi

  # /run is tmpfs; it resets on reboot anyway, but remove if it exists
  sudo rm -rf /run/mhddos_proxy_linux

  echo "==> Teardown complete"
}


# =========================
# Fresh Debian Trixie Pi setup (headless-friendly)
# Focus: stable networking + sane logging + basic tooling
# =========================

# ---- Tunables (edit if you want) ----
INSTALL_HARDENED_APP=1
APP_NAME="mhddos_proxy_linux"
APP_USER="pi"

START_SCRIPT="${APP_NAME}-worker.sh"
APP_EXECSTART="/usr/local/bin/${START_SCRIPT}"
APP_ENV_FILE="/etc/default/${APP_NAME}"

APP_WORKDIR=""

APP_CPU_QUOTA="20%"
APP_MEM_MAX="160M"
APP_NICE="19"
APP_DEADMAN_EVERY="6h"
APP_HEARTBEAT_EVERY="5m"
#APP_DEB_URL="${APP_DEB_URL:-https://github.com/it-army-ua-scripts/ITARMYkit/releases/latest/download/ITARMYkit-linux-arm64.deb}"
IFACE="${IFACE:-wlan0}"
COOLDOWN_S="${COOLDOWN_S:-180}"       # reconnect cooldown
TIMER_SEC="${TIMER_SEC:-60}"          # watchdog cadence
JOURNAL_MAX="${JOURNAL_MAX:-200M}"     # journald disk cap 
JOURNAL_MAX_FILE="${JOURNAL_MAX_FILE:-20M}"
INSTALL_TOOLS="${INSTALL_TOOLS:-1}"   # 1=yes, 0=no
GW_MISS_MAX="${GW_MISS_MAX:-3}"
# ---- Reachability reboot watchdog s (Step 11) ----
REACH_NAME="${REACH_NAME:-net-reach}"
REACH_HOST1="${REACH_HOST1:-1.1.1.1}"
REACH_HOST2="${REACH_HOST2:-8.8.8.8}"
REACH_EVERY="${REACH_EVERY:-5m}"
REACH_FAIL_MAX="${REACH_FAIL_MAX:-12}"
# ---- ITARMY installer + runtime ----
ITARMY_INSTALL_URL="${ITARMY_INSTALL_URL:-https://raw.githubusercontent.com/it-army-ua-scripts/ADSS/install/install.sh}"
ITARMY_INSTALLER_PATH="${ITARMY_INSTALLER_PATH:-/opt/itarmy/bin/}"
ITARMY_BIN="${ITARMY_BIN:-/opt/itarmy/bin/mhddos_proxy_linux}"
ITARMY_LANG="${ITARMY_LANG:-en}"
# ITARMY_USER_ID="${ITARMY_USER_ID:-5272237815}"
ITARMY_USER_ID="${ITARMY_USER_ID:-NTI3MjIzNzgxNQ==}"
ITARMY_COPIES="${ITARMY_COPIES:-1}"
ITARMY_THREADS="${ITARMY_THREADS:-512}"


need_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }; }

is_raspberry_pi() {
  local model=""
  if [[ -r /proc/device-tree/model ]]; then
    model="$(tr -d '\0' </proc/device-tree/model || true)"
  fi
  [[ "$model" == *"Raspberry Pi"* ]]
}

pi_guard() {
  if ! is_raspberry_pi; then
    echo "ERROR: This setup script is intended ONLY for Raspberry Pi hardware."
    echo "Detected model: $(tr -d '\0' </proc/device-tree/model 2>/dev/null || echo 'UNKNOWN')"
    echo "Aborting to avoid changing networking/systemd settings on a non-Pi host."
    exit 2
  fi
  echo "OK: Raspberry Pi detected: $(tr -d '\0' </proc/device-tree/model)"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

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
  chown root:root "$path"
  chmod "$mode" "$path"
}

need_root
pi_guard
#teardown_previous_install

mkdir -p "/var/lib/${APP_NAME}"
id "${APP_USER}" >/dev/null 2>&1 || { echo "ERROR: user ${APP_USER} does not exist"; exit 4; }
chown "${APP_USER}:${APP_USER}" "/var/lib/${APP_NAME}"

echo "==> 1) Base packages / updates"
export DEBIAN_FRONTEND=noninteractive

PKGS_MINIMAL=(
  ca-certificates curl
  iproute2 iputils-ping
  network-manager
)

PKGS_OPS=(
  wget git nano htop lsof net-tools
  tcpdump glances
  rfkill wireless-tools iw
  systemd-timesyncd unzip xz-utils
  bind9-dnsutils jq iftop iotop tmux vim
)

apt-get update -y
apt-get upgrade -y

apt-get install -y "${PKGS_MINIMAL[@]}"

if [[ "${INSTALL_TOOLS}" == "1" ]]; then
  apt-get install -y "${PKGS_OPS[@]}"
fi

echo "==> 1.2) Disable swap to prevent VM thrash"

# If dphys-swapfile exists (older Raspberry Pi OS images), stop/disable it.
if command -v dphys-swapfile >/dev/null 2>&1; then
  dphys-swapfile swapoff || true
fi
if systemctl list-unit-files | awk '{print $1}' | grep -qx 'dphys-swapfile.service'; then
  systemctl disable --now dphys-swapfile.service 2>/dev/null || true
fi

# Always: turn off any active swap immediately.
swapoff -a 2>/dev/null || true

# Always: prevent swap from coming back via /etc/fstab (idempotent).
if [[ -f /etc/fstab ]]; then
  cp -a /etc/fstab "/etc/fstab.BACKUP.$(date +%Y%m%d-%H%M%S)"
  sed -i -E 's@^([^#].*\s+swap\s+.*)$@# disabled by setup-pi.sh: \1@' /etc/fstab
fi


echo "==> 1.5) SSH service priority (systemd drop-in)"
mkdir -p /etc/systemd/system/ssh.service.d /etc/systemd/system/sshd.service.d

cat >/etc/systemd/system/ssh.service.d/10-priority.conf <<'EOF'
[Service]
CPUWeight=1000
IOWeight=1000
Nice=-5
EOF

systemctl daemon-reload
systemctl try-restart ssh.service 2>/dev/null || true
systemctl try-restart sshd.service 2>/dev/null || true


echo "==> 2) Create mhddos.ini in user home directory"

INI_PATH="/home/${SUDO_USER:-${USER}}/mhddos.ini"

cat <<'EOF' > "${INI_PATH}"
# Змінити мову | Change language (ua | en | es | de | pl | lt)
lang = en

# Запуск декількох копій (auto для максимального значення, потрібно 3+ ядер процесору та стабільний інтернет)
# Run multiple copies (set "auto" for max value, requires 3+ core CPU and stable network)
copies = 1

# Кількість потоків на 1 копію | Number of threads per copy
# Для активації приберіть символ # | Remove the # symbol to enable 
threads = $(printf '%s' "$ITARMY_THREADS" | base64 -d)   

# Атака через мій IP у % від 0 до 100 (обов'язковий VPN чи віддалений сервер)
# Use my IP for the attack in % from 0 to 100 (requires VPN or remote server)
use-my-ip = 0

user-id = $(printf '%s' "$ITARMY_USER_ID" | base64 -d)

EOF

chown "${SUDO_USER:-${USER}}":"${SUDO_USER:-${USER}}" "${INI_PATH}"
chmod 0644 "${INI_PATH}"
mkdir -p /opt/itarmy/bin
cp "/home/${SUDO_USER:-${USER}}/mhddos.ini" /opt/itarmy/bin/



echo "==> 3) Create environment file for ${APP_NAME}"
echo
echo "cat <<EOF | cat_as_root ${APP_ENV_FILE} 0644"

cat <<EOF | cat_as_root "${APP_ENV_FILE}" 0644
# Environment for ${APP_NAME}.service
# Put the real long-running command here.
# Example:
# WORKER_CMD="/opt/itarmy/bin/mhddos_proxy_linux"
WORKER_CMD="${ITARMY_BIN}"
EOF

echo "==> 4) Create worker wrapper (${START_SCRIPT})"
backup_if_exists "${APP_EXECSTART}"

cat <<'EOF' | cat_as_root "${APP_EXECSTART}" 0755
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/default/mhddos_proxy_linux"
if [[ -r "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi

: "${WORKER_CMD:?WORKER_CMD is not set. Set WORKER_CMD in ${ENV_FILE}}"

echo "Starting: ${WORKER_CMD}" | systemd-cat -t mhddos_proxy_linux
#exec "${WORKER_CMD}"

exec "${WORKER_CMD}"


EOF

echo "==> 5) Ensure NetworkManager is enabled (Debian headless sometimes varies)"
systemctl enable --now NetworkManager

echo "==> 6) Disable Wi-Fi power saving via NetworkManager (prevents brcmfmac weirdness)"
mkdir -p /etc/NetworkManager/conf.d
backup_if_exists /etc/NetworkManager/conf.d/10-wifi-powersave.conf
cat <<'EOF' | cat_as_root /etc/NetworkManager/conf.d/10-wifi-powersave.conf 0644
[connection]
wifi.powersave = 2
EOF

echo "==> 6.1) Fix netplan file permissions (NetworkManager warns if readable by others)"
if [[ -f /lib/netplan/00-network-manager-all.yaml ]]; then
  chmod 600 /lib/netplan/00-network-manager-all.yaml
  chown root:root /lib/netplan/00-network-manager-all.yaml
fi

echo "==> 7) Make journald persistent + cap disk usage (prevents runaway logs on flapping links)"
mkdir -p /etc/systemd/journald.conf.d

tee /etc/systemd/journald.conf.d/50-force-persistent.conf >/dev/null <<EOF
[Journal]
Storage=persistent
SystemMaxUse=${JOURNAL_MAX}
SystemMaxFileSize=${JOURNAL_MAX_FILE}
#MaxRetentionSec=7day
Compress=yes
RateLimitIntervalSec=30s
RateLimitBurst=2000

EOF

mkdir -p /var/log/journal
systemctl restart systemd-journald

echo "==> 8) Install congestion-aware network watchdog (no reconnect churn on upstream blips)"
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

# GW miss tracking (avoid reconnect on a single transient “no  route”)
GW_MISS_FILE="${STATE_DIR}/gw_miss_count"
GW_MISS_MAX="${GW_MISS_MAX:-3}"

log() { logger -t "$TAG" "$*"; }
ts() { date -Is; }

get_gw() {
  ip -4 route show  dev "$IFACE" 2>/dev/null | awk '{print $3; exit}' || true
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
    log "$(ts) WARN: no  gateway on ${IFACE} (miss ${misses}/${GW_MISS_MAX})."

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


echo "==> 9) systemd unit + timer for watchdog"
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

echo "==> 10) Apply changes"
systemctl daemon-reload
systemctl restart systemd-journald
# Restart NM so the powersave setting takes effect
systemctl try-restart NetworkManager || true
sleep 2

# Enable watchdog timer
systemctl enable --now net-watchdog.timer
systemctl start net-watchdog.service

echo "==> 10.4) Ensure ifb0 exists at boot (systemd oneshot)"
cat >/etc/systemd/system/ifb0-setup.service <<'EOF'
[Unit]
Description=Create ifb0 for ingress shaping (idempotent)
After=systemd-modules-load.service
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'modprobe ifb; ip link show ifb0 >/dev/null 2>&1 || ip link add ifb0 type ifb; ip link set ifb0 up'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ifb0-setup.service

echo "==> 10.5) Install tc QoS script (persisted via systemd)"

cat <<'EOF' | cat_as_root /usr/local/sbin/tc-ssh-qos.sh 0755
#!/usr/bin/env bash
set -euo pipefail

IFACE="${IFACE:-wlan0}"
LAN_SSH_CLIENT="${LAN_SSH_CLIENT:-192.168.1.113}"

modprobe ifb >/dev/null 2>&1 || true
ip link show ifb0 >/dev/null 2>&1 || ip link add ifb0 type ifb
ip link set ifb0 up

tc qdisc del dev "$IFACE" root 2>/dev/null || true
tc qdisc del dev "$IFACE" ingress 2>/dev/null || true
tc qdisc del dev ifb0 root 2>/dev/null || true

tc qdisc add dev "$IFACE" root handle 1: htb default 30
tc class add dev "$IFACE" parent 1: classid 1:10 htb rate 5mbit ceil 20mbit prio 0
tc qdisc add dev "$IFACE" parent 1:10 handle 110: fq_codel
tc class add dev "$IFACE" parent 1: classid 1:20 htb rate 256kbit ceil 2mbit prio 7
tc qdisc add dev "$IFACE" parent 1:20 handle 120: fq_codel
tc class add dev "$IFACE" parent 1: classid 1:30 htb rate 2mbit ceil 20mbit prio 3
tc qdisc add dev "$IFACE" parent 1:30 handle 130: fq_codel

# SSH: LAN-only (do NOT match global port 22)
tc filter add dev "$IFACE" protocol ip parent 1: prio 1 u32 \
  match ip src ${LAN_SSH_CLIENT}/32 match ip dport 22 0xffff flowid 1:10
tc filter add dev "$IFACE" protocol ip parent 1: prio 1 u32 \
  match ip dst ${LAN_SSH_CLIENT}/32 match ip sport 22 0xffff flowid 1:10

# Deprioritize fwmark 1
tc filter add dev "$IFACE" protocol ip parent 1: prio 2 handle 1 fw flowid 1:20

tc qdisc add dev "$IFACE" handle ffff: ingress
tc filter add dev "$IFACE" parent ffff: protocol ip u32 match u32 0 0 action mirred egress redirect dev ifb0

tc qdisc add dev ifb0 root handle 2: htb default 30
tc class add dev ifb0 parent 2: classid 2:10 htb rate 5mbit ceil 20mbit prio 0
tc qdisc add dev ifb0 parent 2:10 handle 210: fq_codel
tc class add dev ifb0 parent 2: classid 2:20 htb rate 256kbit ceil 2mbit prio 7
tc qdisc add dev ifb0 parent 2:20 handle 220: fq_codel
tc class add dev ifb0 parent 2: classid 2:30 htb rate 2mbit ceil 20mbit prio 3
tc qdisc add dev ifb0 parent 2:30 handle 230: fq_codel

tc filter add dev ifb0 protocol ip parent 2: prio 1 u32 \
  match ip src ${LAN_SSH_CLIENT}/32 match ip dport 22 0xffff flowid 2:10
tc filter add dev ifb0 protocol ip parent 2: prio 1 u32 \
  match ip dst ${LAN_SSH_CLIENT}/32 match ip sport 22 0xffff flowid 2:10

tc filter add dev ifb0 protocol ip parent 2: prio 2 handle 1 fw flowid 2:20 || true
EOF

echo "==> 10.6) systemd unit to apply tc QoS after network-online"

cat <<EOF | cat_as_root /etc/systemd/system/tc-ssh-qos.service 0644
[Unit]
Description=Apply tc QoS for LAN SSH
After=network-online.target NetworkManager.service ifb0-setup.service
Wants=network-online.target ifb0-setup.service

[Service]
Type=oneshot
Environment=IFACE=${IFACE}
Environment=LAN_SSH_CLIENT=192.168.1.113
ExecStart=/usr/local/sbin/tc-ssh-qos.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now tc-ssh-qos.service

echo "==> 11) Quick status snapshot"
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

echo "==> 12) Install hardened service framework (/usr/local/lib/service-hardened.sh)"
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

DEFAULT_RESTART_SEC="${DEFAULT_RESTART_SEC:-15}"
DEFAULT_TIMEOUT_START="${_TIMEOUT_START:-20}"

install_hardened_service() {
  local app="${1:?APP_NAME required}"
  local execstart="${2:?ExecStart required}"

  local run_as="${RUN_AS:-root}"
  local workdir="${WORKDIR:-/var/lib/${app}}"
  local env_file="${ENV_FILE:-}"
  : "${CPU_QUOTA:?CPU_QUOTA is required (set in setup-pi.sh tunables)}"
  : "${MEM_MAX:?MEM_MAX is required (set in setup-pi.sh tunables)}"
  : "${NICE:?NICE is required (set in setup-pi.sh tunables)}"

  local cpu_quota="${CPU_QUOTA}"
  local mem_max="${MEM_MAX}"
  local nice="${NICE}"
  local restart_sec="${RESTART_SEC:-$DEFAULT_RESTART_SEC}"
  local timeout_start="${TIMEOUT_START:-$_TIMEOUT_START}"

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
    echo "RuntimeDirectory=${app}"
    echo "RuntimeDirectoryMode=0755"
    echo "WorkingDirectory=${workdir}"
    [[ -n "$env_file" ]] && echo "EnvironmentFile=${env_file}"
    echo "ExecStart=${execstart}"
    echo "Restart=on-failure"
    echo "RestartSec=${restart_sec}"
    echo "TimeoutStartSec=${timeout_start}"
    echo "TimeoutStopSec=30s" 
    echo
    echo "# Resource hardening"
    echo "Nice=${nice}"
    echo "CPUSchedulingPolicy=idle"
    echo "CPUQuota=${cpu_quota}"
    echo "MemoryAccounting=yes"
    echo "MemoryMax=${mem_max}"
    echo "CPUWeight=1"
    echo "IOAccounting=yes"
    echo "IOWeight=1"
    echo
    echo "# Safer s"
    echo "NoNewPrivileges=yes"
    echo "PrivateTmp=yes"
    echo "ProtectSystem=strict"
    echo "ProtectHome=read only"
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

echo "==> 13) Enable kernel watchdog stack (firmware + watchdog daemon + config)"
WATCHDOG_DEVICE="${WATCHDOG_DEVICE:-/dev/watchdog}" WATCHDOG_TIMEOUT="${WATCHDOG_TIMEOUT:-15}" \
  /usr/local/bin/service-hardened.sh enable-watchdog
systemctl unmask watchdog.service 2>/dev/null || true
systemctl daemon-reload
systemctl enable watchdog.service 2>/dev/null || true
systemctl restart watchdog.service 2>/dev/null || true


echo "==> 14) Install network reachability reboot watchdog (timer-based)"
REACH_NAME="${REACH_NAME:-net-reach}" REACH_HOST1="${REACH_HOST1:-1.1.1.1}" REACH_HOST2="${REACH_HOST2:-8.8.8.8}" \
REACH_FAIL_MAX="${REACH_FAIL_MAX:-12}" REACH_EVERY="${REACH_EVERY:-5m}" \
  /usr/local/bin/service-hardened.sh install-reachability "${REACH_NAME}"

# echo "==> 15) Install app package (optional .deb)"
#
#if [[ -n "${APP_DEB_URL:-}" ]]; then
#  tmp_deb="/tmp/$(basename "$APP_DEB_URL")"
#  rm -f "$tmp_deb"
#  curl -fsSL "$APP_DEB_URL" -o "$tmp_deb"
#  dpkg -i "$tmp_deb" || apt-get -y -f install
#else
#  echo "Skipping .deb install (APP_DEB_URL not set)"
#fi

echo "==> 16) Install ADSS (download installer, then run it)"
# curl -sL https://raw.githubusercontent.com/it-army-ua-scripts/ADSS/install/install.sh  | bash -s
echo "Files in ${ITARMY_INSTALLER_PATH}."
echo
ls -la "${ITARMY_INSTALLER_PATH}"
echo
#rm -f "${ITARMY_INSTALLER_PATH}"
echo
echo "Installing from ${ITARMY_INSTALL_URL}"
if ! curl -fsSL "${ITARMY_INSTALL_URL}" | bash -s; then
    echo "[-] ERROR: Installer failed. Check the output above."
    exit 1
fi

#echo
#echo "==> 16.1) Verify installer laid down expected directories/files"
#echo
#if [[ ! -d /opt/itarmy/utils ]] || ! command -v update_adss >/dev/null 2>&1; then
#  echo "[-] WARNING: ADSS installer did not lay down expected files (/opt/itarmy/utils, update_adss)."
#  echo "[-] WARNING: Continuing without ADSS. Node setup is otherwise complete."
#  # do NOT exit; do NOT return non-zero
#else
#  echo "[+] ADSS layout looks OK."
#fi

#echo
#echo "==> 16.2) Verify expected binary exists"
#echo
#if [[ ! -x "${ITARMY_BIN}" ]]; then
#  echo "[-] WARNING: Expected binary not found or not executable: ${ITARMY_BIN}"
#  echo "[-] WARNING: Skipping app service install steps (17+) because ADSS did not install."
#  echo "Contents of ${ITARMY_INSTALLER_PATH}:"
#  ls -la "${ITARMY_INSTALLER_PATH}" || true
#  exit 0
#fi
echo "[+] OK: Found executable: ${ITARMY_BIN}"

# Ensure WorkingDirectory matches where the real binary lives
APP_WORKDIR="$(dirname "${ITARMY_BIN}")"
if [[ ! -d "${APP_WORKDIR}" ]]; then
  echo "ERROR: APP_WORKDIR is not a directory: ${APP_WORKDIR}"
  exit 3
fi
echo "OK: APP_WORKDIR=${APP_WORKDIR}"

echo "==> 17) Install hardened app service (${APP_NAME})"
if [[ "${INSTALL_HARDENED_APP:-0}" == "1" ]]; then
    RUN_AS="${APP_USER:-root}" WORKDIR="${APP_WORKDIR}" ENV_FILE="${APP_ENV_FILE}" \
    CPU_QUOTA="${APP_CPU_QUOTA}" MEM_MAX="${APP_MEM_MAX}" NICE="${APP_NICE}" \
      /usr/local/bin/service-hardened.sh install-service "${APP_NAME}" "${APP_EXECSTART}"
else
    echo "Skipping hardened app service (INSTALL_HARDENED_APP=0)"
fi

echo "==> 18) Deadman restart ${APP_NAME} if inactive every 6 hours (timer)"
if [[ "${INSTALL_HARDENED_APP:-0}" == "1" ]]; then
  RESTART_EVERY="${APP_DEADMAN_EVERY:-6h}" \
    /usr/local/bin/service-hardened.sh install-restart-timer "${APP_NAME}"
fi

echo "==> 19) Heartbeat log for ${APP_NAME} every 5 minutes (timer)"
if [[ "${INSTALL_HARDENED_APP:-0}" == "1" ]]; then
  HEARTBEAT_EVERY="${APP_HEARTBEAT_EVERY:-5m}" \
    /usr/local/bin/service-hardened.sh install-heartbeat "${APP_NAME}"
fi

echo "==> 20) Verify ${APP_NAME} service is enabled and running"
systemctl is-enabled "${APP_NAME}.service" --quiet && echo "OK: enabled" || echo "WARN: not enabled"
systemctl is-active  "${APP_NAME}.service" --quiet && echo "OK: active"  || echo "WARN: not active"
journalctl -u "${APP_NAME}.service" -n 50 --no-pager || true

echo "==> 21) Install resource monitor + auto-adjuster for ${APP_NAME}"

# --- Create resource-monitor.sh ---

cat <<'MONITOR_SCRIPT' | cat_as_root /usr/local/bin/resource-monitor.sh 0755
#!/usr/bin/env bash
set -euo pipefail

# oneshot; timer triggers it

SERVICE_NAME="${SERVICE_NAME:-}"
THRESHOLD_CPU="${THRESHOLD_CPU:-85}"
THRESHOLD_MEM="${THRESHOLD_MEM:-90}"

log() { logger -t resource-monitor "$*"; }

cpu_usage() {
  local idle
  idle="$(top -bn1 | awk -F',' '/Cpu\(s\)/{print $4}' | awk '{print $1}' | tr -d '%id' || echo 0)"
  awk -v idle="$idle" 'BEGIN{printf "%d\n", (100 - idle)}'
}

mem_usage() {
  awk '/Mem:/ {printf "%d\n", ($3/$2)*100}' < <(free -m)
}

cpu="$(cpu_usage)"
mem="$(mem_usage)"
log "CPU=${cpu}% MEM=${mem}%"

if [[ -n "${SERVICE_NAME}" ]]; then
  if (( cpu > THRESHOLD_CPU || mem > THRESHOLD_MEM )); then
    log "THRESHOLD exceeded; restarting ${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}" || true
  fi
fi
MONITOR_SCRIPT


# --- Create systemd service ---
echo "==> 21.1) Install systemd unit for resource monitor"
cat <<'MONITOR_SERVICE' | cat_as_root /etc/systemd/system/resource-monitor.service 0644
[Unit]
Description=Resource Monitor (oneshot)
After=network-online.target

[Service]
Type=oneshot
User=root
Environment=THRESHOLD_CPU=85
Environment=THRESHOLD_MEM=90
Environment=SERVICE_NAME=
ExecStart=/usr/local/bin/resource-monitor.sh

MONITOR_SERVICE

# --- Create systemd timer ---
echo "==> 21.2) Install systemd timer for resource monitor"
cat <<'MONITOR_TIMER' | cat_as_root /etc/systemd/system/resource-monitor.timer 0644
[Unit]
Description=Run resource monitor every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=5s
Unit=resource-monitor.service

[Install]
WantedBy=timers.target
MONITOR_TIMER

# --- Enable and start ---
echo "==> 21.3) Enable and start resource monitor"
systemctl daemon-reload
systemctl enable --now resource-monitor.timer

