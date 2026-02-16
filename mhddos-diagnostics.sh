#!/usr/bin/env bash
set -euo pipefail

#
# run with
# sudo bash -c "curl -sSL https://raw.githubusercontent.com/Glory-2-Ukraine/IT-Army-Raspberry-Pi-Setup/refs/heads/main/mhddos-diagnostics.sh | tee /usr/local/bin/mhddos-diagnostics.sh >/dev/null && chmod +x /usr/local/bin/mhddos-diagnostics.sh && echo 'Diagnostic script installed successfully'"
#

# =========================
# MHDDOS DIAGNOSTIC SCRIPT
# Run this AFTER your main script to collect QA data
# =========================

# Create output directory
OUTPUT_DIR="/var/log/mhddos/diagnostics"
mkdir -p "$OUTPUT_DIR"
echo "=== MHDDOS DIAGNOSTICS $(date -Is) ===" > "$OUTPUT_DIR/diagnostics.log"

# 1. System Information
echo -e "\n[SYSTEM INFO]" >> "$OUTPUT_DIR/diagnostics.log"
uname -a >> "$OUTPUT_DIR/diagnostics.log"
cat /etc/os-release >> "$OUTPUT_DIR/diagnostics.log"
uptime >> "$OUTPUT_DIR/diagnostics.log"

# 2. CPU Status
echo -e "\n[CPU STATUS]" >> "$OUTPUT_DIR/diagnostics.log"
cat /proc/cpuinfo | grep -E "model name|MHz|governor" >> "$OUTPUT_DIR/diagnostics.log"
for i in {0..3}; do
    echo "CPU$i: $(cat /sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor) $(cat /sys/devices/system/cpu/cpu$i/cpufreq/scaling_max_freq 2>/dev/null || echo 'N/A')" >> "$OUTPUT_DIR/diagnostics.log"
done

# 3. Network Interface Status
echo -e "\n[NETWORK STATUS]" >> "$OUTPUT_DIR/diagnostics.log"
ip -o link show >> "$OUTPUT_DIR/diagnostics.log"
iwconfig 2>/dev/null >> "$OUTPUT_DIR/diagnostics.log"
echo "WiFi Power Save: $(iw dev wlan0 get power_save 2>/dev/null || echo 'N/A')" >> "$OUTPUT_DIR/diagnostics.log"
echo "WiFi Power Save: $(iw dev wlan1 get power_save 2>/dev/null || echo 'N/A')" >> "$OUTPUT_DIR/diagnostics.log"

# 4. Power Optimization Status
echo -e "\n[POWER OPTIMIZATIONS]" >> "$OUTPUT_DIR/diagnostics.log"
echo "Bluetooth: $(rfkill list bluetooth 2>/dev/null | grep -c "Soft blocked: yes" || echo 'N/A')" >> "$OUTPUT_DIR/diagnostics.log"
echo "HDMI: $(vcgencmd display_power 2>/dev/null || echo 'N/A')" >> "$OUTPUT_DIR/diagnostics.log"
echo "LEDs: $(cat /sys/class/leds/led0/trigger 2>/dev/null || echo 'N/A')" >> "$OUTPUT_DIR/diagnostics.log"
echo "USB Auto-Suspend: $(ls /sys/bus/usb/devices/*/power/control 2>/dev/null | head -1 | xargs cat 2>/dev/null || echo 'N/A')" >> "$OUTPUT_DIR/diagnostics.log"
echo "ZSwap: $(cat /sys/module/zswap/parameters/enabled 2>/dev/null || echo 'N/A')" >> "$OUTPUT_DIR/diagnostics.log"
echo "Swappiness: $(sysctl vm.swappiness | awk '{print $3}')" >> "$OUTPUT_DIR/diagnostics.log"

# 5. MHDDOS Process Status
echo -e "\n[MHDDOS PROCESS]" >> "$OUTPUT_DIR/diagnostics.log"
pgrep -a mhddos_proxy_linux >> "$OUTPUT_DIR/diagnostics.log" || echo "MHDDOS not running"
ps aux | grep -i mhddos >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "No MHDDOS processes"

# 6. Service Status
echo -e "\n[SERVICE STATUS]" >> "$OUTPUT_DIR/diagnostics.log"
systemctl status mhddos_proxy_linux --no-pager >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "Service not found"
systemctl status resource-monitor --no-pager >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "Monitor not found"
systemctl status crash-protection --no-pager >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "Crash protection not found"

# 7. Log Samples
echo -e "\n[LOG SAMPLES]" >> "$OUTPUT_DIR/diagnostics.log"
echo "=== Resource Monitor Log ===" >> "$OUTPUT_DIR/diagnostics.log"
tail -n 10 /var/log/mhddos/resource-monitor.log >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "No resource monitor log"
echo "=== Crash Protection Log ===" >> "$OUTPUT_DIR/diagnostics.log"
tail -n 10 /var/log/mhddos/crash-protection.log >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "No crash protection log"

# 8. QoS Rules
echo -e "\n[QOS RULES]" >> "$OUTPUT_DIR/diagnostics.log"
tc -s qdisc show >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "No QoS rules"
tc -s class show dev wlan0 >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "No wlan0 QoS"
tc -s class show dev wlan1 >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "No wlan1 QoS"

# 9. System Metrics
echo -e "\n[SYSTEM METRICS]" >> "$OUTPUT_DIR/diagnostics.log"
top -bn1 | head -10 >> "$OUTPUT_DIR/diagnostics.log"
free -h >> "$OUTPUT_DIR/diagnostics.log"
df -h >> "$OUTPUT_DIR/diagnostics.log"
cat /sys/class/thermal/thermal_zone0/temp >> "$OUTPUT_DIR/diagnostics.log"

# 10. Configuration Files
echo -e "\n[CONFIGURATION FILES]" >> "$OUTPUT_DIR/diagnostics.log"
echo "=== mhddos.ini ===" >> "$OUTPUT_DIR/diagnostics.log"
cat /opt/itarmy/bin/mhddos.ini >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "No mhddos.ini"
echo "=== sysctl.conf ===" >> "$OUTPUT_DIR/diagnostics.log"
grep -v "^#" /etc/sysctl.conf | grep -v "^$" >> "$OUTPUT_DIR/diagnostics.log" 2>/dev/null || echo "No sysctl settings"

# Create a tar.gz of all logs for easy transfer
tar -czvf "$OUTPUT_DIR/diagnostics-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$OUTPUT_DIR" .

echo "Diagnostics completed. Output files:"
echo "1. $OUTPUT_DIR/diagnostics.log"
echo "2. $OUTPUT_DIR/diagnostics-$(date +%Y%m%d-%H%M%S).tar.gz"
echo ""
echo "To share for QA:"
echo "scp $OUTPUT_DIR/diagnostics-*.tar.gz user@remote:/path/to/destination"
