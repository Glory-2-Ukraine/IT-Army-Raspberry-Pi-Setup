# IT Army Raspberry Pi Setup
## Context
This program install [Automatic DDoS Server Starter](https://github.com/it-army-ua-scripts/ADSS) in this document will be call as "worker".

The worker had been make by [IT Army of Ukraine](https://itarmy.com.ua/)

## Introduction
### What this repository is for?

This repository contains a single setup script intended to turn a Raspberry Pi into a stable, unattended worker node. The goal is not experimentation or desktop use. The goal is to run a long-lived process reliably on cheap hardware, over Wi-Fi, without babysitting it.

This exists because Raspberry Pis are excellent for this role, but out of the box they are fragile. Wi-Fi drops. Power management does strange things. Logs disappear after reboot. Services fail silently. A node that looks healthy can quietly stop doing useful work.

This script is my attempt to solve those problems in a way that is explicit, auditable, and reversible.

---

### What this script does at a high level?

When run on a supported Raspberry Pi, the script:
* Verifies it is running on real Pi hardware
* Installs a known set of base and operational packages
* Creates a consistent runtime layout on disk
* Installs and runs a worker binary under systemd
	•	Wraps that binary so it can be controlled cleanly
	•	Hardens the service using systemd features
	•	Makes logging persistent and bounded
	•	Disables Wi-Fi power saving to avoid silent stalls
	•	Adds multiple watchdog layers to recover from failures
	•	Produces clear status output at the end

The result is a Pi that can be powered on and left alone.

## Install
Run this as root on a supported Raspberry Pi OS or Debian-based Pi install:

```
curl -fsSL https://raw.githubusercontent.com/Glory-2-Ukraine/IT-Army-Raspberry-Pi-Setup/main/setup-pi.sh | sudo bash
```

> [!NOTE]
> The script is intentionally verbose. A normal run takes several minutes depending on network speed. At the end you should see confirmation that the main service is enabled and that watchdog timers are active.

---

### Requirements and assumptions

This script assumes:
* Real Raspberry Pi hardware
* Raspberry Pi OS or Debian Trixie-based install
* Systemd is the init system
* NetworkManager is present and used
* Wi-Fi or Ethernet connectivity
* Root access via sudo or direct root

> [!WARNING]
> The script will refuse to run if it does not detect Raspberry Pi hardware. This is intentional.

---

### Safety notes

- This script makes real system changes. Before running it, you should understand the following:
	- Systemd unit files are created under /etc/systemd/system
	- NetworkManager configuration is modified
	- Journald is switched to persistent storage
	- Kernel watchdog support may be enabled
	- Watchdog and timer services are installed

- Any file that is modified by this script is backed up first with a timestamped suffix.

- State directories under /var/lib are preserved by default. They are only deleted if you explicitly set WIPE_STATE=1.

- This script is written to be re-runnable. It attempts to tear down its own previous installs before rebuilding.

---

### Configuration overview

Most configuration is done through variables defined near the top of the script.

**In general:**
* You should change variables related to the worker binary, user ID, thread counts, and resource limits.
* You should not change watchdog logic or hardening defaults unless you understand systemd well.

**Configuration is in three places after install:**
* ```/etc/default``` for environment variables
* ```/usr/local/bin``` for wrapper and helper scripts
* ```/etc/systemd/system``` for unit and timer files

> [!NOTE]
> All the files are plain text and intended to be inspected.

---

### Files and directories created or modified
Common paths used by this script include:
* ```/usr/local/bin``` Wrapper scripts and watchdog helpers
* ```/usr/local/lib``` Shared hardening framework script
* ```/etc/systemd/system``` Service units and timers
* ```/etc/default``` Environment file for the worker
* ```/var/lib/APP_NAME``` Persistent state directory
* ```/run/APP_NAME``` Runtime directory created by systemd
* ```/var/log/journal``` Persistent system logs

> [!NOTE]
> Backups are created alongside existing files before modification.

## How the script runs, step by step
1.	Confirms it is running as root on Raspberry Pi hardware
2.	Optionally tears down previous installs of its own services
3.	Installs base system packages
4.	Creates the worker configuration file
5.	Creates an environment file for the worker
6.	Creates a wrapper script that systemd will execute
7.	Ensures NetworkManager is enabled
8.	Disables Wi-Fi power saving
9.	Makes journald persistent and caps disk usage
10.	Installs a congestion-aware network watchdog
11.	Installs and enables the watchdog timer
12.	Installs the service hardening framework
13.	Enables the kernel watchdog stack
14.	Installs a reachability reboot watchdog
15.	Downloads and installs the worker binary
16.	Installs the hardened systemd service
17.	Installs deadman restart and heartbeat timers
18.	Verifies service state and prints recent logs

> [!NOTE]
> Each step is logged to stdout.

## Design decisions and rationale

### Why systemd only?

Systemd provides dependency management, restart control, resource limits, sandboxing, and logging in one place. Using cron or custom loops makes failure modes harder to reason about.

### Why a wrapper script exists?

The wrapper decouples systemd from the worker binary. It allows environment variables, logging, and command changes without editing the unit file.

### Why NetworkManager is required?

NetworkManager exposes consistent state and control across Wi-Fi hardware. Tools like ifupdown are too limited for robust recovery logic.

### Why Wi-Fi power saving is disabled?

Power saving frequently causes silent stalls on Broadcom Wi-Fi chipsets. Throughput looks fine until it does not. Disabling it trades a small amount of power for reliability.

### Why journald is persistent?

When debugging long-running systems, losing logs on reboot is unacceptable. Disk usage is capped to prevent runaway growth.

### Why multiple watchdog layers exist?

No single watchdog catches all failure modes. This design layers:
* Service restart on failure
* Periodic deadman checks
* Network-level reconnect logic
* Full reboot only as a last resort

### Why hardening is applied gradually?

Overly strict hardening breaks real workloads. The defaults here are conservative and were adjusted based on observed failures.

## Useful commands after installation

### Check service status

```
systemctl status mhddos_proxy_linux.service
```

### View logs

```
journalctl -u mhddos_proxy_linux.service
```

### Follow logs live

```
journalctl -f -u mhddos_proxy_linux.service
```

### Restart the worker

```
sudo systemctl restart mhddos_proxy_linux.service
```

### Check timers

```
systemctl list-timers
```

### Re-run the setup safely

```
sudo ./setup-pi.sh
```

## Troubleshooting

### Service runs manually but not under systemd

This usually means WorkingDirectory, permissions, or environment variables differ. Check the wrapper script and the EnvironmentFile entry.

### Failed at step CHDIR

The WorkingDirectory configured in the service does not exist or is not a directory. Fix the APP_WORKDIR variable and rerun the script.

### Start request repeated too quickly

The service is crashing repeatedly. Check logs, then temporarily disable Restart to debug.

### Network looks connected but no traffic

This is usually Wi-Fi power saving or upstream congestion. Check net-watchdog logs.

### Logs disappear after reboot

journald persistence was not enabled or /var/log/journal was missing. Re-run step 7.

### Arch Linux and non-Debian systems

> [!WARNING]
> This script is written for Debian-based systems.

It relies on:
* apt
* Debian filesystem layout
* NetworkManager paths
* systemd defaults used by Raspberry Pi OS

> [!IMPORTANT]
> It will not run correctly on Arch Linux without modification.

Concepts that carry over cleanly:
* systemd service structure
* wrapper pattern
* watchdog layering
* journald configuration

Parts that would need rewriting:
* package installation
* NetworkManager configuration paths
* watchdog package handling

> [!TIP]
> If you are running Arch on a Pi, I recommend using this script as a reference, not running it directly.

## Uninstall and rollback

To disable everything installed by this script:

1. ```sudo systemctl disable mhddos_proxy_linux.service```
2. ```sudo systemctl stop mhddos_proxy_linux.service```
3. ```sudo rm -f /etc/systemd/system/mhddos_proxy_linux.service```
4. ```sudo systemctl daemon-reload```

> [!IMPORTANT]
> You may also remove timers, wrapper scripts, and state directories if desired. Backup files remain for manual restoration.

## Appendix A: Function reference
* **teardown_previous_install** Stops, disables, masks, and removes previously installed units created by this script.
* **need_root** Ensures the script is running as root.
* **is_raspberry_pi** Detects Raspberry Pi hardware via device tree.
* **pi_guard** Aborts execution if hardware is not a Pi.
* **backup_if_exists** Creates timestamped backups of files before modification.
* **cat_as_root** Writes files atomically with correct permissions.
* **net-watchdog.sh** Monitors gateway, neighbor state, and external reachability and reconnects conservatively.
* **service-hardened.sh** Shared framework for installing hardened systemd services and timers.

## Appendix B: Variable reference
* **APP_NAME** Name of the systemd service and state directories.
* **APP_USER** User account under which the worker runs.
* **APP_EXECSTART** Path to the wrapper script executed by systemd.
* **APP_WORKDIR** Working directory for the service.
* **APP_ENV_FILE** Environment file sourced by the wrapper.
* **APP_CPU_QUOTA** CPU limit enforced by systemd.
* **APP_MEM_MAX** Memory limit enforced by systemd.
* **ITARMY_BIN** Path to the worker binary.
* **ITARMY_USER_ID** Identifier passed to the worker.
* **ITARMY_THREADS** Thread count for the worker.
* **JOURNAL_MAX** Maximum disk usage for journald.
* **IFACE** Network interface to monitor.
* **COOLDOWN_S** Minimum seconds between reconnect attempts.
* **REACH_FAIL_MAX** Failures before reboot is triggered.

## Appendix C: Scope and philosophy

This script is not a general-purpose provisioning tool. It is intentionally opinionated. It favors clarity over cleverness and explicit systemd configuration over abstraction.

Every choice here exists because something broke before.

If you are comfortable reading the code, you should. That is the point.
