# ⚡ Astra 9 Blue Team Toolkit — Quick Start

### *"I cloned the repo. Now what?" edition*

This is the fastest path from `git clone` to **not losing your entire environment before lunch**.

If you're new here, run this first. Then go to [README.md](README.md) for the full doctrine, lore, and mild emotional support.

---

## 0) Scope & safety (60 seconds of maturity)

- Use this only on systems you own or are explicitly authorized to defend.
- These scripts can make real changes (accounts, firewall, services). They are not decorative.
- Keep one backup admin session open before hardening, unless you enjoy self-lockout speedruns.

---

## 1) Pull the repo

```bash
git clone https://github.com/adamisanerd/pcdc26.git
cd pcdc26
```

You have now entered the asteroid.

---

## 2) Choose your operator environment

### Option A (recommended): Containerized admin workstation

Because "it worked on my laptop" is not an incident response strategy.

```bash
bash container_run.sh build
bash container_run.sh run
```

Reference: these commands are handled by `container_run.sh` (which builds/runs using `Dockerfile`, `docker-compose.yml`, and `entrypoint.sh`).

Inside the container:

```bash
bt_help
bt_add_host root@10.0.1.10 "web"
bt_add_host root@10.0.1.11 "db"
bt_push_key_all "packetpassword"
```

Reference: all `bt_*` commands are shell functions defined in `blueTeam_profile`.

### Option B: Install directly on Ubuntu admin box

Use this if Docker isn't available or you like living directly on the edge.

```bash
sudo bash pcdc_admin_setup.sh
source ~/.blueTeam_profile
bt_help
```

Reference: `pcdc_admin_setup.sh` installs/admin-preps your environment; `source ~/.blueTeam_profile` loads the `bt_*` function wrappers from `blueTeam_profile`.

---

## 3) First 15 minutes on Linux targets (the golden window)

This is the part where you secure things **before** the red team starts shopping in your infrastructure.

From your admin machine/container, run this on each Linux host:

```bash
bt_run_covert pcdc_linux_audit.sh root@10.0.1.10
bt_run_covert pcdc_linux_harden.sh root@10.0.1.10
bt_run_covert pcdc_alias_detector_v2.sh root@10.0.1.10
bt_run_covert pcdc_webapp_audit.sh root@10.0.1.10
bt_run_covert pcdc_privesc_detector.sh root@10.0.1.10
```

Reference: `bt_run_covert` (from `blueTeam_profile`) is the transport wrapper; each `pcdc_*.sh` argument is the actual script executed on the target.

Then deploy recovery access immediately (do not procrastinate this one):

```bash
bt_run_covert pcdc_recovery_access.sh root@10.0.1.10
```

Reference: same wrapper pattern — `bt_run_covert` from `blueTeam_profile`, target logic in `pcdc_recovery_access.sh`.

Repeat for all hosts, or use `bt_run_all` once your hosts list is ready.

---

## 4) Start continuous monitoring

On each Linux target (interactive terminal on the host):

```bash
sudo /bin/bash pcdc_linux_monitor.sh 45
sudo /bin/bash pcdc_port_monitor_v2.sh --paranoid
```

From admin machine, verify recovery health every ~30 minutes:

```bash
bash pcdc_recovery_check.sh
```

If this says recovery is broken, fix it now — not during active compromise theater.

---

## 5) Windows quick start

Run in elevated PowerShell on each Windows host:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\pcdc_win_audit.ps1
.\pcdc_win_harden.ps1
.\pcdc_win_monitor.ps1 -Interval 45 -Services "w3svc","dns"
```

If there is a Domain Controller in your packet, do this too:

```powershell
Import-Module ActiveDirectory
.\pcdc_win_ad_audit.ps1
```

Because if AD falls, everything else is just a sad side quest.

---

## 6) Incident response when things get spicy

Compromise detected on Linux?

```bash
sudo /bin/bash pcdc_runbook.sh triage
```

Generate report for point recovery / documentation:

```bash
sudo bash pcdc_incident_report.sh
```

Suspicious inject/request shows up with fake urgency and vibes?

```bash
bash pcdc_soceng_defense.sh
```

---

## 7) Operating rhythm (a.k.a. how to not drift into chaos)

- Every host: monitoring loops running.
- Every ~30 min: alias/web/privesc checks + recovery check.
- Every alert: contain, document, report.
- Keep scored services alive first; do archaeology second.

---

## 8) Full tool matrix (what runs when, and in what order)

Use this as your competition-day checklist so every script has a home.

### 8.1 Pre-game / setup once (before scoring starts)

- `pcdc_admin_setup.sh` — one-time setup on Linux admin box.
- `blueTeam_profile` — source once per shell/session for `bt_*` functions.
- `container_run.sh`, `Dockerfile`, `docker-compose.yml`, `entrypoint.sh` — if running the containerized operator environment.
- `pcdc_competition_config.sh` — review/update team identity, infra trust, and service list before heavy monitoring.
- `tmux.conf` — optional, but useful for persistent monitoring panes.

### 8.2 Opening sprint (first 15–30 minutes per Linux host)

Run in this order:

1. `pcdc_linux_audit.sh`
2. `pcdc_linux_harden.sh`
3. `pcdc_alias_detector_v2.sh` (or `pcdc_alias_detector.sh` if needed)
4. `pcdc_webapp_audit.sh`
5. `pcdc_privesc_detector.sh`
6. `pcdc_recovery_access.sh` (do not skip)

Then baseline visibility:

7. `pcdc_network_enum.sh`

### 8.3 Start continuous defenders (keep running)

On Linux targets:

- `pcdc_linux_monitor.sh` — continuous host checks (every N seconds).
- `pcdc_port_monitor_v2.sh` — continuous network/connection anomaly checks.
- `pcdc_port_monitor.sh` — optional fallback/simple monitor.

On Windows targets:

- `pcdc_win_monitor.ps1` — continuous Windows monitoring loop.

### 8.4 Periodic cadence (every ~30 minutes or on each sweep)

- `pcdc_recovery_check.sh` — verify backdoor-resistant recovery access.
- `pcdc_alias_detector_v2.sh` — recheck command tampering.
- `pcdc_webapp_audit.sh` — recheck web exposure/config drift.
- `pcdc_privesc_detector.sh` — recheck local privilege-escalation paths.
- `pcdc_network_enum.sh` — re-baseline hosts/services after changes.

### 8.5 Triggered / incident-only tools

- `pcdc_runbook.sh triage` — immediate IR triage workflow.
- `pcdc_incident_report.sh` — evidence/report package for recovery/scoring narratives.
- `pcdc_soceng_defense.sh` — suspicious inject/email/social request validation.
- `pcdc_recovery_access.sh` — rerun if accounts/keys are modified during incident.
- `pcdc_recovery_check.sh` — rerun immediately after remediation.

### 8.6 Windows hardening/audit sequence (per host)

Run in this order:

1. `pcdc_win_audit.ps1`
2. `pcdc_win_harden.ps1`
3. `pcdc_win_monitor.ps1`
4. `pcdc_win_ad_audit.ps1` (only where AD/DC scope exists)

### 8.7 Utility/test scripts (operator confidence, not target hardening)

- `scripts/check_open_ports.sh`
- `scripts/check_failed_logins.sh`
- `scripts/check_file_integrity.sh`
- `scripts/check_processes.sh`
- `scripts/check_crontabs.sh`
- `tests/*.sh` for validation in CI/local test runs

These are primarily for validation/automation support and are exercised by CI.

---

## 9) Where to go next

- Full architecture and script reference: [README.md](README.md)
- Linux orchestration: [pcdc_runbook.sh](pcdc_runbook.sh)
- Admin fleet functions: [blueTeam_profile](blueTeam_profile)
- CI/tests for utility scripts: [.github/workflows/ci.yml](.github/workflows/ci.yml)

May your logs be boring and your ports unsurprising.
