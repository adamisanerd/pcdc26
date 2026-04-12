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

Inside the container:

```bash
bt_help
bt_add_host root@10.0.1.10 "web"
bt_add_host root@10.0.1.11 "db"
bt_push_key_all "packetpassword"
```

### Option B: Install directly on Ubuntu admin box

Use this if Docker isn't available or you like living directly on the edge.

```bash
sudo bash pcdc_admin_setup.sh
source ~/.blueTeam_profile
bt_help
```

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

Then deploy recovery access immediately (do not procrastinate this one):

```bash
bt_run_covert pcdc_recovery_access.sh root@10.0.1.10
```

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

## 8) Where to go next

- Full architecture and script reference: [README.md](README.md)
- Linux orchestration: [pcdc_runbook.sh](pcdc_runbook.sh)
- Admin fleet functions: [blueTeam_profile](blueTeam_profile)
- CI/tests for utility scripts: [.github/workflows/ci.yml](.github/workflows/ci.yml)

May your logs be boring and your ports unsurprising.
