# ⚡ Astra 9 Blue Team Toolkit — Quick Start

### *"I cloned the repo. Now what?" edition*

This is the fastest path from `git clone` to **not losing your entire environment before lunch**.

If you're new here, run this first. Then go to [README.md](README.md) for the full doctrine, lore, and mild emotional support.

---

## 0) Scope & safety (60 seconds of maturity)

- Use this only on systems you own or are explicitly authorized to defend.
- These scripts can make real changes (accounts, firewall, services). They are not decorative.
- Keep one backup admin session open before hardening, unless you enjoy self-lockout speedruns.
- Do **not** block `192.168.40.0/24` (OOB) or `192.168.20.10` (scoring engine) without Gold Team approval.
- Do **not** modify/use the `goldteam` account.
- Injects and Incident Reports must be submitted from the Report Station and not AI-generated per packet rules.

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

## 3) Fastest path if you're already stabilized

If you're already enumerated, passwords are rotated, persistence/recovery is in place, and hardening is done, run this:

1. Start continuous monitoring on every host:
   - Linux: `pcdc_linux_monitor.sh 45`
   - Linux network: `pcdc_port_monitor_v2.sh --paranoid`
   - Windows: `pcdc_win_monitor.ps1 -Interval 45`
2. Every 30-45 minutes, run a sweep:
   - `pcdc_recovery_check.sh`
   - `pcdc_alias_detector_v2.sh`
   - `pcdc_webapp_audit.sh`
   - `pcdc_privesc_detector.sh`
3. On any high-confidence alert:
   - `pcdc_runbook.sh triage`
   - `pcdc_incident_report.sh`
   - `pcdc_soceng_defense.sh` (for suspicious inject/email requests)

That is the minimum loop to stay alive and keep points.

---

## 4) Fast bootstrap (if starting from scratch)

1. Build/run admin environment (`container_run.sh`) or run `pcdc_admin_setup.sh`.
2. Add hosts + push keys (`bt_add_host`, `bt_push_key_all`).
3. Update `pcdc_competition_config.sh`.
4. Deploy and verify recovery (`pcdc_recovery_access.sh` -> `pcdc_recovery_check.sh`).
5. Baseline then harden (`pcdc_network_enum.sh`, `pcdc_linux_audit.sh`, `pcdc_win_audit.ps1`, then hardening scripts).
6. Start the continuous loop in Section 3.

---

## 5) Guardrails (do not skip)

- Recovery access first. Hardening second.
- Baseline first. Anomaly loops second.
- Keep one backup admin session open during firewall/SSH changes.
- Verify scored services after every hardening change.
- Treat social-engineering injects as incidents until validated (`pcdc_soceng_defense.sh`).

---

## 6) Where to go next

- Full architecture and script reference: [README.md](README.md)
- Linux orchestration: [pcdc_runbook.sh](pcdc_runbook.sh)
- Admin fleet functions: [blueTeam_profile](blueTeam_profile)
- CI/tests for utility scripts: [.github/workflows/ci.yml](.github/workflows/ci.yml)

May your logs be boring and your ports unsurprising.
