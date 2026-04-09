# PCDC 2026 - Blue Team Toolkit 🛡️

This repository contains automated defense and auditing scripts for the South Carolina PCDC 2026 competition. All scripts are written in Bash and are automatically validated via GitHub Actions.

## 🛠️ Toolkit Overview

| Script | Purpose |
| :--- | :--- |
| `pcdc_linux_harden.sh` | Core OS hardening (SSH, sysctl, permissions). |
| `pcdc_linux_audit.sh` | Full system audit to find misconfigurations. |
| `pcdc_port_monitor_v2.sh` | Real-time monitoring of open ports and listeners. |
| `pcdc_alias_detector_v2.sh` | Scans for malicious aliases and shell hijacks. |
| `pcdc_privesc_detector.sh` | Checks for SUID bits and common priv-esc vectors. |
| `pcdc_linux_monitor.sh` | General system health and user activity logs. |
| `pcdc_webapp_audit.sh` | Scans web server configs (Apache/Nginx) for vulnerabilities. |
| `pcdc_incident_report.sh` | Generates a standardized report for competition points. |
| `pcdc_soceng_defense.sh` | Checks for common social engineering/phishing indicators. |
| `pcdc_runbook.sh` | The "Master" script to coordinate the response. |

## 📖 How to Use
1. Clone the repo: `git clone https://github.com`
2. Grant execution: `chmod +x *.sh`
3. Run the audit first: `sudo ./pcdc_linux_audit.sh`

