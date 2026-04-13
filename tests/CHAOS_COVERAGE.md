# Container Chaos Coverage Matrix

This matrix tracks what `tests/test_container_chaos.sh` validates in a disposable Ubuntu container.

## Assertion-tested (deterministic checks)

- `pcdc_scored_service_validate.sh`
  - Detects intentionally bad service config states (`sshd`, `nginx`, `vsftpd`)
- `pcdc_linux_audit.sh`
  - Surfaces a deliberately added rogue account (`rogueaudit`)
- `pcdc_alias_detector_v2.sh`
  - Flags `DEBUG` trap poisoning in `/root/.bashrc`
- `pcdc_webapp_audit.sh`
  - Flags webshell pattern + sensitive file in web root
- `pcdc_privesc_detector.sh`
  - Flags world-writable `/etc/passwd`
- `pcdc_incident_report.sh`
  - Generates report file from scripted answers
- `pcdc_soceng_defense.sh`
  - Exercises checklist pass path via scripted inputs
- `pcdc_network_enum.sh`
  - Runs a scripted minimal local flow and reaches completion output
- `pcdc_securityonion.sh status`
  - Validates missing-env guardrails (`SO_HOST not set`)
- `pcdc_recovery_check.sh`
  - Validates missing-hostfile guardrail path

## Smoke-tested (timeout / startup behavior)

- `pcdc_linux_monitor.sh`
- `pcdc_port_monitor.sh`
- `pcdc_port_monitor_v2.sh`
- `pcdc_runbook.sh status`
- `pcdc_linux_harden.sh`
- `pcdc_recovery_access.sh`
- `pcdc_ssh_validator.sh`
- `pcdc_admin_setup.sh`

These are validated as best-effort runtime starts (`rc` in `{0,1,124}`), because they are interactive, long-running, environment-dependent, or destructive by design.

## Out of scope for this harness

- `pcdc_competition_config.sh`
  - Source-only config library (validated via lint/syntax)

## Notes

- Container chaos is a high-value regression gate, but not a full substitute for real target-host validation.
- The harness intentionally separates deterministic assertions from smoke behavior to keep failures actionable.
