# pcdc26
Code Repo for PCDC 2026

## Blue Team Bash Scripts

This repository contains blue team defensive scripts and a CI/CD pipeline that automatically lints, tests, and smoke-runs every script inside a Linux container on every push and pull request.

### Repository Layout

```
.
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI/CD pipeline
├── scripts/                # Blue team bash scripts
│   ├── check_open_ports.sh       # Enumerate listening ports; alert on specific ones
│   ├── check_failed_logins.sh    # Detect brute-force via auth log analysis
│   ├── check_file_integrity.sh   # Generate / verify SHA-256 checksums
│   ├── check_processes.sh        # List processes; alert on suspicious names
│   └── check_crontabs.sh         # Enumerate all crontab entries
└── tests/                  # Bash test suite
    ├── test_helpers.sh             # Shared assert helpers
    ├── test_check_open_ports.sh
    ├── test_check_failed_logins.sh
    ├── test_check_file_integrity.sh
    ├── test_check_processes.sh
    └── test_check_crontabs.sh
```

### CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs three jobs inside an **Ubuntu 22.04 Linux container** on every push and pull request:

| Job | Description |
|-----|-------------|
| `shellcheck` | Lints all `scripts/` and `tests/` with [ShellCheck](https://www.shellcheck.net/) |
| `test` | Executes the full test suite in `tests/` |
| `smoke` | Smoke-runs every script end-to-end to confirm zero-error execution |

`test` and `smoke` jobs only run after `shellcheck` passes.

### Running Scripts Locally

Make the scripts executable, then call them directly:

```bash
chmod +x scripts/*.sh

# List all open ports
./scripts/check_open_ports.sh

# Alert if port 4444 is listening
./scripts/check_open_ports.sh --alert 4444

# Scan auth log for IPs with ≥10 failed logins
./scripts/check_failed_logins.sh --logfile /var/log/auth.log --threshold 10

# Generate checksums for /etc
./scripts/check_file_integrity.sh --generate --dir /etc --output /tmp/etc.sha256

# Verify /etc against saved checksums
./scripts/check_file_integrity.sh --verify --dir /etc --input /tmp/etc.sha256

# Alert if netcat is running
./scripts/check_processes.sh --suspicious nc

# Enumerate all crontabs
./scripts/check_crontabs.sh
```

### Running Tests Locally

```bash
chmod +x scripts/*.sh tests/*.sh

# Run all tests
for t in tests/test_check_*.sh; do bash "$t"; done
```

