#!/usr/bin/env bash
# test_check_failed_logins.sh - Tests for check_failed_logins.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_helpers.sh
source "$SCRIPT_DIR/test_helpers.sh"

SCRIPT="$SCRIPT_DIR/../scripts/check_failed_logins.sh"

echo "Running tests for check_failed_logins.sh"

# --- Fixture: create a fake auth log ---
TMPDIR_FIXTURE="$(mktemp -d)"
FAKE_LOG="$TMPDIR_FIXTURE/auth.log"

cat > "$FAKE_LOG" <<'EOF'
Apr  9 10:01:01 host sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 54321 ssh2
Apr  9 10:01:02 host sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 54322 ssh2
Apr  9 10:01:03 host sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 54323 ssh2
Apr  9 10:01:04 host sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 54324 ssh2
Apr  9 10:01:05 host sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 54325 ssh2
Apr  9 10:01:06 host sshd[1235]: Failed password for root from 192.168.1.50 port 9999 ssh2
Apr  9 10:01:07 host sshd[1235]: Accepted password for bob from 10.0.0.2 port 22222 ssh2
EOF

# --- Test 1: script is executable ---
if [[ -x "$SCRIPT" ]]; then
    pass "script is executable"
else
    fail "script is not executable"
fi

# --- Test 2: detects IPs exceeding threshold ---
OUTPUT="$(bash "$SCRIPT" --logfile "$FAKE_LOG" --threshold 3 2>&1)"
STATUS=$?
assert_exit "exits 0 on success" 0 "$STATUS"
assert_output_contains "detects high-count IP" "10\.0\.0\.1" "$OUTPUT"

# --- Test 3: threshold filters out low-count IPs ---
OUTPUT="$(bash "$SCRIPT" --logfile "$FAKE_LOG" --threshold 3 2>&1)"
assert_output_not_contains "omits low-count IP" "192\.168\.1\.50" "$OUTPUT"

# --- Test 4: missing logfile exits 1 ---
bash "$SCRIPT" --logfile "/nonexistent/auth.log" 2>&1 || STATUS=$?
assert_exit "missing logfile exits 1" 1 "$STATUS"

# --- Test 5: unknown flag exits 1 ---
bash "$SCRIPT" --bad-flag 2>&1 || STATUS=$?
assert_exit "unknown flag exits 1" 1 "$STATUS"

# --- Cleanup ---
rm -rf "$TMPDIR_FIXTURE"

print_summary "check_failed_logins"
