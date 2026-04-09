#!/usr/bin/env bash
# test_check_open_ports.sh - Tests for check_open_ports.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_helpers.sh
source "$SCRIPT_DIR/test_helpers.sh"

SCRIPT="$SCRIPT_DIR/../scripts/check_open_ports.sh"

echo "Running tests for check_open_ports.sh"

# --- Test 1: script is executable ---
if [[ -x "$SCRIPT" ]]; then
    pass "script is executable"
else
    fail "script is not executable"
fi

# --- Test 2: basic run exits 0 (no alert port) ---
OUTPUT="$(bash "$SCRIPT" 2>&1)"
STATUS=$?
assert_exit "no-args run exits 0" 0 "$STATUS"

# --- Test 3: output contains expected header ---
assert_output_contains "output contains port header" "Open Listening Ports" "$OUTPUT"

# --- Test 4: unknown flag exits non-zero ---
bash "$SCRIPT" --unknown-flag 2>&1 || STATUS=$?
assert_exit "unknown flag exits non-zero" 1 "$STATUS"

# --- Test 5: --alert for a non-listening high port exits 0 ---
# Port 19999 is almost certainly not in use inside a CI container
OUTPUT="$(bash "$SCRIPT" --alert 19999 2>&1)"
STATUS=$?
assert_exit "--alert for free port exits 0" 0 "$STATUS"
assert_output_contains "--alert free port prints OK" "OK:" "$OUTPUT"

print_summary "check_open_ports"
