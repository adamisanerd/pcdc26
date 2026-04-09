#!/usr/bin/env bash
# test_check_processes.sh - Tests for check_processes.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_helpers.sh
source "$SCRIPT_DIR/test_helpers.sh"

SCRIPT="$SCRIPT_DIR/../scripts/check_processes.sh"

echo "Running tests for check_processes.sh"

# --- Test 1: script is executable ---
if [[ -x "$SCRIPT" ]]; then
    pass "script is executable"
else
    fail "script is not executable"
fi

# --- Test 2: basic run exits 0 ---
OUTPUT="$(bash "$SCRIPT" 2>&1)"
STATUS=$?
assert_exit "no-args run exits 0" 0 "$STATUS"

# --- Test 3: output contains process table header context ---
assert_output_contains "output has process info" "Running Processes" "$OUTPUT"

# --- Test 4: --suspicious for a process that definitely isn't running exits 0 ---
OUTPUT="$(bash "$SCRIPT" --suspicious "definitely_not_a_real_process_xyz987" 2>&1)"
STATUS=$?
assert_exit "--suspicious for absent process exits 0" 0 "$STATUS"
assert_output_contains "--suspicious absent shows OK" "OK:" "$OUTPUT"

# --- Test 5: --suspicious detects a running process (bash itself) ---
OUTPUT="$(bash "$SCRIPT" --suspicious "bash" 2>&1)" || STATUS=$?
# bash is running the tests, so pgrep should find it -> exit 2
assert_exit "--suspicious for running process exits 2" 2 "$STATUS"
assert_output_contains "--suspicious found shows ALERT" "ALERT" "$OUTPUT"

# --- Test 6: unknown flag exits 1 ---
bash "$SCRIPT" --unknown 2>&1 || STATUS=$?
assert_exit "unknown flag exits 1" 1 "$STATUS"

print_summary "check_processes"
