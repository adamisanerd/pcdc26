#!/usr/bin/env bash
# test_check_crontabs.sh - Tests for check_crontabs.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_helpers.sh
source "$SCRIPT_DIR/test_helpers.sh"

SCRIPT="$SCRIPT_DIR/../scripts/check_crontabs.sh"

echo "Running tests for check_crontabs.sh"

# --- Test 1: script is executable ---
if [[ -x "$SCRIPT" ]]; then
    pass "script is executable"
else
    fail "script is not executable"
fi

# --- Test 2: basic run exits 0 ---
OUTPUT="$(bash "$SCRIPT" 2>&1)"
STATUS=$?
assert_exit "script exits 0" 0 "$STATUS"

# --- Test 3: output mentions system cron directories ---
assert_output_contains "output lists cron directories" "cron" "$OUTPUT"

# --- Test 4: output contains scan complete message ---
assert_output_contains "output has completion message" "scan complete" "$OUTPUT"

print_summary "check_crontabs"
