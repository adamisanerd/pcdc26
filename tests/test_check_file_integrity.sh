#!/usr/bin/env bash
# test_check_file_integrity.sh - Tests for check_file_integrity.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test_helpers.sh
source "$SCRIPT_DIR/test_helpers.sh"

SCRIPT="$SCRIPT_DIR/../scripts/check_file_integrity.sh"

echo "Running tests for check_file_integrity.sh"

# --- Fixture setup ---
TMPDIR_FIXTURE="$(mktemp -d)"
MONITORED_DIR="$TMPDIR_FIXTURE/monitored"
CHECKSUM_FILE="$TMPDIR_FIXTURE/checksums.sha256"

mkdir -p "$MONITORED_DIR"
echo "hello world" > "$MONITORED_DIR/file1.txt"
echo "blue team"   > "$MONITORED_DIR/file2.txt"

# --- Test 1: script is executable ---
if [[ -x "$SCRIPT" ]]; then
    pass "script is executable"
else
    fail "script is not executable"
fi

# --- Test 2: generate mode creates checksum file ---
OUTPUT="$(bash "$SCRIPT" --generate --dir "$MONITORED_DIR" --output "$CHECKSUM_FILE" 2>&1)"
STATUS=$?
assert_exit "generate exits 0" 0 "$STATUS"
if [[ -f "$CHECKSUM_FILE" ]]; then
    pass "checksum file created"
else
    fail "checksum file not created"
fi
assert_output_contains "generate reports output file" "Checksums written to" "$OUTPUT"

# --- Test 3: verify mode passes on unmodified files ---
OUTPUT="$(bash "$SCRIPT" --verify --dir "$MONITORED_DIR" --input "$CHECKSUM_FILE" 2>&1)"
STATUS=$?
assert_exit "verify exits 0 on clean dir" 0 "$STATUS"
assert_output_contains "verify reports OK" "OK:" "$OUTPUT"

# --- Test 4: verify mode detects a modified file ---
echo "tampered" > "$MONITORED_DIR/file1.txt"
OUTPUT="$(bash "$SCRIPT" --verify --dir "$MONITORED_DIR" --input "$CHECKSUM_FILE" 2>&1)" || STATUS=$?
assert_exit "verify exits 2 on tampered file" 2 "$STATUS"
assert_output_contains "verify reports MODIFIED" "MODIFIED" "$OUTPUT"

# --- Test 5: verify mode detects a missing file ---
rm "$MONITORED_DIR/file2.txt"
OUTPUT="$(bash "$SCRIPT" --verify --dir "$MONITORED_DIR" --input "$CHECKSUM_FILE" 2>&1)" || STATUS=$?
assert_exit "verify exits 2 on missing file" 2 "$STATUS"
assert_output_contains "verify reports MISSING" "MISSING" "$OUTPUT"

# --- Test 6: missing --dir argument exits 1 ---
bash "$SCRIPT" --generate --dir "/nonexistent" --output "$CHECKSUM_FILE" 2>&1 || STATUS=$?
assert_exit "nonexistent dir exits 1" 1 "$STATUS"

# --- Cleanup ---
rm -rf "$TMPDIR_FIXTURE"

print_summary "check_file_integrity"
