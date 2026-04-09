#!/usr/bin/env bash
# test_helpers.sh - Shared helpers for all test scripts
# Source this file from individual test scripts.

PASS=0
FAIL=0

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

assert_exit() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [[ "$actual" -eq "$expected" ]]; then
        pass "$desc (exit $actual)"
    else
        fail "$desc (expected exit $expected, got $actual)"
    fi
}

assert_output_contains() {
    local desc="$1"
    local pattern="$2"
    local output="$3"
    if echo "$output" | grep -qE "$pattern"; then
        pass "$desc"
    else
        fail "$desc (pattern '$pattern' not found in output)"
    fi
}

assert_output_not_contains() {
    local desc="$1"
    local pattern="$2"
    local output="$3"
    if echo "$output" | grep -qE "$pattern"; then
        fail "$desc (unexpected pattern '$pattern' found in output)"
    else
        pass "$desc"
    fi
}

print_summary() {
    local suite="$1"
    echo ""
    echo "=== $suite: $PASS passed, $FAIL failed ==="
    if [[ "$FAIL" -gt 0 ]]; then
        return 1
    fi
}
