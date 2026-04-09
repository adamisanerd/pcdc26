#!/usr/bin/env bash
# check_processes.sh - List running processes and flag suspicious ones
# Usage: ./check_processes.sh [--suspicious <name>]
# Blue Team Use: Detect unexpected or malicious processes

set -euo pipefail

SUSPICIOUS_NAME=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --suspicious)
            SUSPICIOUS_NAME="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

echo "=== Running Processes ==="
ps aux --no-headers | sort -k3 -rn | head -20

if [[ -n "$SUSPICIOUS_NAME" ]]; then
    echo ""
    echo "=== Checking for suspicious process: $SUSPICIOUS_NAME ==="
    MATCH="$(pgrep -a "$SUSPICIOUS_NAME" 2>/dev/null || true)"
    if [[ -n "$MATCH" ]]; then
        echo "ALERT: Suspicious process found:"
        echo "$MATCH"
        exit 2
    else
        echo "OK: Process '$SUSPICIOUS_NAME' not running."
    fi
fi
