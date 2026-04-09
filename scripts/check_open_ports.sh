#!/usr/bin/env bash
# check_open_ports.sh - List all open TCP/UDP listening ports on the host
# Usage: ./check_open_ports.sh [--alert <port>]
# Blue Team Use: Identify unexpected listening services

set -euo pipefail

ALERT_PORT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --alert)
            ALERT_PORT="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

echo "=== Open Listening Ports ==="
ss -tlnup 2>/dev/null || netstat -tlnup 2>/dev/null || echo "Neither ss nor netstat found; install iproute2 or net-tools"

if [[ -n "$ALERT_PORT" ]]; then
    echo ""
    echo "=== Checking for alert port: $ALERT_PORT ==="
    if ss -tlnup 2>/dev/null | grep -q ":${ALERT_PORT}[[:space:]]" || \
       netstat -tlnup 2>/dev/null | grep -q ":${ALERT_PORT}[[:space:]]"; then
        echo "ALERT: Port $ALERT_PORT is listening!"
        exit 2
    else
        echo "OK: Port $ALERT_PORT is not listening."
    fi
fi
