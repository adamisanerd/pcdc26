#!/usr/bin/env bash
# check_failed_logins.sh - Report failed SSH/login attempts from auth logs
# Usage: ./check_failed_logins.sh [--threshold <count>] [--logfile <path>]
# Blue Team Use: Detect brute-force or credential stuffing attacks

set -euo pipefail

THRESHOLD=5
LOGFILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        --logfile)
            LOGFILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# Determine log file path
if [[ -z "$LOGFILE" ]]; then
    if [[ -f /var/log/auth.log ]]; then
        LOGFILE="/var/log/auth.log"
    elif [[ -f /var/log/secure ]]; then
        LOGFILE="/var/log/secure"
    else
        echo "No auth log found. Pass --logfile <path> to specify one." >&2
        exit 1
    fi
fi

if [[ ! -f "$LOGFILE" ]]; then
    echo "Log file not found: $LOGFILE" >&2
    exit 1
fi

echo "=== Failed Login Attempts (source: $LOGFILE) ==="
echo "Threshold: $THRESHOLD failed attempts per IP"
echo ""

# Extract IPs with failed auth and count occurrences
grep -i "failed\|invalid\|authentication failure" "$LOGFILE" \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | sort \
    | uniq -c \
    | sort -rn \
    | awk -v thr="$THRESHOLD" '$1 >= thr { printf "  Count: %-6s IP: %s\n", $1, $2 }'

echo ""
echo "Scan complete."
