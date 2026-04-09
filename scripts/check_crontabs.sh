#!/usr/bin/env bash
# check_crontabs.sh - Enumerate all user and system crontab entries
# Usage: ./check_crontabs.sh
# Blue Team Use: Detect persistence mechanisms via scheduled tasks

set -euo pipefail

EXIT_CODE=0

echo "=== System-wide cron directories ==="
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [[ -d "$dir" ]]; then
        echo "--- $dir ---"
        ls -la "$dir" 2>/dev/null || true
    fi
done

echo ""
echo "=== /etc/crontab ==="
if [[ -f /etc/crontab ]]; then
    cat /etc/crontab
else
    echo "(not found)"
fi

echo ""
echo "=== User crontabs ==="
if command -v getent &>/dev/null; then
    while IFS=: read -r username _ uid _; do
        if [[ "$uid" -ge 1000 || "$username" == "root" ]]; then
            CRONTAB="$(crontab -u "$username" -l 2>/dev/null || true)"
            if [[ -n "$CRONTAB" ]]; then
                echo "--- $username ---"
                echo "$CRONTAB"
            fi
        fi
    done < /etc/passwd
else
    echo "(getent not available)"
fi

echo ""
echo "=== Crontab scan complete. Exit code: $EXIT_CODE ==="
exit "$EXIT_CODE"
