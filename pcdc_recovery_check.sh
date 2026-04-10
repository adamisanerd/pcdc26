#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Recovery Path Integrity Checker
#
#  Run this from your ADMIN MACHINE periodically.
#  Verifies that your recovery access is still intact on
#  every host — if red team found and removed it, you'll
#  know immediately and can re-deploy before you need it.
#
#  Usage: bash pcdc_recovery_check.sh
#  Requires: ~/blueTeam/keys/pcdc_admin (your SSH key)
#            ~/blueTeam/hosts.txt (your fleet)
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

BLUETEAM_KEY="$HOME/blueTeam/keys/pcdc_admin"
HOSTFILE="$HOME/blueTeam/hosts.txt"
RECOVERY_USER="svcmon"     # Must match what you set in pcdc_recovery_access.sh

ok()     { echo -e "${GRN}[OK]${NC}     $1"; }
warn()   { echo -e "${YLW}[WARN]${NC}   $1"; }
alert()  { echo -e "${RED}[ALERT]${NC}  $1"; }
info()   { echo -e "${CYN}[INFO]${NC}   $1"; }

SSH_OPTS="-i $BLUETEAM_KEY \
          -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null \
          -o BatchMode=yes \
          -o ConnectTimeout=5 \
          -o LogLevel=ERROR"

echo ""
echo -e "${BLU}PCDC 2026 | Recovery Path Integrity Check${NC}"
echo -e "$(date)"
echo ""

if [ ! -f "$HOSTFILE" ]; then
    warn "No hosts file found at $HOSTFILE"
    exit 1
fi

# Track overall health
TOTAL=0
HEALTHY=0
DEGRADED=0
LOST=0

printf "%-20s %-12s %-12s %-12s %s\n" "HOST" "KEY→ROOT" "KEY→RECOV" "RECOV_USER" "STATUS"
echo "────────────────────────────────────────────────────────────────"

while read target; do
    [[ "$target" == \#* ]] || [ -z "$target" ] && continue

    user=$(echo "$target" | cut -d@ -f1)
    host=$(echo "$target" | cut -d@ -f2)
    TOTAL=$((TOTAL + 1))

    # Test 1: Key auth as root
    root_key="FAIL"
    root_result=$(ssh $SSH_OPTS root@"$host" "echo KEYOK" 2>/dev/null)
    echo "$root_result" | grep -q "KEYOK" && root_key="${GRN}OK${NC}" || root_key="${RED}FAIL${NC}"

    # Test 2: Key auth as recovery user
    recov_key="FAIL"
    recov_result=$(ssh $SSH_OPTS ${RECOVERY_USER}@"$host" "echo KEYOK" 2>/dev/null)
    echo "$recov_result" | grep -q "KEYOK" && recov_key="${GRN}OK${NC}" || recov_key="${RED}FAIL${NC}"

    # Test 3: Recovery user still exists
    recov_exists="GONE"
    if echo "$recov_result" | grep -q "KEYOK"; then
        # User exists if we could log in
        recov_exists="${GRN}EXISTS${NC}"
    else
        # Try to check via root key
        user_check=$(ssh $SSH_OPTS root@"$host" "id $RECOVERY_USER 2>/dev/null" 2>/dev/null)
        if echo "$user_check" | grep -q "$RECOVERY_USER"; then
            recov_exists="${YLW}EXISTS${NC}"  # exists but key broken
        else
            recov_exists="${RED}GONE${NC}"
        fi
    fi

    # Determine overall status
    if echo "$root_result $recov_result" | grep -q "KEYOK"; then
        STATUS="${GRN}HEALTHY${NC}"
        HEALTHY=$((HEALTHY + 1))
    elif echo "$root_result" | grep -q "KEYOK"; then
        STATUS="${YLW}DEGRADED${NC} (root key only)"
        DEGRADED=$((DEGRADED + 1))
    else
        STATUS="${RED}RECOVERY LOST${NC}"
        LOST=$((LOST + 1))
    fi

    printf "%-20s " "$host"
    echo -e "${root_key}         ${recov_key}         ${recov_exists}      ${STATUS}"

done < "$HOSTFILE"

echo "────────────────────────────────────────────────────────────────"
echo ""
echo -e "Total: $TOTAL  ${GRN}Healthy: $HEALTHY${NC}  ${YLW}Degraded: $DEGRADED${NC}  ${RED}Lost: $LOST${NC}"
echo ""

if [ "$LOST" -gt 0 ] || [ "$DEGRADED" -gt 0 ]; then
    echo -e "${YLW}ACTION REQUIRED:${NC}"
    echo "  Re-deploy recovery access to affected hosts:"
    echo "  bt_run_covert ~/blueTeam/scripts/pcdc_recovery_access.sh root@<host>"
    echo ""
fi

if [ "$LOST" -eq 0 ] && [ "$DEGRADED" -eq 0 ]; then
    echo -e "${GRN}All recovery paths intact. You're good.${NC}"
fi
