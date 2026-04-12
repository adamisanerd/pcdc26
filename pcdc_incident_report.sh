#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Quick Incident Report Builder
#  Run this whenever you detect a Red Team attack.
#  Fill it in, then submit to Gold Team for point recovery.
# ============================================================

GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
mkdir -p "$LOGDIR"

OUTFILE="$LOGDIR/incident_report_$(date +%Y%m%d_%H%M%S).txt"

echo -e "${BLU}PCDC 2026 | Incident Report Builder${NC}"
echo ""

read -rp "Your name: " AUTHOR
read -rp "Compromised system IP: " VICTIM_IP
read -rp "Source/Attacker IP (if known): " SRC_IP
read -rp "Time attack occurred (HH:MM): " ATTACK_TIME
read -rp "How did you detect it?: " DETECTION
read -rp "What was affected (service, file, account)?: " AFFECTED
read -rp "What happened (brief description): " DESCRIPTION
read -rp "Remediation steps taken: " REMEDIATION

cat > "$OUTFILE" << EOF
============================================================
PCDC 2026 | ASTRA 9 — INCIDENT REPORT
============================================================
Reporter:           $AUTHOR
Report Time:        $(date)
Team System IP:     $(hostname -I | awk '{print $1}')
Hostname:           $(hostname)

------------------------------------------------------------
INCIDENT DETAILS (Required by Gold Team)
------------------------------------------------------------
Compromised System: $VICTIM_IP
Source IP:          $SRC_IP
Time of Attack:     $ATTACK_TIME

Detection Method:   $DETECTION

What Was Affected:  $AFFECTED

Description:
$DESCRIPTION

Remediation Taken:
$REMEDIATION

------------------------------------------------------------
SUPPORTING EVIDENCE (auto-collected)
------------------------------------------------------------
Current logged-in users:
$(who)

Recent auth log (last 30 lines):
$(grep -E "Failed|Accepted|Invalid|sudo|ROOT" /var/log/auth.log 2>/dev/null | tail -30)

Current open connections:
$(ss -tnp state established 2>/dev/null)

Recent file modifications (last hour, outside /proc /sys):
$(find / -mmin -60 -type f \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    ! -path "/dev/*" \
    ! -path "/run/*" \
    2>/dev/null | head -20)

============================================================
END OF REPORT
============================================================
EOF

echo ""
echo -e "${GRN}Report saved: $OUTFILE${NC}"
echo ""
echo -e "${YLW}Submit this file to the Gold Team via the inject system.${NC}"
echo ""
cat "$OUTFILE"
