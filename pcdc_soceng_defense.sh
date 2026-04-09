#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Social Engineering Defense & Inject Validator
#
#  WHY THIS SCRIPT EXISTS:
#  The packet explicitly says social engineering WILL happen.
#  The Astra 9 scenario (overworked skeleton crew, panicked
#  management, space emergency) is DESIGNED to create the
#  psychological pressure red teams exploit.
#
#  This script does two things:
#  1. Monitors email/logs for social engineering IOCs
#     (Indicators of Compromise via manipulation)
#  2. Provides a validation checklist your team runs
#     BEFORE acting on any inject or request
#
#  Social engineering attacks at PCDC typically look like:
#  - Fake "CEO/CIO" emails requesting credential resets
#  - Urgent inject-style messages asking you to disable firewall
#  - Phone calls impersonating Gold/White team members
#  - Fake scoring system alerts telling you to open a port
#  - Emails with malicious attachments or links (in inject format)
#  - Requests that come through unofficial channels
#
#  The MGM/Caesars attack the packet references was pure
#  social engineering — no technical exploit needed.
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="$LOGDIR/soceng_$TIMESTAMP.log"

mkdir -p "$LOGDIR"
exec > >(tee -a "$LOGFILE") 2>&1

ok()     { echo -e "${GRN}[OK]${NC}     $1"; }
warn()   { echo -e "${YLW}[WARN]${NC}   $1"; }
alert()  { echo -e "${RED}[ALERT]${NC}  $1"; }
info()   { echo -e "${CYN}[INFO]${NC}   $1"; }
section(){
    echo ""
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ============================================================
# SECTION 1: INJECT VALIDATION CHECKLIST
# Run this interactively when any inject or request arrives
# ============================================================
section "INJECT / REQUEST VALIDATION CHECKLIST"

echo -e "${YLW}Run this checklist for EVERY inject or unusual request.${NC}"
echo -e "${YLW}Answer honestly. If ANY answer is NO — pause before acting.${NC}"
echo ""

INJECT_PASSED=true

ask() {
    local question=$1
    local consequence=$2
    echo -e "${CYN}Q: $question${NC}"
    read -rp "   [y/N]: " ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
        warn "FAIL: $consequence"
        INJECT_PASSED=false
    else
        ok "PASS"
    fi
    echo ""
}

ask "Did this request arrive through the OFFICIAL inject system (Teams/web portal/email)?" \
    "Unofficial channel = could be red team impersonation"

ask "Does the sender's email domain match the official competition domain?" \
    "Spoofed sender address is the #1 social engineering vector"

ask "Does this request ask you to DISABLE or WEAKEN security (firewall, passwords, auth)?" \
    "Legitimate injects rarely ask you to remove security controls"

ask "Is there a DEADLINE creating urgency or panic ('do this NOW or lose points')?" \
    "Urgency is the core manipulator — it bypasses rational thinking"

ask "If this involves credentials or account changes, can you verify via a SECOND channel?" \
    "Always verify credential requests through a different communication path"

ask "Does this request match the PCDC scenario context (space mining ops, Astra 9)?" \
    "Out-of-context requests may be red team attempting to confuse"

ask "Have you checked with your Team Captain before acting on this?" \
    "No individual should act on unusual requests alone"

echo ""
if $INJECT_PASSED; then
    ok "ALL CHECKS PASSED — proceed with caution"
else
    alert "ONE OR MORE CHECKS FAILED"
    alert "Treat this request with extreme suspicion."
    alert "Consult your captain. Request clarification from White Team if uncertain."
    echo ""
    echo "To formally question an inject, your Captain contacts the White Team."
    echo "Document your concern in writing regardless of outcome."
fi

# ============================================================
# SECTION 2: EMAIL LOG ANALYSIS FOR SE INDICATORS
# Scans mail logs for suspicious patterns
# ============================================================
section "SECTION 2: EMAIL LOG ANALYSIS"

MAIL_LOGS=("/var/log/mail.log" "/var/log/maillog" "/var/log/mail/mail.log")

SE_EMAIL_PATTERNS=(
    "password"
    "credential"
    "reset.*account"
    "urgent"
    "immediately"
    "ceo\|cio\|cto\|executive"
    "wire.*transfer"
    "disable.*firewall"
    "open.*port"
    "account.*compromised"
    "verify.*now"
    "click.*here"
    "attachment"
)

for logfile in "${MAIL_LOGS[@]}"; do
    [ ! -f "$logfile" ] && continue

    info "Scanning $logfile for social engineering indicators..."

    for pattern in "${SE_EMAIL_PATTERNS[@]}"; do
        matches=$(grep -i "$pattern" "$logfile" 2>/dev/null | tail -5)
        if [ -n "$matches" ]; then
            warn "SE pattern '$pattern' in mail log:"
            echo "$matches"
        fi
    done
done

# Check postfix mail queue for suspicious subjects/senders
if command -v postcat &>/dev/null && command -v mailq &>/dev/null; then
    info "Checking queued mail for suspicious content..."
    mailq 2>/dev/null | grep "^[A-Z0-9]" | awk '{print $1}' | while read msgid; do
        # Get message headers
        clean_id=$(echo "$msgid" | tr -d '*!')
        content=$(postcat -q "$clean_id" 2>/dev/null | head -30)
        if echo "$content" | grep -qi "password\|credential\|urgent\|wire\|disable"; then
            warn "Suspicious queued message $msgid:"
            echo "$content" | head -10
        fi
    done
fi

# ============================================================
# SECTION 3: AUTH LOG ANALYSIS FOR SE SUCCESS INDICATORS
# If red team successfully social engineered credentials,
# you'll see login patterns that don't match normal ops
# ============================================================
section "SECTION 3: AUTH LOG — SE SUCCESS INDICATORS"

AUTH_LOGS=("/var/log/auth.log" "/var/log/secure")

for logfile in "${AUTH_LOGS[@]}"; do
    [ ! -f "$logfile" ] && continue

    info "Analyzing auth patterns in $logfile..."

    # Logins at unusual hours (competition is daytime — night logins = suspicious)
    echo ""
    info "Logins outside business hours (before 7am or after 8pm):"
    grep "Accepted" "$logfile" 2>/dev/null | while read line; do
        hour=$(echo "$line" | awk '{print $3}' | cut -d: -f1)
        if [ "$hour" -lt 7 ] || [ "$hour" -gt 20 ] 2>/dev/null; then
            warn "Off-hours login: $line"
        fi
    done

    # Successful login immediately after multiple failures (brute force success)
    echo ""
    info "Successful logins preceded by failures (possible brute force success):"
    grep -E "Failed password|Accepted" "$logfile" 2>/dev/null | \
    awk '
    /Failed password/ {
        ip = $NF; failures[ip]++
    }
    /Accepted/ {
        ip = $NF
        if (failures[ip] > 3) {
            print "BRUTE SUCCESS: " $0 " (preceded by " failures[ip] " failures from " ip ")"
        }
    }' | while read line; do
        alert "$line"
    done

    # New source IPs that have never logged in before
    echo ""
    info "All successful login source IPs:"
    grep "Accepted" "$logfile" 2>/dev/null | grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn
done

# ============================================================
# SECTION 4: TEAM SECURITY PROTOCOLS (print and post)
# ============================================================
section "SECTION 4: TEAM SECURITY PROTOCOLS — POST THIS AT YOUR STATION"

cat << 'PROTOCOLS'
╔══════════════════════════════════════════════════════════════╗
║          ASTRA 9 BLUE TEAM — SECURITY PROTOCOLS             ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  CREDENTIAL RULES:                                           ║
║  • NEVER share passwords via email, chat, or phone          ║
║  • NEVER reset passwords based solely on an email request   ║
║  • ALL credential changes require Captain approval          ║
║  • If "Gold/White Team" asks for creds in person,           ║
║    ask for their badge and confirm with another official     ║
║                                                              ║
║  INJECT RULES:                                               ║
║  • Only trust injects from the OFFICIAL inject system       ║
║  • Injects asking to DISABLE security = verify first        ║
║  • Urgency language = slow down, not speed up              ║
║  • Captain reads all injects before team acts               ║
║                                                              ║
║  COMMUNICATION RULES:                                        ║
║  • Phone calls claiming to be from PCDC staff = verify      ║
║  • Verify caller identity through official roster           ║
║  • No private communications with anyone outside team       ║
║    (competition rule + security practice)                   ║
║                                                              ║
║  RED FLAGS — STOP AND VERIFY:                               ║
║  ⚠ "Do this immediately or you'll lose points"              ║
║  ⚠ "This is the CEO, I need you to reset my password"      ║
║  ⚠ Request to open a port or disable a firewall rule       ║
║  ⚠ Email from unfamiliar domain claiming to be officials    ║
║  ⚠ Request that bypasses normal Captain approval flow      ║
║  ⚠ "Don't tell the rest of your team about this"           ║
║                                                              ║
║  THE ARUP RULE: (from the packet's deepfake example)        ║
║  Even if you see someone on video — verify independently.   ║
║  A face on a screen is not proof of identity.               ║
║                                                              ╠
╚══════════════════════════════════════════════════════════════╝
PROTOCOLS

echo ""
section "DONE"
echo -e "${GRN}Log: $LOGFILE${NC}"
