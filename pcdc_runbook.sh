#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  MASTER RUNBOOK
#
#  This script does NOT replace the others.
#  It orchestrates them and maps them to the competition
#  timeline so your team knows EXACTLY what to run, when,
#  and in what order.
#
#  Usage:
#    bash pcdc_runbook.sh phase1    # golden window
#    bash pcdc_runbook.sh phase2    # under attack
#    bash pcdc_runbook.sh triage    # you think you're compromised
#    bash pcdc_runbook.sh report    # generate incident report
#    bash pcdc_runbook.sh status    # quick health check
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
MAG='\033[0;35m'
NC='\033[0m'

SCRIPTDIR="$(dirname "$(readlink -f "$0")")"
LOGDIR="/var/log/blueTeam"
mkdir -p "$LOGDIR"

header() {
    clear
    echo -e "${BLU}"
    echo "  ╔═══════════════════════════════════════════════════════════╗"
    echo "  ║         ASTRA 9 BLUE TEAM — MASTER RUNBOOK               ║"
    echo "  ║         PCDC 2026                                         ║"
    echo "  ╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "  Host: $(hostname) | IP: $(hostname -I | awk '{print $1}') | $(date)"
    echo ""
}

section() {
    echo ""
    echo -e "${MAG}▶▶▶ $1${NC}"
    echo ""
}

run_script() {
    local script=$1
    local desc=$2
    shift 2
    echo -e "${CYN}[RUN]${NC} $desc"
    if [ -f "$SCRIPTDIR/$script" ]; then
        /bin/bash "$SCRIPTDIR/$script" "$@"
    else
        echo -e "${YLW}[SKIP]${NC} $script not found in $SCRIPTDIR"
    fi
}

# ============================================================
# PHASE 1: GOLDEN WINDOW
# Run this the MOMENT you get access to your systems.
# You have 30-90 min before red team attacks.
# Every second here is worth 10x under fire.
# ============================================================
phase1() {
    header
    echo -e "${GRN}PHASE 1: GOLDEN WINDOW — Secure Before Attacks${NC}"
    echo ""
    echo "  What's happening: Competition just started. Red team locked out."
    echo "  Goal: Know your systems, change all credentials, baseline everything."
    echo "  Time budget: Use 80% of your window, keep 20% for injects."
    echo ""
    echo "  PARALLEL WORK — assign each task to a team member:"
    echo "    Person 1: Run audit + harden on Linux box #1"
    echo "    Person 2: Run audit + harden on Linux box #2"
    echo "    Person 3: Windows hardening (see separate checklist)"
    echo "    Person 4: Network/Security Onion setup"
    echo "    Captain:  Read all initial injects, coordinate"
    echo ""
    read -rp "Press Enter to start Phase 1 scripts on THIS machine..."

    section "STEP 1/5: Full System Audit (read-only, safe to run first)"
    run_script "pcdc_linux_audit.sh" "System audit"

    section "STEP 2/5: Hardening (interactive — prompts before changes)"
    echo -e "${YLW}  WARNING: Open a SECOND SSH session before this step.${NC}"
    echo -e "${YLW}  If you lock yourself out, you still have the backup session.${NC}"
    read -rp "  Second session confirmed? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && run_script "pcdc_linux_harden.sh" "System hardening"

    section "STEP 3/5: Shell Poisoning & Alias Check"
    echo "  Systems may be PRE-INFECTED per the packet. Check before trusting anything."
    run_script "pcdc_alias_detector_v2.sh" "Alias/poison detection"

    section "STEP 4/5: Web Application Audit"
    run_script "pcdc_webapp_audit.sh" "Web app & service audit"

    section "STEP 5/5: Privilege Escalation Audit"
    run_script "pcdc_privesc_detector.sh" "Privesc detection"

    echo ""
    echo -e "${GRN}Phase 1 complete. Now start Phase 2 monitors in separate terminals.${NC}"
    echo ""
    echo "  Terminal 1: sudo /bin/bash pcdc_linux_monitor.sh"
    echo "  Terminal 2: sudo /bin/bash pcdc_port_monitor_v2.sh 30"
    echo "  Terminal 3: sudo /bin/bash pcdc_port_monitor_v2.sh --paranoid  (when attacks start)"
    echo ""
}

# ============================================================
# PHASE 2: OPERATING UNDER FIRE
# Monitors running, red team active.
# This is your steady-state operational mode.
# ============================================================
phase2() {
    header
    echo -e "${YLW}PHASE 2: OPERATING UNDER FIRE${NC}"
    echo ""
    echo "  TERMINAL ALLOCATION (open 4 terminals):"
    echo ""
    echo -e "  ${CYN}Terminal 1 — Port Monitor (paranoid mode)${NC}"
    echo "    sudo /bin/bash $SCRIPTDIR/pcdc_port_monitor_v2.sh --paranoid"
    echo ""
    echo -e "  ${CYN}Terminal 2 — System Monitor (every 45s)${NC}"
    echo "    sudo /bin/bash $SCRIPTDIR/pcdc_linux_monitor.sh 45"
    echo ""
    echo -e "  ${CYN}Terminal 3 — Inject watching / business ops${NC}"
    echo "    Keep email/Teams open here. Captain monitors this."
    echo ""
    echo -e "  ${CYN}Terminal 4 — Free for incident response${NC}"
    echo "    When alerts fire, do your investigation here."
    echo "    Use full binary paths to avoid aliased shells:"
    echo "    /bin/bash --norc --noprofile"
    echo ""
    echo "  PERIODIC MANUAL CHECKS (every 30 min):"
    echo "    sudo /bin/bash $SCRIPTDIR/pcdc_alias_detector_v2.sh"
    echo "    sudo /bin/bash $SCRIPTDIR/pcdc_webapp_audit.sh"
    echo "    sudo /bin/bash $SCRIPTDIR/pcdc_privesc_detector.sh"
    echo ""
    echo "  INJECT HANDLING:"
    echo "    sudo /bin/bash $SCRIPTDIR/pcdc_soceng_defense.sh"
    echo "    (run the validation checklist for any unusual inject)"
    echo ""

    echo -e "${YLW}ATTACKER MINDSET — what they're doing right now:${NC}"
    echo ""
    echo "  • Scanning your open ports for unpatched services"
    echo "  • Trying default/common credentials on every service"
    echo "  • Sending social engineering injects via email"
    echo "  • Looking for your webshell upload endpoints"
    echo "  • Checking if you left MySQL accessible externally"
    echo "  • Probing for SUID binaries they can exploit"
    echo "  • Watching your traffic for credential reuse patterns"
    echo ""

    read -rp "Press Enter to run a full quick-check on this machine..."
    section "Quick Health Check"
    run_script "" "" # placeholder
    quick_status
}

# ============================================================
# TRIAGE: You think you're compromised
# Structured incident response when alerts fire
# ============================================================
triage() {
    header
    echo -e "${RED}TRIAGE MODE — Potential Compromise Detected${NC}"
    echo ""
    echo "  Stay calm. Work the problem methodically."
    echo "  Panic is what they're counting on."
    echo ""

    section "STEP 1: OPEN A CLEAN SHELL IMMEDIATELY"
    echo "  Your current shell may be compromised."
    echo "  Before doing ANYTHING investigative, get a clean environment:"
    echo ""
    echo -e "  ${YLW}env -i HOME=/root PATH=/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin /bin/bash --norc --noprofile${NC}"
    echo ""
    read -rp "  Clean shell confirmed? [y/N]: " ans

    section "STEP 2: STOP THE BLEEDING — PRESERVE SERVICES"
    echo "  Check which scored services are still up FIRST."
    echo "  A compromised system that's still serving is better than"
    echo "  a clean system that's down. Don't nuke what's working."
    echo ""
    echo "  Service status:"
    systemctl list-units --type=service --state=running 2>/dev/null | \
        grep -E "apache|nginx|mysql|maria|postfix|named|ssh|ftp|smb" | head -20
    echo ""

    section "STEP 3: IDENTIFY HOW THEY GOT IN"
    echo "  Running compromise detection..."
    echo ""

    # Quick targeted checks
    echo -e "${CYN}New accounts created?${NC}"
    awk -F: '$3 >= 1000 && $1 != "nobody" {print $1, "UID="$3}' /etc/passwd

    echo ""
    echo -e "${CYN}New SSH keys?${NC}"
    find /home /root -name "authorized_keys" -newer /etc/passwd 2>/dev/null | while read f; do
        echo -e "${RED}MODIFIED: $f${NC}"
        cat "$f"
    done

    echo ""
    echo -e "${CYN}Processes with network connections that shouldn't have them?${NC}"
    ss -tnp state established 2>/dev/null | grep -E "bash|sh|python|perl|nc|ncat"

    echo ""
    echo -e "${CYN}New files in web root (last 30 min)?${NC}"
    find /var/www /srv/www 2>/dev/null -type f -mmin -30 | head -20

    echo ""
    echo -e "${CYN}Hidden files in /tmp?${NC}"
    find /tmp /var/tmp /dev/shm -name ".*" -o -type f -executable 2>/dev/null

    echo ""
    echo -e "${CYN}Last 20 auth events:${NC}"
    tail -20 /var/log/auth.log 2>/dev/null || tail -20 /var/log/secure 2>/dev/null

    section "STEP 4: CONTAINMENT OPTIONS"
    echo "  Choose based on what you found:"
    echo ""
    echo "  A) Red team has a shell → kill the process, reset the account they used"
    echo "     kill -9 <PID>"
    echo "     usermod -L <compromised_user>"
    echo "     passwd <compromised_user>"
    echo ""
    echo "  B) Webshell planted → remove the file, check for others, reset web perms"
    echo "     rm /var/www/html/<webshell>"
    echo "     chown -R www-data:www-data /var/www/html"
    echo "     chmod -R 755 /var/www/html"
    echo ""
    echo "  C) Backdoor user created → delete them"
    echo "     userdel -r <backdoor_user>"
    echo ""
    echo "  D) SSH key planted → remove from authorized_keys"
    echo "     > /home/<user>/.ssh/authorized_keys"
    echo ""
    echo "  E) Completely owned, can't recover → consider revert (costs points)"
    echo "     Exhaust all other options first. Max 2 reverts per machine."
    echo ""

    section "STEP 5: DOCUMENT EVERYTHING FOR INCIDENT REPORT"
    echo "  Running incident report generator..."
    run_script "pcdc_incident_report.sh" "Incident report"
}

# ============================================================
# QUICK STATUS: Fast health check, any time
# ============================================================
quick_status() {
    header
    echo -e "${GRN}QUICK STATUS CHECK${NC}"
    echo ""

    section "Services"
    for svc in apache2 nginx httpd mysql mariadb postgresql postfix named vsftpd smbd sshd; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo -e "  ${GRN}[UP]${NC}   $svc"
        elif systemctl list-unit-files 2>/dev/null | grep -q "^${svc}.service"; then
            echo -e "  ${RED}[DOWN]${NC} $svc"
        fi
    done

    section "Open Ports"
    ss -tulnp 2>/dev/null | tail -n +2 | while read proto rq sq local foreign state proc; do
        port=$(echo "$local" | rev | cut -d: -f1 | rev)
        binary=$(echo "$proc" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
        echo "  :$port → $binary"
    done

    section "Logged In Users"
    who

    section "Recent Auth Events (last 10)"
    tail -10 /var/log/auth.log 2>/dev/null || tail -10 /var/log/secure 2>/dev/null

    section "Established Connections"
    ss -tnp state established 2>/dev/null | tail -n +2

    section "Processes with Sockets (flag shells)"
    ss -tnp state established 2>/dev/null | grep -E '"(bash|sh|python|perl|nc|ncat)"'

    section "Disk & Load"
    df -h / /var /tmp 2>/dev/null
    uptime
}

# ============================================================
# MAIN
# ============================================================
case "${1:-}" in
    phase1)   phase1 ;;
    phase2)   phase2 ;;
    triage)   triage ;;
    report)   run_script "pcdc_incident_report.sh" "Incident Report" ;;
    status)   quick_status ;;
    *)
        header
        echo "  Usage: /bin/bash pcdc_runbook.sh <phase>"
        echo ""
        echo "  Phases:"
        echo -e "    ${GRN}phase1${NC}  — Golden window: audit, harden, baseline everything"
        echo -e "    ${YLW}phase2${NC}  — Under fire: what to monitor and how to operate"
        echo -e "    ${RED}triage${NC}  — Compromised: structured incident response"
        echo -e "    ${CYN}status${NC}  — Quick health check (run anytime)"
        echo -e "    ${CYN}report${NC}  — Generate incident report for Gold Team"
        echo ""
        echo "  All scripts should be in the same directory as this runbook."
        echo "  Always invoke with full path: /bin/bash pcdc_runbook.sh"
        echo "  Never 'source' or '.' this file."
        echo ""
        ;;
esac
