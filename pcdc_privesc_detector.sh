#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Privilege Escalation & Lateral Movement Detector
#
#  WHY THIS SCRIPT EXISTS:
#  The packet lists Active Directory and covers Windows/Linux
#  mixed environments. The red team's kill chain is:
#
#  Initial access → Local privesc → Credential harvest →
#  Lateral movement → Persistence → Exfil/Disruption
#
#  Most blue teams secure the front door (SSH, passwords)
#  and completely miss the interior. This script watches
#  the interior — privilege changes, lateral movement
#  indicators, and credential harvesting attempts.
#
#  Covers:
#  - Sudo rule abuse and new sudo grants
#  - SUID binary creation (classic privesc)
#  - Capabilities abuse (getcap — often overlooked)
#  - Writable /etc/passwd or shadow (immediate privesc)
#  - /etc/sudoers.d/ drops (persistence via sudo)
#  - Unexpected su/sudo activity
#  - Passwd/shadow changes mid-competition
#  - /proc/sysrq-trigger abuse (crash/reboot attacks)
#  - Core dump credential leakage
#  - Ptrace-based credential theft (gdb/strace on auth process)
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="$LOGDIR/privesc_$TIMESTAMP.log"
INCIDENT_LOG="$LOGDIR/incidents_$TIMESTAMP.log"
STATE_DIR="$LOGDIR/privesc_state"

mkdir -p "$LOGDIR" "$STATE_DIR"
exec > >(tee -a "$LOGFILE") 2>&1

ok()     { echo -e "${GRN}[OK]${NC}     $1"; }
warn()   { echo -e "${YLW}[WARN]${NC}   $1"; }
alert()  {
    echo -e "${RED}[ALERT]${NC}  $1"
    echo "[$(date '+%H:%M:%S')] ALERT: $1" >> "$INCIDENT_LOG"
}
info()   { echo -e "${CYN}[INFO]${NC}   $1"; }
section(){
    echo ""
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

log_incident() {
    cat >> "$INCIDENT_LOG" << EOF
============================================================
INCIDENT: $1
Time:     $(date)
System:   $(hostname) [$(hostname -I | awk '{print $1}')]
Detail:   $2
============================================================
EOF
}

# ============================================================
# SECTION 1: SUDO CONFIGURATION AUDIT
# ============================================================
section "SECTION 1: SUDO CONFIGURATION AUDIT"

# Baseline sudo config
SUDO_HASH_FILE="$STATE_DIR/sudo.hash"
current_sudo_hash=$(sha256sum /etc/sudoers 2>/dev/null | awk '{print $1}')

if [ ! -f "$SUDO_HASH_FILE" ]; then
    echo "$current_sudo_hash" > "$SUDO_HASH_FILE"
    ok "Sudoers baseline captured: $current_sudo_hash"
else
    stored_hash=$(cat "$SUDO_HASH_FILE")
    if [ "$current_sudo_hash" != "$stored_hash" ]; then
        alert "/etc/sudoers HAS BEEN MODIFIED since baseline!"
        log_incident "SUDOERS MODIFIED" "/etc/sudoers hash changed"
        diff <(echo "$stored_hash") <(echo "$current_sudo_hash")
    else
        ok "/etc/sudoers unchanged"
    fi
fi

# Dangerous sudo patterns
info "Checking sudoers for dangerous grants..."
grep -v "^#\|^$" /etc/sudoers 2>/dev/null | while read line; do
    # NOPASSWD sudo — any user can sudo without password
    if echo "$line" | grep -q "NOPASSWD"; then
        warn "NOPASSWD sudo grant: $line"
    fi
    # ALL=(ALL) ALL — full root access
    if echo "$line" | grep -qP "ALL\s*=\s*\(ALL\)\s*ALL"; then
        warn "Full root sudo access: $line"
    fi
    # Sudo to shell — immediate root
    if echo "$line" | grep -qE "/bin/(bash|sh|zsh|dash|ksh)"; then
        alert "Sudo grants shell access: $line"
        log_incident "SUDO SHELL GRANT" "$line"
    fi
done

# Check sudoers.d — red team drops files here for persistence
info "Checking /etc/sudoers.d/ for new/suspicious files..."
SUDO_D_HASH="$STATE_DIR/sudoers_d.hash"
current_d_hash=$(ls -la /etc/sudoers.d/ 2>/dev/null | sha256sum | awk '{print $1}')

if [ ! -f "$SUDO_D_HASH" ]; then
    echo "$current_d_hash" > "$SUDO_D_HASH"
    info "sudoers.d baseline captured"
    ls /etc/sudoers.d/ 2>/dev/null
else
    if [ "$current_d_hash" != "$(cat $SUDO_D_HASH)" ]; then
        alert "/etc/sudoers.d/ CHANGED — new file may have been dropped!"
        log_incident "SUDOERS.D MODIFIED" "New drop-in sudo rule detected"
        ls -la /etc/sudoers.d/ 2>/dev/null
        cat /etc/sudoers.d/* 2>/dev/null
    else
        ok "/etc/sudoers.d/ unchanged"
    fi
fi

# ============================================================
# SECTION 2: LINUX CAPABILITIES (getcap)
# Often completely overlooked by blue teams.
# Capabilities allow processes to do root-level things
# without being root. Python with cap_setuid = instant root.
# ============================================================
section "SECTION 2: LINUX CAPABILITIES AUDIT"

info "All binaries with elevated capabilities (getcap):"
if command -v getcap &>/dev/null; then
    CAPS_FILE="$STATE_DIR/capabilities.baseline"
    current_caps=$(getcap -r / 2>/dev/null)

    echo "$current_caps"

    # Flag specifically dangerous capabilities
    echo "$current_caps" | while read line; do
        binary=$(echo "$line" | awk '{print $1}')
        caps=$(echo "$line" | awk '{print $2, $3}')

        case "$caps" in
            *cap_setuid*)
                alert "PRIVESC: $binary has cap_setuid — can become any user including root"
                log_incident "DANGEROUS CAPABILITY" "$binary cap_setuid"
                ;;
            *cap_sys_admin*)
                alert "PRIVESC: $binary has cap_sys_admin — near-root level access"
                log_incident "DANGEROUS CAPABILITY" "$binary cap_sys_admin"
                ;;
            *cap_net_raw*)
                warn "$binary has cap_net_raw — can capture network traffic (packet sniffer)"
                ;;
            *cap_dac_override*)
                alert "PRIVESC: $binary has cap_dac_override — can read/write ANY file"
                log_incident "DANGEROUS CAPABILITY" "$binary cap_dac_override"
                ;;
        esac
    done

    # Compare to baseline
    if [ ! -f "$CAPS_FILE" ]; then
        echo "$current_caps" > "$CAPS_FILE"
        ok "Capabilities baseline saved"
    else
        new_caps=$(comm -13 <(sort "$CAPS_FILE") <(echo "$current_caps" | sort))
        if [ -n "$new_caps" ]; then
            alert "NEW CAPABILITIES ADDED since baseline:"
            echo "$new_caps"
            log_incident "NEW CAPABILITY ADDED" "$new_caps"
            echo "$current_caps" > "$CAPS_FILE"
        fi
    fi
else
    warn "getcap not available — install libcap2-bin"
fi

# ============================================================
# SECTION 3: SUID/SGID BASELINE AND DRIFT
# ============================================================
section "SECTION 3: SUID/SGID DRIFT DETECTION"

SUID_BASELINE="$STATE_DIR/suid.baseline"
current_suid=$(find / -perm -4000 -type f 2>/dev/null | sort)

if [ ! -f "$SUID_BASELINE" ]; then
    echo "$current_suid" > "$SUID_BASELINE"
    info "SUID baseline captured ($(echo "$current_suid" | wc -l) binaries)"
else
    new_suid=$(comm -13 "$SUID_BASELINE" <(echo "$current_suid"))
    if [ -n "$new_suid" ]; then
        alert "NEW SUID BINARY CREATED — IMMEDIATE PRIVESC RISK:"
        echo "$new_suid" | while read f; do
            echo -e "  ${RED}$f${NC}"
            ls -la "$f"
            log_incident "NEW SUID BINARY" "$f"
        done
        echo "$current_suid" > "$SUID_BASELINE"
    else
        ok "No new SUID binaries"
    fi
fi

# Flag SUID binaries in non-standard locations
echo "$current_suid" | while read f; do
    dir=$(dirname "$f")
    if echo "$dir" | grep -qv -E '^/(usr/(local/)?)?(s)?bin|/usr/lib'; then
        alert "SUID BINARY IN UNUSUAL LOCATION: $f"
        log_incident "UNUSUAL SUID LOCATION" "$f"
    fi
done

# ============================================================
# SECTION 4: /etc/passwd and /etc/shadow WRITE PERMISSION
# If these are world-writable, it's immediate game over
# ============================================================
section "SECTION 4: CRITICAL FILE PERMISSIONS"

CRITICAL_FILES=(
    "/etc/passwd:644"
    "/etc/shadow:640"
    "/etc/sudoers:440"
    "/etc/ssh/sshd_config:600"
    "/etc/crontab:644"
)

for entry in "${CRITICAL_FILES[@]}"; do
    filepath=$(echo "$entry" | cut -d: -f1)
    _expected_perm=$(echo "$entry" | cut -d: -f2)

    [ ! -f "$filepath" ] && continue

    actual_perm=$(stat -c '%a' "$filepath" 2>/dev/null)
    owner=$(stat -c '%U:%G' "$filepath" 2>/dev/null)

    # Check world-writable
    if [ $((8#$actual_perm & 8#002)) -ne 0 ]; then
        alert "CRITICAL FILE IS WORLD-WRITABLE: $filepath (perms: $actual_perm)"
        log_incident "WORLD WRITABLE CRITICAL FILE" "$filepath perms $actual_perm"
    # Check group-writable
    elif [ $((8#$actual_perm & 8#020)) -ne 0 ]; then
        warn "Critical file is group-writable: $filepath (perms: $actual_perm, owner: $owner)"
    else
        ok "$filepath: perms $actual_perm owner $owner"
    fi
done

# ============================================================
# SECTION 5: PTRACE ATTACHMENT DETECTION
# gdb/strace attached to sshd, sudo, passwd = credential theft
# This is how red teams harvest passwords in plaintext
# ============================================================
section "SECTION 5: PTRACE / DEBUGGER ATTACHMENT"

info "Checking for processes being traced (gdb, strace attached to auth processes)..."

# Check /proc/PID/status for TracerPid != 0
AUTH_PROCS=("sshd" "sudo" "passwd" "login" "su" "mysql" "postgres")

for proc_name in "${AUTH_PROCS[@]}"; do
    pids=$(pgrep -x "$proc_name" 2>/dev/null)
    for pid in $pids; do
        tracer=$(grep "^TracerPid:" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
        if [ -n "$tracer" ] && [ "$tracer" != "0" ]; then
            tracer_name=$(cat "/proc/$tracer/comm" 2>/dev/null)
            tracer_cmd=$(cat "/proc/$tracer/cmdline" 2>/dev/null | tr '\0' ' ')
            alert "CREDENTIAL THEFT: $proc_name (PID $pid) is being traced by PID $tracer ($tracer_name)"
            alert "  Tracer command: $tracer_cmd"
            log_incident "PTRACE CREDENTIAL THEFT" \
                "$proc_name PID $pid traced by $tracer_name ($tracer)"
        fi
    done
done

# Check if ptrace is restricted
ptrace_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
if [ -n "$ptrace_scope" ]; then
    case "$ptrace_scope" in
        0) warn "ptrace_scope=0: Any process can ptrace any other (default, risky)";;
        1) ok "ptrace_scope=1: ptrace restricted to parent processes";;
        2) ok "ptrace_scope=2: ptrace requires root";;
        3) ok "ptrace_scope=3: ptrace completely disabled";;
    esac

    # Harden if needed
    if [ "$ptrace_scope" = "0" ]; then
        warn "Consider hardening: echo 2 > /proc/sys/kernel/yama/ptrace_scope"
    fi
fi

# ============================================================
# SECTION 6: CORE DUMP ANALYSIS
# Core dumps from auth processes can contain passwords in plaintext
# ============================================================
section "SECTION 6: CORE DUMP EXPOSURE"

info "Recent core dumps (may contain credentials in plaintext):"
find / -name "core" -o -name "core.[0-9]*" -o -name "*.core" 2>/dev/null | \
    grep -v "/proc" | while read f; do
    warn "Core dump found: $f ($(ls -lh $f 2>/dev/null | awk '{print $5}'))"
    # Check if it came from an auth-related process
    if file "$f" 2>/dev/null | grep -q "ELF"; then
        alert "Core dump at $f may contain plaintext credentials — delete or secure it"
        log_incident "CORE DUMP CREDENTIAL RISK" "$f"
    fi
done

# Disable core dumps for auth processes going forward
info "Core dump limit settings:"
ulimit -c
cat /proc/sys/kernel/core_pattern 2>/dev/null

info "To disable core dumps: ulimit -c 0"

# ============================================================
# SECTION 7: SUDO/SU ACTIVITY MONITORING
# Track who is escalating privileges and how often
# ============================================================
section "SECTION 7: PRIVILEGE ESCALATION ACTIVITY"

AUTH_LOGS=("/var/log/auth.log" "/var/log/secure")

for logfile in "${AUTH_LOGS[@]}"; do
    [ ! -f "$logfile" ] && continue

    info "Sudo activity from $logfile:"
    grep "sudo\|COMMAND" "$logfile" 2>/dev/null | tail -30 | while read line; do
        # Flag sudo to shell
        if echo "$line" | grep -qE "/bin/(bash|sh|zsh|dash)"; then
            alert "SUDO TO SHELL: $line"
            log_incident "SUDO SHELL ESCALATION" "$line"
        else
            info "$line"
        fi
    done

    echo ""
    info "Failed sudo attempts (credential probing):"
    grep "sudo.*incorrect password\|sudo.*authentication failure" "$logfile" 2>/dev/null | tail -10

    echo ""
    info "su attempts:"
    grep "\bsu\b" "$logfile" 2>/dev/null | grep -v "sudo" | tail -10
done

# ============================================================
# SECTION 8: /proc/sysrq-trigger PROTECTION
# echo b > /proc/sysrq-trigger reboots the machine instantly
# echo c > crashes it. Red team can use this as a last resort.
# ============================================================
section "SECTION 8: SYSRQ PROTECTION"

sysrq=$(cat /proc/sys/kernel/sysrq 2>/dev/null)
info "Current sysrq value: $sysrq"
if [ "$sysrq" != "0" ]; then
    warn "SysRq is enabled (value: $sysrq)"
    warn "Red team with write access to /proc/sysrq-trigger can reboot/crash the system"
    warn "To disable: echo 0 > /proc/sys/kernel/sysrq"

    # Check who has write access
    ls -la /proc/sysrq-trigger 2>/dev/null
fi

section "PRIVESC AUDIT COMPLETE"
echo -e "${GRN}Log: $LOGFILE${NC}"
echo -e "${GRN}Incidents: $INCIDENT_LOG${NC}"
