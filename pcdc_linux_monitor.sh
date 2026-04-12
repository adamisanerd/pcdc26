#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Continuous Monitor & Persistence Hunter
#  Run in a dedicated terminal. Loops every N seconds.
#  Alerts on changes. Logs incidents for your report.
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
INCIDENT_LOG="$LOGDIR/incidents_$TIMESTAMP.log"
STATE_DIR="$LOGDIR/state"

mkdir -p "$LOGDIR" "$STATE_DIR"

INTERVAL=${1:-60}  # default: check every 60 seconds

ok()       { echo -e "${GRN}[OK]${NC}       $1"; }
warn()     { echo -e "${YLW}[WARN]${NC}     $1"; }
alert()    { 
    local msg="$1"
    echo -e "${RED}[ALERT]${NC}    $msg"
    echo "[$(date)] ALERT: $msg" >> "$INCIDENT_LOG"
}
info()     { echo -e "${CYN}[INFO]${NC}     $1"; }

log_incident() {
    local type=$1
    local detail=$2
    local src_ip=$3
    local dst_ip
    dst_ip=$(hostname -I | awk '{print $1}')
    cat >> "$INCIDENT_LOG" << EOF

============================================================
INCIDENT DETECTED
============================================================
Time:       $(date)
Type:       $type
Detail:     $detail
Source IP:  ${src_ip:-UNKNOWN}
System IP:  $dst_ip
Hostname:   $(hostname)
============================================================
EOF
    echo -e "${RED}[INCIDENT LOGGED]${NC} $type — see $INCIDENT_LOG"
}

# ============================================================
# BASELINE: capture initial state to diff against
# ============================================================
baseline() {
    info "Capturing baseline state..."

    # User list
    cut -d: -f1 /etc/passwd | sort > "$STATE_DIR/users.baseline"

    # Listening ports
    ss -tulnp 2>/dev/null | sort > "$STATE_DIR/ports.baseline"

    # Running processes (by name)
    ps aux | awk '{print $11}' | sort -u > "$STATE_DIR/procs.baseline"

    # Crontabs
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -u "$user" -l 2>/dev/null
    done | sort > "$STATE_DIR/crons.baseline"
    cat /etc/cron.d/* 2>/dev/null | sort >> "$STATE_DIR/crons.baseline"

    # Authorized keys
    find /home /root -name "authorized_keys" -exec cat {} \; 2>/dev/null | sort > "$STATE_DIR/authkeys.baseline"

    # SUID binaries
    find / -perm -4000 -type f 2>/dev/null | sort > "$STATE_DIR/suid.baseline"

    # /etc/passwd hash
    md5sum /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null > "$STATE_DIR/passwdfiles.baseline"

    ok "Baseline captured. Monitoring every ${INTERVAL}s."
    echo ""
}

# ============================================================
# CHECK FUNCTIONS
# ============================================================

check_new_users() {
    cut -d: -f1 /etc/passwd | sort > "$STATE_DIR/users.current"
    local new_users
    new_users=$(comm -13 "$STATE_DIR/users.baseline" "$STATE_DIR/users.current")
    if [ -n "$new_users" ]; then
        alert "NEW USER(S) DETECTED: $new_users"
        log_incident "NEW USER ACCOUNT" "$new_users" ""
        # Update baseline
        cp "$STATE_DIR/users.current" "$STATE_DIR/users.baseline"
    fi

    # Check for UID 0 accounts other than root
    awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read user; do
        alert "UID 0 ACCOUNT EXISTS: $user — BACKDOOR SUSPECTED"
        log_incident "UID 0 BACKDOOR ACCOUNT" "User: $user" ""
    done
}

check_new_ports() {
    ss -tulnp 2>/dev/null | sort > "$STATE_DIR/ports.current"
    local new_ports
    new_ports=$(comm -13 "$STATE_DIR/ports.baseline" "$STATE_DIR/ports.current")
    if [ -n "$new_ports" ]; then
        alert "NEW LISTENING PORT DETECTED:"
        echo "$new_ports"
        log_incident "NEW OPEN PORT" "$new_ports" ""
        cp "$STATE_DIR/ports.current" "$STATE_DIR/ports.baseline"
    fi
}

check_new_processes() {
    ps aux | awk '{print $11}' | sort -u > "$STATE_DIR/procs.current"
    local new_procs
    new_procs=$(comm -13 "$STATE_DIR/procs.baseline" "$STATE_DIR/procs.current")
    if [ -n "$new_procs" ]; then
        # Filter noise
        filtered=$(echo "$new_procs" | grep -v -E '^\[|ps|awk|sort|comm|bash|sh$|grep|tee')
        if [ -n "$filtered" ]; then
            warn "New processes detected: $filtered"
        fi
        cp "$STATE_DIR/procs.current" "$STATE_DIR/procs.baseline"
    fi
}

check_cron_changes() {
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -u "$user" -l 2>/dev/null
    done | sort > "$STATE_DIR/crons.current"
    cat /etc/cron.d/* 2>/dev/null | sort >> "$STATE_DIR/crons.current"

    if ! diff -q "$STATE_DIR/crons.baseline" "$STATE_DIR/crons.current" &>/dev/null; then
        alert "CRON CHANGE DETECTED:"
        diff "$STATE_DIR/crons.baseline" "$STATE_DIR/crons.current"
        log_incident "CRON JOB MODIFIED" "$(diff "$STATE_DIR/crons.baseline" "$STATE_DIR/crons.current")" ""
        cp "$STATE_DIR/crons.current" "$STATE_DIR/crons.baseline"
    fi
}

check_authkeys() {
    find /home /root -name "authorized_keys" -exec cat {} \; 2>/dev/null | sort > "$STATE_DIR/authkeys.current"
    if ! diff -q "$STATE_DIR/authkeys.baseline" "$STATE_DIR/authkeys.current" &>/dev/null; then
        alert "AUTHORIZED_KEYS CHANGED — POSSIBLE BACKDOOR:"
        diff "$STATE_DIR/authkeys.baseline" "$STATE_DIR/authkeys.current"
        log_incident "AUTHORIZED_KEYS MODIFIED" "$(diff "$STATE_DIR/authkeys.baseline" "$STATE_DIR/authkeys.current")" ""
        cp "$STATE_DIR/authkeys.current" "$STATE_DIR/authkeys.baseline"
    fi
}

check_passwd_files() {
    md5sum /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null > "$STATE_DIR/passwdfiles.current"
    if ! diff -q "$STATE_DIR/passwdfiles.baseline" "$STATE_DIR/passwdfiles.current" &>/dev/null; then
        alert "CRITICAL: /etc/passwd, /etc/shadow, or /etc/sudoers has been modified!"
        diff "$STATE_DIR/passwdfiles.baseline" "$STATE_DIR/passwdfiles.current"
        log_incident "PASSWD/SHADOW/SUDOERS MODIFIED" "$(diff "$STATE_DIR/passwdfiles.baseline" "$STATE_DIR/passwdfiles.current")" ""
        cp "$STATE_DIR/passwdfiles.current" "$STATE_DIR/passwdfiles.baseline"
    fi
}

check_suid() {
    find / -perm -4000 -type f 2>/dev/null | sort > "$STATE_DIR/suid.current"
    local new_suid
    new_suid=$(comm -13 "$STATE_DIR/suid.baseline" "$STATE_DIR/suid.current")
    if [ -n "$new_suid" ]; then
        alert "NEW SUID BINARY DETECTED — PRIVILEGE ESCALATION RISK: $new_suid"
        log_incident "NEW SUID BINARY" "$new_suid" ""
        cp "$STATE_DIR/suid.current" "$STATE_DIR/suid.baseline"
    fi
}

check_failed_logins() {
    # Count recent failures
    local fail_count
    fail_count=$(grep "Failed password" /var/log/auth.log 2>/dev/null | \
        awk -v since="$(date -d '2 minutes ago' '+%b %e %H:%M')" '$0 >= since' | wc -l)
    if [ "$fail_count" -gt 5 ]; then
        local attacking_ip
        attacking_ip=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 | \
            grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
        alert "BRUTE FORCE DETECTED: $fail_count failures in last 2 min. Top source: $attacking_ip"
        log_incident "BRUTE FORCE ATTACK" "$fail_count failed attempts" "$attacking_ip"
    fi
}

check_temp_executables() {
    find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | while read f; do
        alert "EXECUTABLE IN TEMP DIR: $f"
        log_incident "MALWARE STAGING" "Executable found in temp: $f" ""
    done
}

check_outbound_connections() {
    # Look for unexpected outbound — flag non-standard ports
    ss -tnp state established 2>/dev/null | grep -v -E ':22 |:80 |:443 |:25 |:53 |:3306 |:5432 ' | \
    grep -v "ESTABLISHED" | head -5 | while read line; do
        warn "Unusual outbound connection: $line"
    done

    # Look for established connections with suspicious foreign IPs
    ss -tnp state established 2>/dev/null | tail -n +2 | while read line; do
        local foreign
        foreign=$(echo "$line" | awk '{print $5}')
        local port
        port=$(echo "$foreign" | rev | cut -d: -f1 | rev)
        # Flag high ephemeral ports making inbound connections (potential reverse shells)
        if [[ "$port" -gt 1024 ]] && [[ "$port" -lt 65535 ]]; then
            info "Established: $line"
        fi
    done
}

check_deleted_but_running() {
    for exe_link in /proc/*/exe; do
        target=$(readlink "$exe_link" 2>/dev/null)
        if [[ "$target" == *"(deleted)"* ]]; then
            alert "DELETED BINARY STILL RUNNING (common malware): $exe_link -> $target"
            log_incident "RUNNING DELETED BINARY" "$exe_link -> $target" ""
        fi
    done
}

# ============================================================
# SERVICE HEALTH CHECK
# ============================================================
SCORED_SERVICES=()  # Populated at runtime via argument or prompt

prompt_services() {
    echo ""
    info "Enter the names of your scored services (space-separated)."
    info "Examples: apache2 nginx mysql ssh named vsftpd postfix smbd"
    read -rp "Services: " -a SCORED_SERVICES
    echo ""
    ok "Monitoring services: ${SCORED_SERVICES[*]}"
    echo ""
}

check_services() {
    for svc in "${SCORED_SERVICES[@]}"; do
        if ! systemctl is-active --quiet "$svc" 2>/dev/null; then
            alert "SCORED SERVICE DOWN: $svc"
            log_incident "SERVICE DOWN" "Service $svc is not running" ""
            info "Attempting to restart $svc..."
            systemctl restart "$svc" 2>/dev/null
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                ok "Restarted: $svc"
            else
                bad "FAILED to restart: $svc — MANUAL INTERVENTION NEEDED"
            fi
        fi
    done
}

# ============================================================
# INCIDENT REPORT GENERATOR
# ============================================================
generate_incident_report() {
    local outfile
    outfile="$LOGDIR/incident_report_$(date +%Y%m%d_%H%M%S).txt"
    cat > "$outfile" << EOF
============================================================
PCDC 2026 | ASTRA 9 BLUE TEAM
INCIDENT REPORT
============================================================
Team:           [YOUR TEAM NAME]
System:         $(hostname)
System IP:      $(hostname -I | awk '{print $1}')
Report Time:    $(date)
Report Author:  [YOUR NAME]

------------------------------------------------------------
INCIDENT SUMMARY
------------------------------------------------------------
$(cat "$INCIDENT_LOG" 2>/dev/null || echo "No incidents logged yet.")

------------------------------------------------------------
CURRENT SYSTEM STATE
------------------------------------------------------------
Logged-in users:
$(who)

Active connections:
$(ss -tnp state established 2>/dev/null)

Recent auth events:
$(grep -E "Failed|sudo|Accepted|Invalid" /var/log/auth.log 2>/dev/null | tail -20)

============================================================
END OF REPORT
============================================================
EOF
    ok "Incident report generated: $outfile"
    echo "$outfile"
}

# ============================================================
# MAIN LOOP
# ============================================================
clear
echo -e "${BLU}"
echo "  ____  ____ ____   ____ "
echo " |  _ \\/ ___|  _ \\ / ___|"
echo " | |_) \\__ \\| | | | |    "
echo " |  __/ ___) | |_| | |___ "
echo " |_|  |____/|____/ \\____|"
echo ""
echo "  ASTRA 9 BLUE TEAM MONITOR"
echo "  PCDC 2026"
echo -e "${NC}"
echo ""
echo -e "Host: $(hostname) | IP: $(hostname -I | awk '{print $1}')"
echo -e "Incident log: $INCIDENT_LOG"
echo -e "Check interval: ${INTERVAL}s"
echo ""

prompt_services
baseline

echo ""
info "Starting monitoring loop. Press Ctrl+C to stop."
info "Type 'r' + Enter at any time to generate an incident report."
echo ""

LOOP=0
while true; do
    LOOP=$((LOOP + 1))
    echo -e "${BLU}--- Check #$LOOP | $(date) ---${NC}"

    check_new_users
    check_new_ports
    check_new_processes
    check_cron_changes
    check_authkeys
    check_passwd_files
    check_suid
    check_failed_logins
    check_temp_executables
    check_deleted_but_running
    check_services

    echo ""

    # Non-blocking read for 'r' to generate report
    read -t "$INTERVAL" -n 1 key 2>/dev/null
    if [[ "$key" == "r" ]]; then
        generate_incident_report
    fi
done
