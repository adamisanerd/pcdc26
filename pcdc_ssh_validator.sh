#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  SSH Credential Validator & Multi-Host Asset Mapper
#
#  PURPOSE:
#  You've discovered live hosts on your VLAN via network enum.
#  You have a credential list from your Blue Team Packet (and
#  possibly additional accounts found during audit).
#  This script validates which credentials work on which
#  machines so you know your access surface before the
#  Red Team does.
#
#  USE CASES:
#  - Verify which packet-provided accounts are active
#  - Discover which machines share credentials (lateral risk)
#  - Find accounts that work somewhere they shouldn't
#  - Run your audit/hardening scripts across all machines
#    from a single terminal once access is confirmed
#
#  SCOPE REMINDER:
#  Run this ONLY against hosts on YOUR assigned VLAN.
#  Only use credentials from your Blue Team Packet or
#  accounts you discovered on your own machines.
#
#  Requires: ssh, sshpass (auto-installs if missing)
#  Run as root for full capability.
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
MAG='\033[0;35m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="$LOGDIR/ssh_validator_$TIMESTAMP.log"
RESULTS_FILE="$LOGDIR/credential_map_$TIMESTAMP.txt"
STATE_DIR="$LOGDIR/netstate"

mkdir -p "$LOGDIR" "$STATE_DIR"
exec > >(tee -a "$LOGFILE") 2>&1

ok()      { echo -e "${GRN}[OK]${NC}      $1"; }
warn()    { echo -e "${YLW}[WARN]${NC}    $1"; }
alert()   { echo -e "${RED}[ALERT]${NC}   $1"; }
info()    { echo -e "${CYN}[INFO]${NC}    $1"; }
success() { echo -e "${GRN}[ACCESS]${NC}  $1"; }
fail()    { echo -e "${RED}[FAIL]${NC}    $1"; }
section() {
    echo ""
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ============================================================
# DEPENDENCY CHECK: sshpass
# Needed for non-interactive SSH password auth
# ============================================================
check_deps() {
    if ! command -v sshpass &>/dev/null; then
        warn "sshpass not found. Attempting to install..."
        apt-get install -y sshpass 2>/dev/null || \
        yum install -y sshpass 2>/dev/null || \
        dnf install -y sshpass 2>/dev/null

        if ! command -v sshpass &>/dev/null; then
            warn "Could not install sshpass automatically."
            warn "Manual install: apt install sshpass"
            warn "Falling back to key-based auth only."
            SSHPASS_AVAILABLE=false
        else
            ok "sshpass installed"
            SSHPASS_AVAILABLE=true
        fi
    else
        ok "sshpass available"
        SSHPASS_AVAILABLE=true
    fi

    if ! command -v ssh &>/dev/null; then
        warn "ssh not found — install openssh-client"
        exit 1
    fi
}

# SSH options — strict timeout, no host key prompts
# StrictHostKeyChecking=no because competition systems
# are freshly provisioned; host keys will be unknown
SSH_OPTS="-o StrictHostKeyChecking=no \
          -o ConnectTimeout=5 \
          -o BatchMode=no \
          -o LogLevel=ERROR \
          -o UserKnownHostsFile=/dev/null \
          -o PasswordAuthentication=yes \
          -o PubkeyAuthentication=no"

SSH_OPTS_KEYONLY="-o StrictHostKeyChecking=no \
                  -o ConnectTimeout=5 \
                  -o BatchMode=yes \
                  -o LogLevel=ERROR \
                  -o UserKnownHostsFile=/dev/null \
                  -o PubkeyAuthentication=yes \
                  -o PasswordAuthentication=no"

# ============================================================
# DATA STRUCTURES
# Hosts and credentials loaded interactively or from files
# ============================================================

# Arrays of targets and credentials
declare -a TARGET_HOSTS=()
declare -a USERNAMES=()
declare -a PASSWORDS=()

# Working credentials per host: WORKING[ip] = "user:pass"
declare -A WORKING_CREDS

# ============================================================
# INPUT METHODS
# ============================================================

load_hosts_interactive() {
    section "TARGET HOSTS"
    echo -e "${YLW}Enter the IP addresses of hosts on YOUR VLAN to test.${NC}"
    echo -e "${YLW}These should be machines assigned to your Blue Team.${NC}"
    echo ""

    # Pre-populate from previous network enum if available
    if [ -f "$STATE_DIR/live_ips.baseline" ]; then
        info "Previously discovered hosts (from pcdc_network_enum.sh):"
        cat "$STATE_DIR/live_ips.baseline"
        echo ""
        read -rp "Load these as targets? [y/N]: " ans
        if [[ "$ans" =~ ^[Yy]$ ]]; then
            while read ip; do
                TARGET_HOSTS+=("$ip")
            done < "$STATE_DIR/live_ips.baseline"
            ok "Loaded ${#TARGET_HOSTS[@]} hosts from previous enum"
        fi
    fi

    echo ""
    echo "Enter additional hosts manually (empty line to finish):"
    while true; do
        read -rp "  Host IP (or Enter to finish): " host
        [ -z "$host" ] && break
        # Basic IP format validation
        if echo "$host" | grep -qP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'; then
            TARGET_HOSTS+=("$host")
            ok "Added: $host"
        else
            warn "Invalid IP format: $host — skipping"
        fi
    done

    echo ""
    ok "Total targets: ${#TARGET_HOSTS[@]}"
    for h in "${TARGET_HOSTS[@]}"; do echo "  $h"; done
}

load_hosts_from_file() {
    local file=$1
    while read line; do
        line=$(echo "$line" | tr -d '[:space:]')
        [ -z "$line" ] || [[ "$line" == \#* ]] && continue
        TARGET_HOSTS+=("$line")
    done < "$file"
    ok "Loaded ${#TARGET_HOSTS[@]} hosts from $file"
}

load_credentials_interactive() {
    section "CREDENTIALS"
    echo -e "${YLW}Enter username/password pairs from your Blue Team Packet.${NC}"
    echo -e "${YLW}These are the accounts you need to validate and then change.${NC}"
    echo ""
    echo "Format: enter username, then password for each pair."
    echo "Empty username = done."
    echo ""

    while true; do
        read -rp "  Username (or Enter to finish): " uname
        [ -z "$uname" ] && break
        read -rsp "  Password for $uname: " pass
        echo ""
        USERNAMES+=("$uname")
        PASSWORDS+=("$pass")
        ok "Added credential: $uname / [hidden]"
    done

    echo ""
    ok "Total credential pairs: ${#USERNAMES[@]}"
}

load_credentials_from_file() {
    # File format: username:password (one per line, # for comments)
    local file=$1
    while IFS=: read -r uname pass; do
        [[ "$uname" == \#* ]] || [ -z "$uname" ] && continue
        USERNAMES+=("$uname")
        PASSWORDS+=("$pass")
    done < "$file"
    ok "Loaded ${#USERNAMES[@]} credential pairs from $file"
    warn "Loaded from file — remember to delete credential files after use"
}

# ============================================================
# CORE FUNCTION: Test a single credential against a single host
# Returns: 0 = success, 1 = auth fail, 2 = connection fail
# ============================================================
test_ssh_credential() {
    local host=$1
    local user=$2
    local pass=$3
    local port=${4:-22}

    if ! $SSHPASS_AVAILABLE; then
        # Key-based only fallback
        result=$(ssh $SSH_OPTS_KEYONLY -p "$port" "${user}@${host}" \
            "echo CONNECTED && id && hostname" 2>&1)
        exit_code=$?
    else
        result=$(sshpass -p "$pass" ssh $SSH_OPTS -p "$port" \
            "${user}@${host}" \
            "echo CONNECTED && id && hostname" 2>&1)
        exit_code=$?
    fi

    if echo "$result" | grep -q "CONNECTED"; then
        # Extract useful info from the connection
        remote_id=$(echo "$result" | grep "^uid=\|^id=" | head -1)
        remote_host=$(echo "$result" | grep -v "CONNECTED\|uid=\|Warning\|Pseudo" | \
            tail -1 | tr -d '[:space:]')
        echo "SUCCESS|${remote_id}|${remote_host}"
        return 0
    elif echo "$result" | grep -qi "Permission denied\|Authentication failed\|auth fail"; then
        echo "AUTHFAIL"
        return 1
    elif echo "$result" | grep -qi "Connection refused\|No route\|timeout\|Network unreachable"; then
        echo "CONNFAIL"
        return 2
    else
        echo "ERROR|$result"
        return 3
    fi
}

# ============================================================
# MAIN SCAN: Test all credentials against all hosts
# ============================================================
run_credential_sweep() {
    section "CREDENTIAL SWEEP"

    local total_tests=$(( ${#TARGET_HOSTS[@]} * ${#USERNAMES[@]} ))
    local test_num=0
    local success_count=0
    local fail_count=0
    local conn_fail_count=0

    info "Testing ${#USERNAMES[@]} credential pair(s) against ${#TARGET_HOSTS[@]} host(s)"
    info "Total tests: $total_tests"
    echo ""

    # Initialize results file header
    cat > "$RESULTS_FILE" << EOF
============================================================
ASTRA 9 BLUE TEAM — CREDENTIAL MAP
Generated: $(date)
Hosts tested: ${#TARGET_HOSTS[@]}
Credentials tested: ${#USERNAMES[@]}
============================================================

EOF

    for host in "${TARGET_HOSTS[@]}"; do
        echo ""
        echo -e "${MAG}── Testing host: $host ──${NC}"

        # Quick connectivity check first
        if ! ping -c 1 -W 2 "$host" &>/dev/null; then
            warn "Host $host not responding to ping — skipping"
            echo "HOST $host: UNREACHABLE" >> "$RESULTS_FILE"
            continue
        fi

        # Check if SSH port is open
        if ! timeout 3 bash -c "echo >/dev/tcp/$host/22" 2>/dev/null; then
            warn "SSH port 22 not open on $host — skipping"
            echo "HOST $host: SSH PORT CLOSED" >> "$RESULTS_FILE"
            continue
        fi

        echo "HOST $host:" >> "$RESULTS_FILE"
        host_has_working=false

        for i in "${!USERNAMES[@]}"; do
            uname="${USERNAMES[$i]}"
            pass="${PASSWORDS[$i]}"
            test_num=$((test_num + 1))

            printf "  [%3d/%3d] %-15s / %-20s → " \
                "$test_num" "$total_tests" "$uname" "[password]"

            result=$(test_ssh_credential "$host" "$uname" "$pass")
            exit_code=$?

            case $exit_code in
                0)
                    success_count=$((success_count + 1))
                    remote_info=$(echo "$result" | cut -d'|' -f2)
                    remote_hostname=$(echo "$result" | cut -d'|' -f3)
                    echo -e "${GRN}ACCESS GRANTED${NC} ($remote_info @ $remote_hostname)"

                    # Store working credential for this host
                    # Keep the first working cred, note all of them
                    if ! $host_has_working; then
                        WORKING_CREDS["$host"]="$uname:$pass"
                        host_has_working=true
                    fi

                    # Log to results file
                    echo "  [SUCCESS] $uname / [pass] → $remote_info" >> "$RESULTS_FILE"

                    # Flag if this looks like a root/privileged account
                    if echo "$remote_info" | grep -q "uid=0\|root"; then
                        alert "  ROOT ACCESS confirmed on $host as $uname"
                        echo "  [ROOT ACCESS] $uname has root/UID0 on $host" >> "$RESULTS_FILE"
                    fi
                    ;;
                1)
                    fail_count=$((fail_count + 1))
                    echo -e "${RED}AUTH FAILED${NC}"
                    echo "  [FAIL]    $uname / [pass]" >> "$RESULTS_FILE"
                    ;;
                2)
                    conn_fail_count=$((conn_fail_count + 1))
                    echo -e "${YLW}CONN ERROR${NC}"
                    break  # No point testing more creds if host unreachable
                    ;;
                *)
                    echo -e "${YLW}ERROR${NC}"
                    ;;
            esac

            # Small delay to avoid overwhelming the host
            sleep 0.2
        done

        if ! $host_has_working; then
            warn "No working credentials found for $host"
            echo "  [NO ACCESS] No credentials worked for this host" >> "$RESULTS_FILE"
        fi

        echo "" >> "$RESULTS_FILE"
    done

    echo ""
    section "SWEEP SUMMARY"
    ok "Tests completed: $test_num"
    ok "Successful logins: $success_count"
    info "Auth failures: $fail_count"
    info "Connection failures: $conn_fail_count"
}

# ============================================================
# POST-SWEEP: Deep dive on working credentials
# Once we know what works, pull system info from each host
# ============================================================
run_remote_audit() {
    section "REMOTE HOST INFORMATION GATHERING"

    if [ ${#WORKING_CREDS[@]} -eq 0 ]; then
        warn "No working credentials found — skipping remote audit"
        return
    fi

    info "Gathering system information from ${#WORKING_CREDS[@]} accessible host(s)..."
    echo ""

    for host in "${!WORKING_CREDS[@]}"; do
        creds="${WORKING_CREDS[$host]}"
        uname=$(echo "$creds" | cut -d: -f1)
        pass=$(echo "$creds" | cut -d: -f2-)

        echo ""
        echo -e "${MAG}── Remote Info: $host (as $uname) ──${NC}"

        # Pull key info in a single SSH connection to minimize overhead
        REMOTE_CMD='
echo "=== HOSTNAME ==="
hostname

echo "=== OS ==="
cat /etc/os-release 2>/dev/null | grep "^PRETTY_NAME\|^NAME\|^VERSION" | head -3
uname -r

echo "=== UPTIME ==="
uptime

echo "=== USERS ==="
awk -F: '"'"'($3 == 0 || $3 >= 1000) && $7 !~ /nologin|false/ {print $1, "UID="$3, $7}'"'"' /etc/passwd

echo "=== LISTENING PORTS ==="
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

echo "=== RUNNING SERVICES ==="
systemctl list-units --type=service --state=running 2>/dev/null | grep -E "apache|nginx|mysql|maria|postfix|named|ftp|smb|ssh" | head -10

echo "=== DISK ==="
df -h / 2>/dev/null

echo "=== INTERFACES ==="
ip addr show 2>/dev/null | grep -E "^[0-9]+:|inet "

echo "=== SUDO ==="
sudo -l 2>/dev/null | head -10
'
        if $SSHPASS_AVAILABLE; then
            remote_result=$(sshpass -p "$pass" ssh $SSH_OPTS \
                "${uname}@${host}" "$REMOTE_CMD" 2>/dev/null)
        else
            remote_result=$(ssh $SSH_OPTS_KEYONLY \
                "${uname}@${host}" "$REMOTE_CMD" 2>/dev/null)
        fi

        if [ -n "$remote_result" ]; then
            echo "$remote_result"

            # Append to results file
            echo "" >> "$RESULTS_FILE"
            echo "REMOTE INFO: $host" >> "$RESULTS_FILE"
            echo "$remote_result" >> "$RESULTS_FILE"

            # Flag specific concerns from remote data
            if echo "$remote_result" | grep -q "telnet\|:23 "; then
                alert "Telnet running on $host — disable immediately"
            fi
            if echo "$remote_result" | grep -q ":3306 " | grep -v "127\.0\.0\.1"; then
                warn "MySQL may be network-exposed on $host"
            fi
            if echo "$remote_result" | grep -q "UID=0" | grep -v "^root"; then
                alert "Non-root UID=0 account on $host — backdoor risk"
            fi
        else
            warn "Could not retrieve remote info from $host"
        fi
    done
}

# ============================================================
# REMOTE SCRIPT DEPLOYMENT
# Push and run your audit/hardening scripts across all
# accessible machines from this single terminal
# ============================================================
deploy_scripts_remotely() {
    section "REMOTE SCRIPT DEPLOYMENT"

    if [ ${#WORKING_CREDS[@]} -eq 0 ]; then
        warn "No working credentials — cannot deploy scripts"
        return
    fi

    echo -e "${YLW}Available scripts to deploy:${NC}"
    echo "  1) pcdc_linux_audit.sh     — read-only audit (safe, run first)"
    echo "  2) pcdc_alias_detector_v2.sh — shell poisoning check"
    echo "  3) pcdc_privesc_detector.sh  — privilege escalation check"
    echo "  4) pcdc_webapp_audit.sh      — web app security check"
    echo "  5) Custom command"
    echo "  0) Skip deployment"
    echo ""
    read -rp "Deploy which script? [0-5]: " choice

    [ "$choice" = "0" ] && return

    SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
    REMOTE_TMPDIR="/tmp/.blueTeam_$$"

    for host in "${!WORKING_CREDS[@]}"; do
        creds="${WORKING_CREDS[$host]}"
        uname=$(echo "$creds" | cut -d: -f1)
        pass=$(echo "$creds" | cut -d: -f2-)

        echo ""
        info "Deploying to $host as $uname..."

        case $choice in
            1) SCRIPT="$SCRIPT_DIR/pcdc_linux_audit.sh" ;;
            2) SCRIPT="$SCRIPT_DIR/pcdc_alias_detector_v2.sh" ;;
            3) SCRIPT="$SCRIPT_DIR/pcdc_privesc_detector.sh" ;;
            4) SCRIPT="$SCRIPT_DIR/pcdc_webapp_audit.sh" ;;
            5)
                read -rp "Enter full path to script: " SCRIPT
                ;;
        esac

        if [ ! -f "$SCRIPT" ]; then
            warn "Script not found: $SCRIPT"
            continue
        fi

        # Copy script to remote host
        if $SSHPASS_AVAILABLE; then
            sshpass -p "$pass" scp \
                -o StrictHostKeyChecking=no \
                -o LogLevel=ERROR \
                "$SCRIPT" "${uname}@${host}:${REMOTE_TMPDIR}_audit.sh" 2>/dev/null

            # Execute remotely
            info "Running $(basename $SCRIPT) on $host..."
            sshpass -p "$pass" ssh $SSH_OPTS "${uname}@${host}" \
                "chmod +x ${REMOTE_TMPDIR}_audit.sh && \
                 sudo /bin/bash ${REMOTE_TMPDIR}_audit.sh 2>/dev/null; \
                 rm -f ${REMOTE_TMPDIR}_audit.sh" 2>/dev/null | \
                tee "$LOGDIR/remote_$(echo $host | tr . _)_$(basename $SCRIPT)_$TIMESTAMP.log"
        else
            scp $SSH_OPTS_KEYONLY \
                "$SCRIPT" "${uname}@${host}:${REMOTE_TMPDIR}_audit.sh" 2>/dev/null
            ssh $SSH_OPTS_KEYONLY "${uname}@${host}" \
                "chmod +x ${REMOTE_TMPDIR}_audit.sh && \
                 sudo /bin/bash ${REMOTE_TMPDIR}_audit.sh; \
                 rm -f ${REMOTE_TMPDIR}_audit.sh" 2>/dev/null | \
                tee "$LOGDIR/remote_$(echo $host | tr . _)_$(basename $SCRIPT)_$TIMESTAMP.log"
        fi

        ok "Done: $host — log saved to $LOGDIR/"
    done
}

# ============================================================
# CREDENTIAL REUSE ANALYSIS
# Highlights dangerous patterns — same creds on multiple hosts
# ============================================================
analyze_credential_reuse() {
    section "CREDENTIAL REUSE ANALYSIS"

    info "Checking for credential reuse across hosts..."
    info "Shared credentials = if one host is compromised, they all are"
    echo ""

    # Group hosts by working credential pair
    declare -A CRED_TO_HOSTS

    for host in "${!WORKING_CREDS[@]}"; do
        cred="${WORKING_CREDS[$host]}"
        uname=$(echo "$cred" | cut -d: -f1)
        # Don't store passwords in the display — just note the username
        if [ -z "${CRED_TO_HOSTS[$uname]}" ]; then
            CRED_TO_HOSTS["$uname"]="$host"
        else
            CRED_TO_HOSTS["$uname"]="${CRED_TO_HOSTS[$uname]} $host"
        fi
    done

    for uname in "${!CRED_TO_HOSTS[@]}"; do
        hosts="${CRED_TO_HOSTS[$uname]}"
        host_count=$(echo "$hosts" | wc -w)

        if [ "$host_count" -gt 1 ]; then
            warn "Credential reuse: '$uname' works on $host_count hosts: $hosts"
            warn "  → Change passwords on each host to UNIQUE values immediately"
            echo "CRED REUSE: $uname works on: $hosts" >> "$RESULTS_FILE"
        else
            ok "Unique: '$uname' only works on: $hosts"
        fi
    done
}

# ============================================================
# PRINT FINAL RESULTS TABLE
# ============================================================
print_results_table() {
    section "RESULTS SUMMARY"

    echo -e "${BLU}Host            │ Username        │ Access  │ Privilege${NC}"
    echo -e "${BLU}────────────────┼─────────────────┼─────────┼──────────${NC}"

    for host in "${TARGET_HOSTS[@]}"; do
        if [ -n "${WORKING_CREDS[$host]}" ]; then
            uname=$(echo "${WORKING_CREDS[$host]}" | cut -d: -f1)
            # Check if root access
            is_root=""
            grep "ROOT ACCESS.*$host\|$host.*ROOT ACCESS" "$RESULTS_FILE" &>/dev/null && \
                is_root="${RED}ROOT${NC}"

            printf "%-15s │ %-15s │ ${GRN}%-7s${NC} │ %s\n" \
                "$host" "$uname" "YES" "$is_root"
        else
            printf "%-15s │ %-15s │ ${RED}%-7s${NC} │\n" \
                "$host" "N/A" "NO"
        fi
    done

    echo ""
    echo -e "${YLW}Full results saved to: $RESULTS_FILE${NC}"
    echo ""

    # Priority action list
    echo -e "${YLW}PRIORITY ACTIONS based on results:${NC}"
    echo ""

    local no_access_hosts=()
    for host in "${TARGET_HOSTS[@]}"; do
        [ -z "${WORKING_CREDS[$host]}" ] && no_access_hosts+=("$host")
    done

    if [ ${#no_access_hosts[@]} -gt 0 ]; then
        alert "Hosts with NO working credentials:"
        for h in "${no_access_hosts[@]}"; do
            echo "  $h — check if SSH is running, verify packet credentials"
        done
        echo ""
    fi

    if [ ${#WORKING_CREDS[@]} -gt 0 ]; then
        ok "Accessible hosts — change passwords NOW (before Red Team attacks):"
        for host in "${!WORKING_CREDS[@]}"; do
            uname=$(echo "${WORKING_CREDS[$host]}" | cut -d: -f1)
            echo "  $host → ssh ${uname}@${host} → passwd"
        done
    fi
}

# ============================================================
# MAIN
# ============================================================
clear
echo -e "${BLU}"
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │   ASTRA 9 SSH CREDENTIAL VALIDATOR               │"
echo "  │   Blue Team Asset Verification | PCDC 2026       │"
echo "  └──────────────────────────────────────────────────┘"
echo -e "${NC}"
echo "  Run against: YOUR VLAN hosts only"
echo "  Credentials: From your Blue Team Packet"
echo "  Log:         $LOGFILE"
echo ""

check_deps

echo ""
echo -e "${YLW}Input method:${NC}"
echo "  1) Enter hosts and credentials interactively"
echo "  2) Load hosts from file + credentials interactively"
echo "  3) Load both from files"
echo "       Hosts file format:       one IP per line"
echo "       Credentials file format: username:password (one per line)"
echo ""
read -rp "Choice [1/2/3]: " input_method

case $input_method in
    1)
        load_hosts_interactive
        load_credentials_interactive
        ;;
    2)
        read -rp "Hosts file path: " hosts_file
        load_hosts_from_file "$hosts_file"
        load_credentials_interactive
        ;;
    3)
        read -rp "Hosts file path: " hosts_file
        read -rp "Credentials file path: " creds_file
        load_hosts_from_file "$hosts_file"
        load_credentials_from_file "$creds_file"
        warn "Credential files on disk are a security risk."
        warn "Delete after use: rm -f $creds_file"
        ;;
    *)
        warn "Invalid choice — defaulting to interactive"
        load_hosts_interactive
        load_credentials_interactive
        ;;
esac

if [ ${#TARGET_HOSTS[@]} -eq 0 ] || [ ${#USERNAMES[@]} -eq 0 ]; then
    warn "No hosts or credentials provided. Exiting."
    exit 1
fi

# Confirm before running
echo ""
echo -e "${YLW}Ready to test:${NC}"
echo "  Hosts:       ${#TARGET_HOSTS[@]}"
echo "  Credentials: ${#USERNAMES[@]}"
echo "  Total tests: $(( ${#TARGET_HOSTS[@]} * ${#USERNAMES[@]} ))"
echo ""
read -rp "Proceed? [y/N]: " confirm
[[ ! "$confirm" =~ ^[Yy]$ ]] && echo "Aborted." && exit 0

# Run the sweep
run_credential_sweep

# Analyze reuse
analyze_credential_reuse

# Gather remote info from accessible hosts
echo ""
read -rp "Pull system info from accessible hosts? [Y/n]: " pull_info
[[ ! "$pull_info" =~ ^[Nn]$ ]] && run_remote_audit

# Deploy scripts
echo ""
read -rp "Deploy audit scripts to accessible hosts? [Y/n]: " deploy
[[ ! "$deploy" =~ ^[Nn]$ ]] && deploy_scripts_remotely

# Print summary
print_results_table

echo ""
echo -e "${GRN}Log:     $LOGFILE${NC}"
echo -e "${GRN}Results: $RESULTS_FILE${NC}"
echo ""
echo -e "${YLW}SECURITY NOTE:${NC}"
echo "  This script does not store passwords on disk in the results file."
echo "  If you loaded credentials from a file, delete it:"
echo "  history -c && rm -f <credentials_file>"
echo ""
