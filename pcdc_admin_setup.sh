#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Admin Client Setup & Covert Remote Execution Framework
#
#  PURPOSE:
#  Your Ubuntu admin machine is your command center.
#  Running scripts DIRECTLY on target machines means:
#  - Your processes show up in 'ps aux' on the target
#  - Your script files sit in /tmp on the target
#  - Red team watching process lists sees your activity
#  - Your bash history on the target reveals your methods
#
#  Running from THIS machine means:
#  - Target only sees an SSH connection — completely normal
#  - Your scripts never touch the target filesystem
#  - Red team watching the target sees nothing unusual
#  - All your tooling stays on YOUR machine
#  - If red team compromises a target, your admin client
#    is untouched and you maintain visibility
#
#  This script sets up your admin machine and provides
#  functions for running any script covertly via:
#    1. SSH pipe    — script runs in memory, never written to target disk
#    2. SSH heredoc — inline commands, no file transfer needed
#    3. Parallel    — hit all your hosts simultaneously
#
#  Run this script ONCE to set up your admin environment.
#  Then use the functions it installs into your shell.
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
MAG='\033[0;35m'
NC='\033[0m'

LOGDIR="$HOME/blueTeam/logs"
KEYDIR="$HOME/blueTeam/keys"
HOSTFILE="$HOME/blueTeam/hosts.txt"
SCRIPTDIR="$HOME/blueTeam/scripts"
PROFILEFILE="$HOME/.blueTeam_profile"

mkdir -p "$LOGDIR" "$KEYDIR" "$SCRIPTDIR"

ok()      { echo -e "${GRN}[OK]${NC}      $1"; }
warn()    { echo -e "${YLW}[WARN]${NC}    $1"; }
alert()   { echo -e "${RED}[ALERT]${NC}   $1"; }
info()    { echo -e "${CYN}[INFO]${NC}    $1"; }
section() {
    echo ""
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ============================================================
# STEP 1: HARDEN YOUR OWN ADMIN MACHINE FIRST
# Your admin client is the most valuable machine on the
# network — it has credentials to everything else.
# If it gets compromised, everything is compromised.
# ============================================================
section "STEP 1: HARDEN ADMIN CLIENT"

info "Hardening YOUR Ubuntu admin machine..."

# Disable unnecessary services on admin machine
for svc in avahi-daemon cups bluetooth; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        systemctl stop "$svc" && systemctl disable "$svc"
        ok "Disabled: $svc"
    fi
done

# Ensure firewall is up on admin machine — allow only outbound
if command -v ufw &>/dev/null; then
    ufw --force reset 2>/dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
    ok "UFW firewall configured: deny incoming, allow outgoing"
fi

# No SSH server on admin machine unless you need it
# (If red team can't SSH into your admin machine, they can't use it)
if systemctl is-active --quiet ssh 2>/dev/null || \
   systemctl is-active --quiet sshd 2>/dev/null; then
    warn "SSH server running on YOUR admin machine"
    warn "Consider: systemctl stop ssh && systemctl disable ssh"
    warn "If you need inbound SSH, harden it heavily."
fi

# Disable bash history for this session — your commands stay private
# Uncomment if you want full opsec (but you lose your own history too)
# export HISTFILE=/dev/null
# export HISTSIZE=0
info "To disable command history for this session: export HISTFILE=/dev/null"

# ============================================================
# STEP 2: INSTALL DEPENDENCIES ON ADMIN MACHINE
# ============================================================
section "STEP 2: INSTALL ADMIN TOOLS"

DEPS=("sshpass" "nmap" "tmux" "netcat-openbsd" "curl" "tcpdump" "tshark" "whois")

for dep in "${DEPS[@]}"; do
    if ! command -v "$dep" &>/dev/null; then
        info "Installing: $dep"
        apt-get install -y "$dep" 2>/dev/null && ok "Installed: $dep" || warn "Failed: $dep"
    else
        ok "Already installed: $dep"
    fi
done

# ============================================================
# STEP 3: SSH KEY SETUP
# Key auth is better than password auth for repeated operations:
# - No password visible in process list or command history
# - Faster (no password prompt in scripts)
# - Can be passphrase-protected for security
# We generate a competition-specific key pair here
# ============================================================
section "STEP 3: SSH KEY PAIR GENERATION"

COMP_KEY="$KEYDIR/pcdc_admin"

if [ ! -f "$COMP_KEY" ]; then
    info "Generating competition SSH key pair..."
    ssh-keygen -t ed25519 \
               -f "$COMP_KEY" \
               -C "pcdc2026_blueteam_admin" \
               -N "" 2>/dev/null   # No passphrase for competition speed
                                   # Add one if you have time: -N "yourpassphrase"
    ok "Key generated: $COMP_KEY"
    ok "Public key: ${COMP_KEY}.pub"
else
    ok "Key already exists: $COMP_KEY"
fi

info "Your public key (copy this to target machines' authorized_keys):"
echo ""
cat "${COMP_KEY}.pub"
echo ""

# ============================================================
# STEP 4: SSH CONFIG FILE
# Defines connection profiles per host so you can just type
# 'ssh webserver' instead of 'ssh -i /path/to/key root@10.0.1.10'
# ============================================================
section "STEP 4: SSH CONFIG SETUP"

SSH_CONFIG="$HOME/.ssh/config"
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

# We'll write host entries as we discover machines
# For now, set global SSH defaults for the competition environment

cat >> "$SSH_CONFIG" << 'EOF'

# ── PCDC 2026 Blue Team Admin Client Config ──────────────────
Host pcdc-*
    IdentityFile ~/blueTeam/keys/pcdc_admin
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel ERROR
    ConnectTimeout 5
    ServerAliveInterval 10
    ServerAliveCountMax 3
    # Compression helps on slow competition networks
    Compression yes
    # ControlMaster allows SSH connection reuse
    # Same TCP connection for multiple SSH commands = faster + less network noise
    ControlMaster auto
    ControlPath /tmp/.ssh-control-%r@%h:%p
    ControlPersist 10m

EOF

chmod 600 "$SSH_CONFIG"
ok "SSH config written to $SSH_CONFIG"
info "Name your hosts in /etc/hosts and prefix with 'pcdc-' to use this profile"

# ============================================================
# STEP 5: HOST MANAGEMENT FUNCTIONS
# Written to a profile file you source into your shell
# ============================================================
section "STEP 5: INSTALLING SHELL FUNCTIONS"

cat > "$PROFILEFILE" << 'PROFILE_EOF'
# ============================================================
#  PCDC 2026 Blue Team — Admin Shell Functions
#  Source this file: source ~/.blueTeam_profile
#  Or add to .bashrc: echo "source ~/.blueTeam_profile" >> ~/.bashrc
# ============================================================

BLUETEAM_DIR="$HOME/blueTeam"
BLUETEAM_LOGS="$HOME/blueTeam/logs"
BLUETEAM_KEY="$HOME/blueTeam/keys/pcdc_admin"
BLUETEAM_SCRIPTS="$HOME/blueTeam/scripts"

# Colors
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; NC='\033[0m'

# ── SSH shorthand with competition key ────────────────────────
# Usage: bt_ssh root@10.0.1.10
# or with sshpass: bt_ssh root@10.0.1.10 "password"
bt_ssh() {
    local target=$1
    local pass=$2
    local TIMESTAMP
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)

    if [ -n "$pass" ]; then
        sshpass -p "$pass" ssh \
            -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=5 \
            -o ControlMaster=auto \
            -o "ControlPath=/tmp/.ssh-ctrl-%r@%h:%p" \
            -o ControlPersist=10m \
            "$target"
    else
        ssh \
            -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=5 \
            -o ControlMaster=auto \
            -o "ControlPath=/tmp/.ssh-ctrl-%r@%h:%p" \
            -o ControlPersist=10m \
            "$target"
    fi
}

# ── COVERT REMOTE SCRIPT EXECUTION ───────────────────────────
# The key function. Pipes a script through SSH stdin.
# The script NEVER touches the target's filesystem.
# Target only sees: an SSH connection running bash
# No files in /tmp, no entries in package managers,
# no script name in process list — just "bash"
#
# Usage: bt_run_covert <script_path> <user@host> [password]
bt_run_covert() {
    local script=$1
    local target=$2
    local pass=$3
    local TIMESTAMP host_clean
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    host_clean=$(echo "$target" | tr '@.' '_')
    local log="$BLUETEAM_LOGS/covert_${host_clean}_$(basename $script)_${TIMESTAMP}.log"

    if [ ! -f "$script" ]; then
        echo -e "${RED}[ERR]${NC} Script not found: $script"
        return 1
    fi

    echo -e "${CYN}[RUN]${NC} $(basename $script) → $target (covert pipe)"
    echo -e "${CYN}[LOG]${NC} $log"

    # The magic: cat the script and pipe it to bash on the remote host
    # 'bash -s' reads commands from stdin
    # The script is NEVER written to any file on the remote host
    # sudo -S reads password from stdin when combined with echo
    if [ -n "$pass" ]; then
        cat "$script" | sshpass -p "$pass" ssh \
            -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=5 \
            -o ControlMaster=auto \
            -o "ControlPath=/tmp/.ssh-ctrl-%r@%h:%p" \
            -o ControlPersist=10m \
            "$target" \
            "sudo bash -s" \
            2>/dev/null | tee "$log"
    else
        cat "$script" | ssh \
            -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=5 \
            -o ControlMaster=auto \
            -o "ControlPath=/tmp/.ssh-ctrl-%r@%h:%p" \
            -o ControlPersist=10m \
            "$target" \
            "sudo bash -s" \
            2>/dev/null | tee "$log"
    fi

    echo -e "${GRN}[DONE]${NC} Output saved: $log"
}

# ── COVERT REMOTE COMMAND ─────────────────────────────────────
# Run a single command remotely without any file transfer
# Usage: bt_cmd <user@host> <password> <command>
# Example: bt_cmd root@10.0.1.10 "pass" "cat /etc/passwd"
bt_cmd() {
    local target=$1
    local pass=$2
    local cmd=$3

    if [ -n "$pass" ]; then
        sshpass -p "$pass" ssh \
            -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=5 \
            -o ControlMaster=auto \
            -o "ControlPath=/tmp/.ssh-ctrl-%r@%h:%p" \
            -o ControlPersist=10m \
            "$target" \
            "sudo bash -c '$cmd'" 2>/dev/null
    else
        ssh \
            -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -o ConnectTimeout=5 \
            "$target" \
            "sudo bash -c '$cmd'" 2>/dev/null
    fi
}

# ── PARALLEL COVERT EXECUTION ─────────────────────────────────
# Run a script against ALL hosts simultaneously
# All outputs logged separately, results shown as they arrive
# Usage: bt_run_all <script_path> [password_if_same_for_all]
# Hosts loaded from ~/blueTeam/hosts.txt (user@ip format)
bt_run_all() {
    local script=$1
    local pass=$2
    local TIMESTAMP
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local pids=()
    local hosts=()

    if [ ! -f "$BLUETEAM_DIR/hosts.txt" ]; then
        echo -e "${RED}[ERR]${NC} No hosts file found at $BLUETEAM_DIR/hosts.txt"
        echo "  Format: user@ip (one per line)"
        return 1
    fi

    while read line; do
        [[ "$line" == \#* ]] || [ -z "$line" ] && continue
        hosts+=("$line")
    done < "$BLUETEAM_DIR/hosts.txt"

    echo -e "${BLU}[PARALLEL]${NC} Running $(basename $script) on ${#hosts[@]} hosts simultaneously"
    echo ""

    for target in "${hosts[@]}"; do
        (
            host_clean=$(echo "$target" | tr '@.' '_')
            log="$BLUETEAM_LOGS/parallel_${host_clean}_$(basename $script)_${TIMESTAMP}.log"
            echo -e "${CYN}[START]${NC} $target"

            if [ -n "$pass" ]; then
                cat "$script" | sshpass -p "$pass" ssh \
                    -i "$BLUETEAM_KEY" \
                    -o StrictHostKeyChecking=no \
                    -o UserKnownHostsFile=/dev/null \
                    -o LogLevel=ERROR \
                    -o ConnectTimeout=5 \
                    "$target" "sudo bash -s" 2>/dev/null > "$log"
            else
                cat "$script" | ssh \
                    -i "$BLUETEAM_KEY" \
                    -o StrictHostKeyChecking=no \
                    -o UserKnownHostsFile=/dev/null \
                    -o LogLevel=ERROR \
                    -o ConnectTimeout=5 \
                    "$target" "sudo bash -s" 2>/dev/null > "$log"
            fi

            echo -e "${GRN}[DONE]${NC}  $target → $log"
        ) &
        pids+=($!)
    done

    # Wait for all background jobs
    echo ""
    echo "Waiting for all hosts to complete..."
    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    echo ""
    echo -e "${GRN}[ALL DONE]${NC} Logs in $BLUETEAM_LOGS/"
    echo ""
    # Print a summary of what we got from each host
    for target in "${hosts[@]}"; do
        host_clean=$(echo "$target" | tr '@.' '_')
        log=$(ls -t "$BLUETEAM_LOGS"/parallel_${host_clean}_*.log 2>/dev/null | head -1)
        if [ -f "$log" ]; then
            line_count=$(wc -l < "$log")
            alert_count=$(grep -c "\[ALERT\]\|\[BAD\]" "$log" 2>/dev/null)
            if [ "$alert_count" -gt 0 ]; then
                echo -e "  ${RED}$target${NC}: $line_count lines, ${RED}$alert_count ALERTS${NC} → $log"
            else
                echo -e "  ${GRN}$target${NC}: $line_count lines, clean → $log"
            fi
        fi
    done
}

# ── PUSH SSH KEY TO TARGET ────────────────────────────────────
# Deploy your public key to a target so future connections
# don't need a password at all
# Usage: bt_push_key <user@host> <password>
bt_push_key() {
    local target=$1
    local pass=$2

    echo -e "${CYN}[KEY]${NC} Pushing SSH key to $target..."
    sshpass -p "$pass" ssh-copy-id \
        -i "$BLUETEAM_KEY.pub" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o LogLevel=ERROR \
        "$target" 2>/dev/null

    if [ $? -eq 0 ]; then
        echo -e "${GRN}[OK]${NC} Key deployed to $target — password no longer needed"
        # Test key auth
        ssh -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o BatchMode=yes \
            -o ConnectTimeout=5 \
            "$target" "echo KEY_AUTH_OK" 2>/dev/null | grep -q KEY_AUTH_OK && \
            echo -e "${GRN}[OK]${NC} Key auth confirmed" || \
            echo -e "${YLW}[WARN]${NC} Key deployed but test failed — check sshd config"
    else
        echo -e "${RED}[FAIL]${NC} Key push failed for $target"
    fi
}

# ── PUSH KEYS TO ALL HOSTS ────────────────────────────────────
# Usage: bt_push_key_all <password>
bt_push_key_all() {
    local pass=$1
    while read target; do
        [[ "$target" == \#* ]] || [ -z "$target" ] && continue
        bt_push_key "$target" "$pass"
    done < "$BLUETEAM_DIR/hosts.txt"
}

# ── LIVE WATCH: STREAM LOGS FROM A REMOTE HOST ───────────────
# Watch auth.log or any log file in real time from your admin machine
# The tail process runs on the remote host but output streams here
# Usage: bt_watch_log <user@host> [password] [logfile]
bt_watch_log() {
    local target=$1
    local pass=$2
    local logfile=${3:-/var/log/auth.log}

    echo -e "${CYN}[WATCH]${NC} Streaming $logfile from $target (Ctrl+C to stop)"
    echo ""

    if [ -n "$pass" ]; then
        sshpass -p "$pass" ssh \
            -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -t "$target" \
            "sudo tail -f $logfile" 2>/dev/null
    else
        ssh \
            -i "$BLUETEAM_KEY" \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            -t "$target" \
            "sudo tail -f $logfile" 2>/dev/null
    fi
}

# ── MULTI-HOST LOG WATCHER via tmux ──────────────────────────
# Opens a tmux session with one pane per host, each streaming
# auth.log in real time — your security dashboard
# Usage: bt_dashboard [logfile]
bt_dashboard() {
    local logfile=${1:-/var/log/auth.log}

    if ! command -v tmux &>/dev/null; then
        echo -e "${RED}[ERR]${NC} tmux not installed: apt install tmux"
        return 1
    fi

    if [ ! -f "$BLUETEAM_DIR/hosts.txt" ]; then
        echo -e "${RED}[ERR]${NC} No hosts file: $BLUETEAM_DIR/hosts.txt"
        return 1
    fi

    local session="blueteam_dashboard"
    tmux kill-session -t "$session" 2>/dev/null

    local first=true
    while read target; do
        [[ "$target" == \#* ]] || [ -z "$target" ] && continue

        user=$(echo "$target" | cut -d@ -f1)
        host=$(echo "$target" | cut -d@ -f2)

        if $first; then
            tmux new-session -d -s "$session" -n "$host"
            tmux send-keys -t "$session" \
                "echo '=== $host ===' && ssh -i $BLUETEAM_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $target 'sudo tail -f $logfile'" Enter
            first=false
        else
            tmux new-window -t "$session" -n "$host"
            tmux send-keys -t "$session:$host" \
                "echo '=== $host ===' && ssh -i $BLUETEAM_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR $target 'sudo tail -f $logfile'" Enter
        fi
    done < "$BLUETEAM_DIR/hosts.txt"

    echo -e "${GRN}[DASHBOARD]${NC} Launching tmux dashboard..."
    echo "  Each window = one host streaming $logfile"
    echo "  Ctrl+B then number to switch panes"
    echo "  Ctrl+B then d to detach (dashboard keeps running)"
    echo "  tmux attach -t $session to reattach"
    echo ""
    tmux attach -t "$session"
}

# ── QUICK STATUS ACROSS ALL HOSTS ────────────────────────────
# One-liner health check — are your services up?
# Usage: bt_status_all [password]
bt_status_all() {
    local pass=$1

    if [ ! -f "$BLUETEAM_DIR/hosts.txt" ]; then
        echo "No hosts file. Create $BLUETEAM_DIR/hosts.txt"
        return
    fi

    echo -e "${BLU}━━━━ FLEET STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    printf "%-20s %-10s %-10s %-10s %-10s\n" "HOST" "SSH" "HTTP" "MySQL" "ALERTS"
    echo -e "${BLU}──────────────────────────────────────────────────────────────${NC}"

    while read target; do
        [[ "$target" == \#* ]] || [ -z "$target" ] && continue
        host=$(echo "$target" | cut -d@ -f2)

        # Check SSH
        ssh_status="${RED}DOWN${NC}"
        if timeout 3 bash -c "echo >/dev/tcp/$host/22" 2>/dev/null; then
            ssh_status="${GRN}UP${NC}"
        fi

        # Check HTTP
        http_status="${RED}DOWN${NC}"
        if timeout 3 bash -c "echo >/dev/tcp/$host/80" 2>/dev/null; then
            http_status="${GRN}UP${NC}"
        fi

        # Check MySQL
        mysql_status="${YLW}N/A${NC}"
        if timeout 3 bash -c "echo >/dev/tcp/$host/3306" 2>/dev/null; then
            mysql_status="${YLW}OPEN${NC}"
        fi

        # Quick alert count from most recent log
        recent_log=$(ls -t "$BLUETEAM_LOGS"/*$(echo $host | tr . _)* 2>/dev/null | head -1)
        alert_count=0
        [ -f "$recent_log" ] && alert_count=$(grep -c "\[ALERT\]\|\[BAD\]" "$recent_log" 2>/dev/null)

        [ "$alert_count" -gt 0 ] && \
            alert_display="${RED}$alert_count${NC}" || \
            alert_display="${GRN}0${NC}"

        printf "%-20s " "$host"
        echo -e "${ssh_status}       ${http_status}      ${mysql_status}      ${alert_display}"
    done < "$BLUETEAM_DIR/hosts.txt"

    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ── ADD HOST TO FLEET ─────────────────────────────────────────
# Usage: bt_add_host user@ip "hostname_label"
bt_add_host() {
    local target=$1
    local label=${2:-""}
    echo "$target  ${label:+# $label}" >> "$BLUETEAM_DIR/hosts.txt"
    echo -e "${GRN}[OK]${NC} Added $target to fleet"
    cat "$BLUETEAM_DIR/hosts.txt"
}

# ── HELP ──────────────────────────────────────────────────────
bt_help() {
    echo -e "${BLU}"
    echo "  PCDC 2026 Blue Team Admin Functions"
    echo "  ════════════════════════════════════════════════════════"
    echo -e "${NC}"
    echo -e "  ${GRN}bt_ssh${NC} <user@host> [password]"
    echo "    Open interactive SSH session"
    echo ""
    echo -e "  ${GRN}bt_cmd${NC} <user@host> <password> <command>"
    echo "    Run a single command remotely (no file transfer)"
    echo ""
    echo -e "  ${GRN}bt_run_covert${NC} <script> <user@host> [password]"
    echo "    Run a local script on a remote host via stdin pipe"
    echo "    Script NEVER written to remote filesystem"
    echo ""
    echo -e "  ${GRN}bt_run_all${NC} <script> [password]"
    echo "    Run a script on ALL hosts in parallel"
    echo ""
    echo -e "  ${GRN}bt_push_key${NC} <user@host> <password>"
    echo "    Deploy SSH key to a host (no more password needed)"
    echo ""
    echo -e "  ${GRN}bt_push_key_all${NC} <password>"
    echo "    Deploy SSH key to ALL hosts"
    echo ""
    echo -e "  ${GRN}bt_watch_log${NC} <user@host> [password] [logfile]"
    echo "    Stream a remote log file to your terminal in real time"
    echo ""
    echo -e "  ${GRN}bt_dashboard${NC} [logfile]"
    echo "    Open tmux dashboard streaming logs from ALL hosts"
    echo ""
    echo -e "  ${GRN}bt_status_all${NC} [password]"
    echo "    Quick service health check across all hosts"
    echo ""
    echo -e "  ${GRN}bt_add_host${NC} <user@ip> [label]"
    echo "    Add a host to your fleet"
    echo ""
    echo "  Hosts file: $BLUETEAM_DIR/hosts.txt"
    echo "  Logs:       $BLUETEAM_DIR/logs/"
    echo "  SSH key:    $BLUETEAM_DIR/keys/pcdc_admin"
}

echo -e "${GRN}Blue Team admin functions loaded. Type bt_help for usage.${NC}"
PROFILE_EOF

ok "Shell functions written to $PROFILEFILE"

# ============================================================
# STEP 6: HOSTS FILE TEMPLATE
# ============================================================
section "STEP 6: HOSTS FILE"

if [ ! -f "$HOSTFILE" ]; then
    cat > "$HOSTFILE" << 'EOF'
# PCDC 2026 Blue Team Fleet
# Format: user@ip   # optional label
# Example:
#   root@10.0.1.10   # web server
#   root@10.0.1.11   # mail server
#   root@10.0.1.12   # database server
#
# Populate this from your Blue Team Packet
# Then use bt_run_all to hit everything at once

EOF
    ok "Hosts file template created: $HOSTFILE"
    warn "Edit $HOSTFILE with your machines from the Blue Team Packet"
fi

# ============================================================
# STEP 7: COPY SCRIPTS TO ADMIN MACHINE
# ============================================================
section "STEP 7: SCRIPT STAGING"

SCRIPT_SOURCE="$(dirname "$(readlink -f "$0")")"

if [ -d "$SCRIPT_SOURCE" ]; then
    info "Copying Blue Team scripts to $SCRIPTDIR..."
    for script in "$SCRIPT_SOURCE"/pcdc_*.sh; do
        [ -f "$script" ] && cp "$script" "$SCRIPTDIR/" && \
            ok "Staged: $(basename $script)"
    done
fi

# ============================================================
# DONE — Print final instructions
# ============================================================
section "SETUP COMPLETE"

echo -e "${GRN}Your admin machine is ready. Here's how to use it:${NC}"
echo ""
echo "  1. Load functions into your shell:"
echo -e "     ${YLW}source ~/.blueTeam_profile${NC}"
echo ""
echo "  2. Add your target machines from the Blue Team Packet:"
echo -e "     ${YLW}bt_add_host root@10.0.1.10 'web server'${NC}"
echo -e "     ${YLW}bt_add_host root@10.0.1.11 'mail server'${NC}"
echo ""
echo "  3. Push your SSH key to each host (do this first):"
echo -e "     ${YLW}bt_push_key_all 'packetpassword'${NC}"
echo ""
echo "  4. Run your audit across all machines simultaneously:"
echo -e "     ${YLW}bt_run_all ~/blueTeam/scripts/pcdc_linux_audit.sh${NC}"
echo ""
echo "  5. Launch the log monitoring dashboard:"
echo -e "     ${YLW}bt_dashboard${NC}"
echo ""
echo "  6. Quick health check:"
echo -e "     ${YLW}bt_status_all${NC}"
echo ""
echo -e "${YLW}OPSEC REMINDERS:${NC}"
echo "  • bt_run_covert pipes scripts through stdin — nothing written to target disk"
echo "  • ControlMaster reuses SSH connections — less network noise from repeated calls"
echo "  • Your admin machine should have NO inbound SSH if possible"
echo "  • Keep your blueTeam/ directory permissions tight: chmod 700 ~/blueTeam"
echo "  • Never store passwords in the hosts.txt file — use key auth after bt_push_key"
echo ""
echo -e "${GRN}SSH public key to distribute to your targets:${NC}"
cat "$KEYDIR/pcdc_admin.pub" 2>/dev/null
echo ""
