#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Alias & Shell Poisoning Detector
#
#  Red team technique: wrap common commands (ls, sudo, cd, ps,
#  netstat, ssh, passwd, etc.) in aliases or shell functions
#  that silently log your keystrokes, steal credentials,
#  or phone home while appearing to work normally.
#
#  This script detects:
#  - Malicious aliases in all user environments
#  - Poisoned shell rc files (.bashrc, .bash_profile, etc.)
#  - Overridden binaries (binary in PATH before real one)
#  - Malicious shell functions
#  - LD_PRELOAD hijacks (library injection)
#  - $PATH manipulation
#  - Suspicious environment variables
#  - Keyloggers watching /dev/tty or /dev/pts
#
#  Run as root. No loop needed — run periodically or on suspicion.
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="$LOGDIR/alias_audit_$TIMESTAMP.log"
INCIDENT_LOG="$LOGDIR/incidents_$TIMESTAMP.log"

mkdir -p "$LOGDIR"
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

# Commands that red teams love to alias/wrap
CRITICAL_CMDS=(
    "sudo" "su" "passwd" "ssh" "scp" "sftp"
    "ls" "ps" "netstat" "ss" "top" "htop"
    "cat" "less" "more" "grep" "find"
    "wget" "curl" "nc" "bash" "sh"
    "id" "whoami" "w" "who"
    "iptables" "ufw" "firewall-cmd"
    "systemctl" "service"
    "python" "python3" "perl" "ruby"
)

# ============================================================
# SECTION 1: SCAN ALL RC FILES FOR SUSPICIOUS CONTENT
# ============================================================
section "SECTION 1: RC FILE AUDIT"

RC_FILES=(
    "/etc/bash.bashrc"
    "/etc/profile"
    "/etc/environment"
    "/root/.bashrc"
    "/root/.bash_profile"
    "/root/.profile"
    "/root/.bash_login"
    "/root/.zshrc"
)

# Add all user home rc files
for homedir in /home/*/; do
    user=$(basename "$homedir")
    for rc in .bashrc .bash_profile .profile .bash_login .zshrc .zprofile .kshrc; do
        [ -f "$homedir$rc" ] && RC_FILES+=("$homedir$rc")
    done
done

# Also check /etc/profile.d/
for f in /etc/profile.d/*.sh; do
    RC_FILES+=("$f")
done

SUSPICIOUS_PATTERNS=(
    "alias sudo"
    "alias su"
    "alias ls"
    "alias ps"
    "alias ssh"
    "alias passwd"
    "alias netstat"
    "alias ss"
    "alias cat"
    "alias id"
    "alias whoami"
    "curl"
    "wget"
    "nc "
    "ncat"
    "netcat"
    "socat"
    "base64"
    "eval"
    "exec "
    "LD_PRELOAD"
    "LD_LIBRARY_PATH"
    "/dev/tcp"
    "/dev/udp"
    ">/dev/null 2>&1 &"
    "nohup"
    "disown"
    "mkfifo"
    "bash -i"
    "sh -i"
    "python.*socket"
    "perl.*socket"
    "openssl.*s_client"
    "history -c"
    "HISTFILE=/dev/null"
    "HISTSIZE=0"
    "unset HISTFILE"
    "export HISTFILE"
)

for rcfile in "${RC_FILES[@]}"; do
    if [ ! -f "$rcfile" ]; then continue; fi

    echo ""
    info "Scanning: $rcfile (modified: $(stat -c '%y' "$rcfile" 2>/dev/null | cut -d. -f1))"

    found_something=false
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        matches=$(grep -n "$pattern" "$rcfile" 2>/dev/null)
        if [ -n "$matches" ]; then
            alert "SUSPICIOUS PATTERN '$pattern' in $rcfile:"
            echo "$matches" | while read line; do
                echo -e "    ${RED}$line${NC}"
            done
            log_incident "SUSPICIOUS RC FILE CONTENT" "$rcfile contains '$pattern'" 
            found_something=true
        fi
    done

    if ! $found_something; then
        ok "Clean: $rcfile"
    else
        warn "Full contents of $rcfile:"
        cat -n "$rcfile"
    fi
done

# ============================================================
# SECTION 2: ALIAS DUMP FROM ALL LIVE SHELLS
# ============================================================
section "SECTION 2: LIVE ALIAS INSPECTION"

info "Dumping aliases from every user's running shell processes..."

# Get all unique bash/zsh/sh PIDs
SHELL_PIDS=$(ps aux | grep -E '\b(bash|zsh|sh|dash)\b' | grep -v grep | awk '{print $2}')

for pid in $SHELL_PIDS; do
    user=$(ps -o user= -p "$pid" 2>/dev/null)
    cmd=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
    env_file="/proc/$pid/environ"

    echo ""
    info "Shell PID $pid (user: $user, cmd: $cmd)"

    # Read the environment of this process
    if [ -r "$env_file" ]; then
        # Check for LD_PRELOAD — one of the most dangerous
        ld_preload=$(cat "$env_file" 2>/dev/null | tr '\0' '\n' | grep "^LD_PRELOAD")
        if [ -n "$ld_preload" ]; then
            alert "LD_PRELOAD SET in PID $pid (user: $user): $ld_preload"
            log_incident "LD_PRELOAD INJECTION" "PID $pid user $user: $ld_preload" ""
        fi

        # Check PATH for suspicious prepended directories
        path_val=$(cat "$env_file" 2>/dev/null | tr '\0' '\n' | grep "^PATH=")
        if [ -n "$path_val" ]; then
            first_dir=$(echo "$path_val" | cut -d= -f2 | cut -d: -f1)
            # Flag if PATH starts with a non-standard directory
            if echo "$first_dir" | grep -qv -E '^/(usr/(local/)?(s)?bin|s?bin|usr/s?bin)$'; then
                alert "SUSPICIOUS PATH PREPEND in PID $pid: $path_val"
                log_incident "PATH MANIPULATION" "PID $pid: $path_val" ""
            fi
        fi

        # Check for HISTFILE suppression
        hist=$(cat "$env_file" 2>/dev/null | tr '\0' '\n' | grep -E "^HISTFILE|^HISTSIZE|^HISTFILESIZE")
        if [ -n "$hist" ]; then
            warn "History config in PID $pid: $hist"
        fi
    fi
done

# ============================================================
# SECTION 3: WHICH BINARY RUNS WHEN YOU TYPE A COMMAND?
# Check for PATH hijacking — fake binary placed before real one
# ============================================================
section "SECTION 3: BINARY PATH VERIFICATION"

info "Checking each critical command — where does it resolve in PATH?"

for cmd in "${CRITICAL_CMDS[@]}"; do
    # Find ALL locations of this command in PATH
    all_locations=$(which -a "$cmd" 2>/dev/null)
    first_location=$(which "$cmd" 2>/dev/null)

    if [ -z "$first_location" ]; then
        info "$cmd: not found in PATH"
        continue
    fi

    # Expected standard locations
    STANDARD_PATHS=("/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin")
    cmd_dir=$(dirname "$first_location")

    is_standard=false
    for std in "${STANDARD_PATHS[@]}"; do
        if [ "$cmd_dir" == "$std" ]; then
            is_standard=true
            break
        fi
    done

    if ! $is_standard; then
        alert "PATH HIJACK: '$cmd' resolves to NON-STANDARD location: $first_location"
        echo "  All locations:"
        echo "$all_locations" | while read loc; do echo "    $loc"; done
        log_incident "BINARY PATH HIJACK" "'$cmd' found at non-standard path: $first_location" ""
    else
        ok "$cmd → $first_location"
    fi

    # Flag if there are multiple locations (possible shadow binary)
    loc_count=$(echo "$all_locations" | wc -l)
    if [ "$loc_count" -gt 1 ]; then
        warn "'$cmd' exists in multiple PATH locations — verify which one runs:"
        echo "$all_locations" | while read loc; do
            echo "    $loc ($(ls -la "$loc" 2>/dev/null))"
        done
    fi
done

# ============================================================
# SECTION 4: LD_PRELOAD & LIBRARY HIJACKING
# Most insidious — can wrap ANY system call invisibly
# ============================================================
section "SECTION 4: LD_PRELOAD & LIBRARY HIJACKING"

info "Checking system-wide LD_PRELOAD config..."

# /etc/ld.so.preload is loaded for EVERY process — if modified, everything is compromised
if [ -f /etc/ld.so.preload ]; then
    alert "CRITICAL: /etc/ld.so.preload EXISTS — inspect immediately:"
    cat /etc/ld.so.preload
    log_incident "LD_PRELOAD SYSTEM HIJACK" "/etc/ld.so.preload: $(cat /etc/ld.so.preload)" ""
else
    ok "/etc/ld.so.preload does not exist (normal)"
fi

echo ""
info "Checking LD_PRELOAD in all running process environments:"
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"; pid="${pid##*/}"
    if [ -r "/proc/$pid/environ" ]; then
        ld=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep "^LD_PRELOAD")
        if [ -n "$ld" ]; then
            proc_name=$(cat "/proc/$pid/comm" 2>/dev/null)
            alert "LD_PRELOAD found in PID $pid ($proc_name): $ld"
            log_incident "LD_PRELOAD IN PROCESS" "PID $pid $proc_name: $ld" ""
        fi
    fi
done

echo ""
info "Shared library cache (ldconfig -p) — look for unexpected libraries:"
ldconfig -p 2>/dev/null | grep -v -E 'lib(c|m|dl|pthread|rt|util|nsl|resolv|crypt|stdc\+\+|gcc_s|z)\.' | head -30

# ============================================================
# SECTION 5: SHELL FUNCTION POISONING
# Functions override binaries and don't show in 'which'
# ============================================================
section "SECTION 5: SHELL FUNCTION DETECTION"

info "Extracting shell functions from rc files..."
info "(Shell functions are checked by 'type cmd' not 'which cmd')"
echo ""

# For each rc file, extract function definitions
for rcfile in "${RC_FILES[@]}"; do
    if [ ! -f "$rcfile" ]; then continue; fi

    funcs=$(grep -n "^[a-zA-Z_][a-zA-Z0-9_]*\s*()" "$rcfile" 2>/dev/null)
    if [ -n "$funcs" ]; then
        warn "Shell functions defined in $rcfile:"
        echo "$funcs"

        # Check if any function has the same name as a critical command
        echo "$funcs" | while read line; do
            funcname=$(echo "$line" | grep -oP '^[0-9]+:\K[a-zA-Z_][a-zA-Z0-9_]*')
            for cmd in "${CRITICAL_CMDS[@]}"; do
                if [ "$funcname" == "$cmd" ]; then
                    alert "CRITICAL COMMAND SHADOWED BY FUNCTION: '$cmd' in $rcfile"
                    log_incident "FUNCTION SHADOWING CRITICAL CMD" \
                        "'$cmd' defined as shell function in $rcfile" ""
                fi
            done
        done
    fi
done

echo ""
info "Testing 'type' vs 'which' for critical commands (mismatch = poisoned):"
for cmd in "${CRITICAL_CMDS[@]}"; do
    which_result=$(which "$cmd" 2>/dev/null)
    # Run 'type' in a clean bash subshell sourcing each user's rc
    # We can check root's environment at minimum
    type_result=$(bash -c "type $cmd" 2>/dev/null)

    if echo "$type_result" | grep -q "function\|alias"; then
        alert "'$cmd' is a SHELL FUNCTION or ALIAS, not the real binary!"
        echo "  type output: $type_result"
        echo "  which output: $which_result"
        log_incident "COMMAND SHADOWED" "'$cmd' is a function/alias" ""
    fi
done

# ============================================================
# SECTION 6: SUSPICIOUS ENVIRONMENT VARIABLES ACROSS PROCESSES
# ============================================================
section "SECTION 6: ENVIRONMENT VARIABLE AUDIT"

SUSPICIOUS_VARS=("LD_PRELOAD" "LD_LIBRARY_PATH" "PROMPT_COMMAND" "BASH_ENV" "ENV" "ZDOTDIR")

info "Scanning all process environments for dangerous variables..."
for pid_dir in /proc/[0-9]*/; do
    pid="${pid_dir%/}"; pid="${pid##*/}"
    env_file="/proc/$pid/environ"
    if [ ! -r "$env_file" ]; then continue; fi

    proc_name=$(cat "/proc/$pid/comm" 2>/dev/null)

    for var in "${SUSPICIOUS_VARS[@]}"; do
        match=$(cat "$env_file" 2>/dev/null | tr '\0' '\n' | grep "^${var}=")
        if [ -n "$match" ]; then
            case "$var" in
                "PROMPT_COMMAND")
                    alert "PROMPT_COMMAND set in PID $pid ($proc_name) — can execute code on every prompt:"
                    echo "  $match"
                    log_incident "PROMPT_COMMAND POISONING" "PID $pid $proc_name: $match" ""
                    ;;
                "BASH_ENV"|"ENV")
                    alert "$var set in PID $pid ($proc_name) — executed for every bash script:"
                    echo "  $match"
                    log_incident "BASH_ENV POISONING" "PID $pid $proc_name: $match" ""
                    ;;
                "LD_PRELOAD"|"LD_LIBRARY_PATH")
                    # Already handled in section 4, only flag non-standard paths
                    val=$(echo "$match" | cut -d= -f2)
                    if echo "$val" | grep -qv -E '^/usr/lib|^/lib'; then
                        alert "$var non-standard value in PID $pid ($proc_name): $val"
                        log_incident "SUSPICIOUS $var" "PID $pid $proc_name: $val" ""
                    fi
                    ;;
            esac
        fi
    done
done

# ============================================================
# SECTION 7: HISTORY FILE TAMPERING
# Attackers often suppress history to hide their tracks
# ============================================================
section "SECTION 7: HISTORY TAMPERING CHECK"

for homedir in /root /home/*/; do
    user=$(basename "$homedir")
    hist_file="$homedir/.bash_history"

    if [ ! -f "$hist_file" ]; then
        warn "No .bash_history for $user — possibly deleted or suppressed"
        continue
    fi

    line_count=$(wc -l < "$hist_file")
    last_mod=$(stat -c '%y' "$hist_file" 2>/dev/null | cut -d. -f1)
    info "$user: .bash_history has $line_count lines (last modified: $last_mod)"

    if [ "$line_count" -lt 5 ]; then
        warn "Very few history entries for $user ($line_count lines) — may have been wiped"
    fi

    # Check if history is symlinked to /dev/null (common suppression)
    if [ -L "$hist_file" ]; then
        target=$(readlink "$hist_file")
        alert "HISTORY SYMLINKED for $user: $hist_file → $target"
        log_incident "HISTORY SUPPRESSED" "$user .bash_history → $target" ""
    fi
done

# Check for HISTFILE suppression in active shells
info "Checking for history suppression in active processes:"
for pid in $(pgrep -x bash -x zsh 2>/dev/null); do
    user=$(ps -o user= -p "$pid" 2>/dev/null)
    if [ -r "/proc/$pid/environ" ]; then
        hist_env=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | grep -E "HISTFILE|HISTSIZE")
        if echo "$hist_env" | grep -qE "HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0"; then
            alert "HISTORY DISABLED in PID $pid (user: $user): $hist_env"
            log_incident "HISTORY DISABLED" "PID $pid user $user: $hist_env" ""
        fi
    fi
done

# ============================================================
# SECTION 8: TTY WATCHERS (Keyloggers watching your terminal)
# ============================================================
section "SECTION 8: TTY/PTY WATCHER DETECTION"

info "Processes with open handles on terminal devices (potential keyloggers):"

# List all /dev/pts/* and /dev/tty* readers
ls /dev/pts/ 2>/dev/null | while read pt; do
    watchers=$(lsof "/dev/pts/$pt" 2>/dev/null | grep -v "^COMMAND\|bash\|sshd\|login\|getty")
    if [ -n "$watchers" ]; then
        warn "Processes watching /dev/pts/$pt (beyond normal shells):"
        echo "$watchers"
        # Flag anything that isn't a normal terminal program
        echo "$watchers" | grep -v -E "screen|tmux|script|expect" | while read line; do
            alert "POSSIBLE KEYLOGGER on /dev/pts/$pt: $line"
            log_incident "POSSIBLE KEYLOGGER" "/dev/pts/$pt: $line" ""
        done
    fi
done

# Check for 'script' command running (records everything)
script_procs=$(pgrep -a script 2>/dev/null)
if [ -n "$script_procs" ]; then
    warn "'script' command running (records terminal session):"
    echo "$script_procs"
fi

# Check for strace attached to processes (can capture syscalls including passwords)
strace_procs=$(pgrep -a strace 2>/dev/null)
if [ -n "$strace_procs" ]; then
    alert "STRACE RUNNING — can capture passwords and syscalls:"
    echo "$strace_procs"
    log_incident "STRACE KEYLOGGER" "$strace_procs" ""
fi

# ============================================================
# SECTION 9: REMEDIATION SUGGESTIONS
# ============================================================
section "SECTION 9: REMEDIATION QUICK REFERENCE"

echo -e "${YLW}If you found aliases/functions wrapping critical commands:${NC}"
echo "  1. Identify the source rc file"
echo "  2. Edit or delete the offending lines: nano /home/user/.bashrc"
echo "  3. Force reload: source /etc/profile"
echo "  4. Kill and reopen any affected shell sessions"
echo "  5. Verify with: type sudo; which sudo"
echo ""
echo -e "${YLW}If you found LD_PRELOAD or /etc/ld.so.preload:${NC}"
echo "  1. Back up: cp /etc/ld.so.preload /etc/ld.so.preload.bak"
echo "  2. Clear it: > /etc/ld.so.preload"
echo "  3. Verify: cat /etc/ld.so.preload"
echo ""
echo -e "${YLW}If you found a PATH hijack:${NC}"
echo "  1. Remove the fake binary: rm /suspicious/path/sudo"
echo "  2. Fix PATH in /etc/environment or /etc/profile"
echo "  3. Verify: which sudo; hash -r; which sudo"
echo ""
echo -e "${YLW}To run commands SAFELY bypassing aliases/functions:${NC}"
echo "  Use the full path:  /usr/bin/sudo, /bin/ls, /usr/bin/passwd"
echo "  Or use backslash:   \\sudo, \\ls, \\passwd"
echo "  Or use 'command':   command sudo, command ls"
echo ""
echo -e "${YLW}To audit your OWN current shell for aliases:${NC}"
echo "  alias           # show all active aliases"
echo "  declare -f      # show all shell functions"
echo "  env             # show all environment variables"
echo "  type <cmd>      # shows if cmd is alias/function/binary"
echo ""

section "AUDIT COMPLETE"
echo -e "${GRN}Log: $LOGFILE${NC}"
echo -e "${GRN}Incidents: $INCIDENT_LOG${NC}"
