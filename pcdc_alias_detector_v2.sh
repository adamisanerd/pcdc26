#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Alias & Shell Poisoning Detector v2
#
#  WHAT CHANGED FROM v1 AND WHY:
#
#  GAP 1: v1 only read rc files as text with grep.
#  A smart red teamer hides the alias AFTER a legitimate-looking
#  block using invisible unicode, zero-width characters, or by
#  encoding the payload in base64 inside an eval. We now scan
#  for base64 blobs, unicode anomalies, and eval patterns.
#
#  GAP 2: v1 checked PROMPT_COMMAND but missed DEBUG traps.
#  'trap "evil_command" DEBUG' executes before EVERY command.
#  It's one of the most effective keystroke-capture techniques
#  and almost nobody checks for it.
#
#  GAP 3: v1 missed /proc/PID/maps for LD_PRELOAD injection.
#  Even if LD_PRELOAD env var is cleared, a loaded library stays
#  in /proc/PID/maps. We now check maps for unexpected .so files.
#
#  GAP 4: v1 didn't catch function-in-subshell tricks.
#  Red teams define malicious functions in /etc/bash.bashrc then
#  call them from a subshell so they don't appear in the parent's
#  'declare -f' output. We source each rc file in a subshell and
#  dump what functions get defined.
#
#  GAP 5: v1 missed PAM module backdoors.
#  Inserting a rogue PAM module (pam_unix.so replacement) captures
#  EVERY password typed for sudo/su/login on the system. This is
#  arguably the most dangerous persistence mechanism on Linux.
#
#  GAP 6: v1 missed git/pip/package manager hooks.
#  Red teams plant hooks in ~/.gitconfig, pip post-install scripts,
#  or npm/cargo configs to execute on routine admin operations.
#
#  Run as root. Run this script with the actual binary paths,
#  not via a potentially aliased shell:
#    /bin/bash pcdc_alias_detector_v2.sh
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="$LOGDIR/alias_v2_$TIMESTAMP.log"
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

# All rc/config files to scan
RC_FILES=()
for f in /etc/bash.bashrc /etc/profile /etc/environment /etc/bashrc; do
    [ -f "$f" ] && RC_FILES+=("$f")
done
for f in /etc/profile.d/*.sh; do
    [ -f "$f" ] && RC_FILES+=("$f")
done
for homedir in /root /home/*/; do
    for rc in .bashrc .bash_profile .profile .bash_login .zshrc .zprofile .kshrc .config/fish/config.fish; do
        [ -f "$homedir/$rc" ] && RC_FILES+=("$homedir/$rc")
    done
done

# ============================================================
# SECTION 1: ADVANCED RC FILE ANALYSIS
# Includes base64, eval, unicode, and obfuscation detection
# ============================================================
section "SECTION 1: ADVANCED RC FILE ANALYSIS"

SUSPICIOUS_PATTERNS=(
    "alias sudo" "alias su" "alias ls" "alias ps" "alias ssh"
    "alias passwd" "alias netstat" "alias ss=" "alias cat"
    "alias id" "alias whoami" "alias curl" "alias wget"
    "curl " "wget " "nc " "ncat" "netcat" "socat"
    "base64" "eval " "exec " "mkfifo" "bash -i" "sh -i"
    ">/dev/null 2>&1 &" "nohup" "disown"
    "/dev/tcp" "/dev/udp"
    "history -c" "HISTFILE=/dev/null" "HISTSIZE=0" "unset HISTFILE"
    "LD_PRELOAD" "LD_LIBRARY_PATH"
    "python.*socket\|python.*connect\|python.*bind"
    "perl.*socket\|perl.*connect"
    "openssl.*s_client\|openssl.*connect"
    # NEW in v2:
    "trap.*DEBUG"           # DEBUG trap — captures every command
    "trap.*RETURN"          # RETURN trap — fires on function return
    "trap.*ERR"             # Can be abused
    "PROMPT_COMMAND"        # Runs before every prompt
    "command_not_found"     # Handler hook
    "\$\(.*base64"          # base64 decode in subshell
    "echo.*|.*base64.*-d"   # piped base64 decode
    "xxd -r"                # hex decode
    "python.*exec\|python.*compile"
    "perl.*eval\|perl.*system"
    "ruby.*eval\|ruby.*system"
)

for rcfile in "${RC_FILES[@]}"; do
    [ ! -f "$rcfile" ] && continue

    echo ""
    info "Scanning: $rcfile"
    info "  Size: $(wc -c < "$rcfile") bytes | Modified: $(stat -c '%y' "$rcfile" 2>/dev/null | cut -d. -f1)"

    found_something=false

    # Pattern matching
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        matches=$(grep -nP "$pattern" "$rcfile" 2>/dev/null)
        if [ -n "$matches" ]; then
            alert "  PATTERN '$pattern':"
            echo "$matches" | while read line; do echo -e "    ${RED}$line${NC}"; done
            log_incident "SUSPICIOUS RC PATTERN" "$rcfile: $pattern"
            found_something=true
        fi
    done

    # NEW: Check for non-ASCII/unicode hiding (zero-width chars, unicode homoglyphs)
    non_ascii=$(grep -Pn '[^\x00-\x7F]' "$rcfile" 2>/dev/null)
    if [ -n "$non_ascii" ]; then
        alert "  NON-ASCII CHARACTERS DETECTED (possible unicode obfuscation):"
        echo "$non_ascii" | head -5 | while read line; do
            echo -e "    ${RED}$line${NC}"
        done
        log_incident "UNICODE OBFUSCATION" "$rcfile contains non-ASCII"
        found_something=true
    fi

    # NEW: Check for long base64-looking strings (encoded payloads)
    b64_blobs=$(grep -oP '[A-Za-z0-9+/]{60,}={0,2}' "$rcfile" 2>/dev/null)
    if [ -n "$b64_blobs" ]; then
        alert "  POSSIBLE BASE64 PAYLOAD in $rcfile:"
        echo "$b64_blobs" | while read blob; do
            decoded=$(echo "$blob" | base64 -d 2>/dev/null | strings 2>/dev/null | head -3)
            echo -e "    ${RED}Blob: ${blob:0:40}...${NC}"
            [ -n "$decoded" ] && echo "    Decoded preview: $decoded"
        done
        log_incident "BASE64 ENCODED PAYLOAD" "$rcfile"
        found_something=true
    fi

    # NEW: Lines with unusual character density (obfuscated one-liners)
    long_lines=$(awk 'length > 200 {print NR": "substr($0,1,100)"..."}' "$rcfile" 2>/dev/null)
    if [ -n "$long_lines" ]; then
        warn "  UNUSUALLY LONG LINES (obfuscation indicator):"
        echo "$long_lines"
    fi

    $found_something || ok "  Clean: $rcfile"
done

# ============================================================
# SECTION 2: DEBUG TRAP DETECTION
# 'trap "cmd" DEBUG' runs cmd before EVERY command the user types
# This is a perfect keystroke/credential capture mechanism
# ============================================================
section "SECTION 2: DEBUG TRAP & HOOK DETECTION"

info "Checking for DEBUG/RETURN/ERR traps in rc files..."

for rcfile in "${RC_FILES[@]}"; do
    [ ! -f "$rcfile" ] && continue
    trap_lines=$(grep -n "trap " "$rcfile" 2>/dev/null)
    if [ -n "$trap_lines" ]; then
        warn "TRAP directives in $rcfile:"
        echo "$trap_lines" | while read line; do
            # DEBUG trap is almost always malicious in rc files
            if echo "$line" | grep -qi "DEBUG\|RETURN"; then
                alert "  DANGEROUS TRAP: $line"
                log_incident "DEBUG TRAP BACKDOOR" "$rcfile: $line"
            else
                info "  Trap (review): $line"
            fi
        done
    fi
done

# Check LIVE shells for active traps by inspecting /proc
info "Checking active traps in running shell processes..."
for pid in $(pgrep -x bash -x zsh 2>/dev/null); do
    user=$(ps -o user= -p "$pid" 2>/dev/null)
    # We can check the process's open files and maps but not directly inspect
    # the trap table without attaching a debugger. Instead, check /proc/PID/environ
    # for variables that traps commonly set
    env_vars=$(cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n')
    if echo "$env_vars" | grep -qi "BASH_COMMAND\|trap"; then
        warn "PID $pid ($user) has trap-related env vars — investigate"
    fi
done

# ============================================================
# SECTION 3: PAM MODULE BACKDOOR DETECTION
# Replacing or adding a PAM module captures ALL passwords
# typed to sudo, su, login, sshd on the system
# ============================================================
section "SECTION 3: PAM MODULE INTEGRITY CHECK"

info "PAM is used by sudo, ssh, su, login — a rogue PAM module captures all passwords"
echo ""

PAM_DIR="/lib/security"
PAM_DIR64="/lib/x86_64-linux-gnu/security"
PAM_DIR_ALT="/usr/lib/security"

# Check each pam directory
for pamdir in "$PAM_DIR" "$PAM_DIR64" "$PAM_DIR_ALT"; do
    [ ! -d "$pamdir" ] && continue
    info "PAM modules in $pamdir:"
    ls -la "$pamdir"/*.so 2>/dev/null

    echo ""
    # Hash all PAM modules at first run, compare on subsequent runs
    PAMHASH_FILE="$LOGDIR/pam_hashes.baseline"
    if [ ! -f "$PAMHASH_FILE" ]; then
        info "Creating PAM module baseline hashes..."
        sha256sum "$pamdir"/*.so 2>/dev/null > "$PAMHASH_FILE"
        ok "PAM baseline saved to $PAMHASH_FILE"
    else
        info "Comparing current PAM modules against baseline..."
        while read expected_hash filepath; do
            if [ ! -f "$filepath" ]; then
                alert "PAM MODULE MISSING: $filepath — was it deleted or replaced?"
                log_incident "PAM MODULE MISSING" "$filepath"
                continue
            fi
            current_hash=$(sha256sum "$filepath" 2>/dev/null | awk '{print $1}')
            if [ "$current_hash" != "$expected_hash" ]; then
                alert "PAM MODULE MODIFIED: $filepath"
                alert "  Expected: $expected_hash"
                alert "  Current:  $current_hash"
                log_incident "PAM MODULE TAMPERED" "$filepath hash changed"
            else
                ok "$(basename $filepath): unchanged"
            fi
        done < "$PAMHASH_FILE"

        # Check for NEW pam modules added since baseline
        sha256sum "$pamdir"/*.so 2>/dev/null | while read hash file; do
            if ! grep -q "$file" "$PAMHASH_FILE"; then
                alert "NEW PAM MODULE ADDED: $file"
                log_incident "NEW PAM MODULE" "$file"
            fi
        done
    fi
done

# Check /etc/pam.d/ configs for suspicious entries
section "PAM Configuration Audit"
info "Checking /etc/pam.d/ for suspicious module entries..."
grep -rn "pam_exec\|pam_script\|pam_python" /etc/pam.d/ 2>/dev/null | while read line; do
    alert "SUSPICIOUS PAM CONFIG (code execution module): $line"
    log_incident "PAM CODE EXEC MODULE" "$line"
done

grep -rn "required.*pam_permit\|sufficient.*pam_permit" /etc/pam.d/ 2>/dev/null | while read line; do
    alert "PAM_PERMIT (always succeeds) in critical config: $line"
    log_incident "PAM BYPASS" "$line"
done

# ============================================================
# SECTION 4: /proc/PID/maps — LOADED LIBRARY INSPECTION
# Even if LD_PRELOAD env var was cleared after injection,
# the library stays mapped in memory. This catches that.
# ============================================================
section "SECTION 4: LOADED LIBRARY INSPECTION (/proc/PID/maps)"

EXPECTED_LIB_DIRS=("/lib" "/usr/lib" "/lib/x86_64-linux-gnu" "/usr/lib/x86_64-linux-gnu"
                   "/lib64" "/usr/lib64" "/lib/i386-linux-gnu")

info "Scanning all process memory maps for unexpected shared libraries..."

for pid in $(ls /proc | grep '^[0-9]' | head -200); do
    maps_file="/proc/$pid/maps"
    [ ! -r "$maps_file" ] && continue

    comm=$(cat "/proc/$pid/comm" 2>/dev/null)
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)

    grep "\.so" "$maps_file" 2>/dev/null | awk '{print $6}' | grep "\.so" | sort -u | while read lib; do
        [ -z "$lib" ] && continue
        lib_dir=$(dirname "$lib")

        is_standard=false
        for expected_dir in "${EXPECTED_LIB_DIRS[@]}"; do
            if [[ "$lib_dir" == "$expected_dir" ]] || [[ "$lib_dir" == "$expected_dir"* ]]; then
                is_standard=true
                break
            fi
        done

        if ! $is_standard; then
            alert "NON-STANDARD LIBRARY LOADED in PID $pid ($comm | $exe):"
            alert "  Library: $lib"
            log_incident "SUSPICIOUS LIBRARY INJECTION" \
                "PID $pid $comm loaded non-standard lib: $lib"
        fi

        # Flag libraries from /tmp, /dev/shm, /var/tmp — always malicious
        if echo "$lib" | grep -qE '^(/tmp|/dev/shm|/var/tmp|/run/user)'; then
            alert "CRITICAL: LIBRARY LOADED FROM TEMP DIR in PID $pid ($comm):"
            alert "  $lib"
            log_incident "MALWARE LIBRARY FROM TEMP" \
                "PID $pid $comm loaded lib from temp: $lib"
        fi
    done
done

# ============================================================
# SECTION 5: SUBSHELL FUNCTION EXTRACTION
# Defines malicious functions in rc files then calls them
# from subshells — bypasses parent shell 'declare -f'
# ============================================================
section "SECTION 5: SUBSHELL FUNCTION EXTRACTION"

info "Sourcing each rc file in a clean subshell and dumping defined functions..."
info "This catches functions that only appear when the rc file is loaded."
echo ""

for rcfile in "${RC_FILES[@]}"; do
    [ ! -f "$rcfile" ] && continue

    # Source the file in a subshell and list what functions get defined
    funcs=$(bash --norc --noprofile -c "source '$rcfile' 2>/dev/null; declare -F" 2>/dev/null | \
        awk '{print $3}')

    if [ -n "$funcs" ]; then
        warn "Functions defined by $rcfile:"
        echo "$funcs" | while read funcname; do
            # Flag if function shadows a critical command
            for cmd in "${CRITICAL_CMDS[@]}"; do
                if [ "$funcname" == "$cmd" ]; then
                    alert "  CRITICAL CMD SHADOWED: '$funcname' defined as function in $rcfile"
                    # Get the function body
                    body=$(bash --norc --noprofile -c \
                        "source '$rcfile' 2>/dev/null; declare -f $funcname" 2>/dev/null)
                    alert "  Function body:"
                    echo "$body" | while read line; do echo -e "    ${RED}$line${NC}"; done
                    log_incident "FUNCTION SHADOWS CRITICAL CMD" \
                        "$rcfile defines function '$funcname'"
                fi
            done
            echo "  - $funcname"
        done
    fi
done

# ============================================================
# SECTION 6: PACKAGE MANAGER & TOOL HOOKS
# Red teams plant hooks in git, pip, npm configs that execute
# during normal admin operations like 'git pull' or 'pip install'
# ============================================================
section "SECTION 6: PACKAGE MANAGER & TOOL HOOKS"

info "Checking git global config for hooks and URL rewriting..."
for homedir in /root /home/*/; do
    gitconfig="$homedir/.gitconfig"
    [ ! -f "$gitconfig" ] && continue
    warn "Git config: $gitconfig"
    cat "$gitconfig"

    # Flag suspicious git config entries
    grep -n "core.hooksPath\|url.*insteadOf\|filter\.\|credential\.helper" "$gitconfig" 2>/dev/null | \
    while read line; do
        alert "SUSPICIOUS GIT CONFIG in $gitconfig: $line"
        log_incident "GIT CONFIG HOOK" "$gitconfig: $line"
    done
done

# Global git hooks directory
for hook_dir in /usr/share/git-core/templates/hooks /etc/git/hooks; do
    [ ! -d "$hook_dir" ] && continue
    info "Git hooks in $hook_dir:"
    ls -la "$hook_dir" 2>/dev/null
    find "$hook_dir" -type f -executable 2>/dev/null | while read hook; do
        warn "Executable git hook: $hook"
        cat "$hook"
    done
done

info "Checking pip configuration for index URL rewriting..."
for pipconf in /root/.pip/pip.conf /etc/pip.conf /root/.config/pip/pip.conf; do
    [ ! -f "$pipconf" ] && continue
    warn "pip config: $pipconf"
    cat "$pipconf"
    grep -n "index-url\|extra-index-url\|trusted-host" "$pipconf" 2>/dev/null | while read line; do
        warn "pip source override: $line"
    done
done

# ============================================================
# SECTION 7: /etc/ld.so.conf — LIBRARY SEARCH PATH POISONING
# Adding a malicious directory here causes every process to
# search it for libraries before standard dirs
# ============================================================
section "SECTION 7: LIBRARY SEARCH PATH AUDIT"

info "/etc/ld.so.conf and includes:"
cat /etc/ld.so.conf 2>/dev/null
grep -rn "." /etc/ld.so.conf.d/ 2>/dev/null | while read line; do
    path=$(echo "$line" | awk -F: '{print $2}')
    file=$(echo "$line" | awk -F: '{print $1}')
    # Flag non-standard library paths
    if echo "$path" | grep -qv -E '^/(usr/)?lib'; then
        alert "NON-STANDARD LIBRARY PATH in $file: $path"
        log_incident "LIBRARY PATH POISONING" "$file: $path"
    else
        info "$file: $path"
    fi
done

# ============================================================
# SECTION 8: BINARY PATH AND TYPE VERIFICATION (improved v1)
# Now uses full path invocation to bypass any shell aliases
# ============================================================
section "SECTION 8: BINARY INTEGRITY & PATH VERIFICATION"

info "Checking critical command resolution (using full-path 'which' and 'type')..."

for cmd in "${CRITICAL_CMDS[@]}"; do
    # Use /usr/bin/which explicitly to bypass alias on 'which' itself
    first=$(/usr/bin/which "$cmd" 2>/dev/null)
    all=$(/usr/bin/which -a "$cmd" 2>/dev/null)
    count=$(echo "$all" | grep -c ".")

    if [ -z "$first" ]; then
        info "$cmd: not installed"
        continue
    fi

    cmd_dir=$(dirname "$first")
    if echo "$cmd_dir" | grep -qv -E '^/(usr/(local/)?)?(s)?bin$'; then
        alert "PATH HIJACK: '$cmd' resolves to non-standard: $first"
        log_incident "PATH HIJACK" "$cmd at $first"
    fi

    if [ "$count" -gt 1 ]; then
        warn "MULTIPLE LOCATIONS for '$cmd':"
        echo "$all" | while read loc; do echo "    $loc"; done
    fi

    # Check if it's been tampered with via file attributes
    if command -v lsattr &>/dev/null; then
        attrs=$(lsattr "$first" 2>/dev/null)
        info "$cmd: $attrs"
    fi
done

# ============================================================
# SECTION 9: AUDIT LOG INTEGRITY
# Red teams often tamper with or flush auth.log/syslog to
# erase evidence of their access. Detect log gaps.
# ============================================================
section "SECTION 9: LOG INTEGRITY & GAPS"

for logfile in /var/log/auth.log /var/log/syslog /var/log/messages /var/log/secure; do
    [ ! -f "$logfile" ] && continue

    size=$(wc -c < "$logfile")
    lines=$(wc -l < "$logfile")
    modified=$(stat -c '%Y' "$logfile" 2>/dev/null)
    now=$(date +%s)
    age=$(( now - modified ))

    info "$logfile: $lines lines, $size bytes, last modified ${age}s ago"

    # Alert if log file is suspiciously small
    [ "$size" -lt 1000 ] && alert "Log file suspiciously small: $logfile ($size bytes) — possibly wiped"

    # Alert if log hasn't been written to in >5 minutes (logging may be disabled)
    [ "$age" -gt 300 ] && warn "Log not updated in ${age}s: $logfile — logging may be disrupted"

    # Check for time gaps in auth.log (missing periods = log tampering)
    if [[ "$logfile" == *auth.log* ]] || [[ "$logfile" == *secure* ]]; then
        info "Last 5 auth events:"
        tail -5 "$logfile" 2>/dev/null
    fi
done

# Check if syslog daemon is actually running
if ! pgrep -x "rsyslogd\|syslogd\|syslog-ng" &>/dev/null; then
    alert "SYSLOG DAEMON NOT RUNNING — logging is disabled! Red team may have killed it."
    log_incident "LOGGING DISABLED" "No syslog daemon running"
fi

# ============================================================
# SECTION 10: REMEDIATION QUICK REFERENCE
# ============================================================
section "SECTION 10: REMEDIATION"

echo -e "${YLW}Run commands safely (bypass all aliases/functions):${NC}"
echo "  /bin/bash --norc --noprofile     # clean shell, no rc files loaded"
echo "  /usr/bin/sudo -i                  # full path sudo"
echo "  \\sudo command                     # backslash bypasses alias"
echo "  command sudo                      # 'command' bypasses shell functions"
echo "  env -i /bin/bash                  # completely clean environment"
echo ""
echo -e "${YLW}Kill a suspicious process safely:${NC}"
echo "  /bin/kill -9 <PID>"
echo ""
echo -e "${YLW}If you suspect your shell is compromised, open a clean one:${NC}"
echo "  /bin/bash --norc --noprofile --nologin"
echo "  env -i HOME=/root PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin /bin/bash --norc"
echo ""
echo -e "${YLW}Check your OWN current shell right now:${NC}"
echo "  alias                  # all active aliases"
echo "  declare -f             # all shell functions"
echo "  trap -p                # all active traps"
echo "  echo \$PROMPT_COMMAND   # is this set?"
echo "  echo \$BASH_ENV         # is this set?"
echo "  env                    # full environment"
echo ""

section "AUDIT COMPLETE"
echo -e "${GRN}Log: $LOGFILE${NC}"
echo -e "${GRN}Incidents: $INCIDENT_LOG${NC}"
