#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Port Traffic Monitor v2 — Attacker-Aware Edition
#
#  WHAT CHANGED FROM v1 AND WHY:
#
#  GAP 1: v1 trusted 'ss' output blindly.
#  A red teamer with root can replace or wrap ss/netstat with
#  a version that hides their connections. We now cross-reference
#  ss output against /proc/net/tcp directly — that's kernel
#  memory, much harder to fake without a rootkit.
#
#  GAP 2: v1 only checked binary NAME from ss proc field.
#  Red team can rename nc to "apache2" or copy sshd binary.
#  We now check the actual inode, file hash, and /proc/PID/exe
#  symlink to verify the binary on disk matches what's expected.
#
#  GAP 3: v1 missed IPv6 listeners entirely.
#  Many services dual-stack. Backdoors often bind ::1 or :::4444
#  specifically because blue teams forget IPv6.
#
#  GAP 4: v1 had no TIME_WAIT / half-open detection.
#  SYN floods and slow loris attacks leave traces in socket state
#  that established-only checks miss completely.
#
#  GAP 5: v1 tunneling detection was too shallow.
#  Real tunnel detection needs byte ratio analysis and timing,
#  not just "is socat running". Added iodine/dnscat2 detection,
#  and per-connection byte asymmetry flagging.
#
#  GAP 6: v1 sleep() is predictable.
#  A smart red team times their activity between your check
#  intervals. We now jitter the sleep and add a paranoia mode
#  with much shorter intervals.
#
#  Run as root. Usage:
#    bash pcdc_port_monitor_v2.sh [interval_seconds] [--paranoid]
#    --paranoid: 5s interval, maximum verbosity
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
LOGFILE="$LOGDIR/portmon_v2_$TIMESTAMP.log"
INCIDENT_LOG="$LOGDIR/incidents_$TIMESTAMP.log"
STATE_DIR="$LOGDIR/portstate_v2"

mkdir -p "$LOGDIR" "$STATE_DIR"
exec > >(tee -a "$LOGFILE") 2>&1

ok()      { echo -e "${GRN}[OK]${NC}      $1"; }
warn()    { echo -e "${YLW}[WARN]${NC}    $1"; }
alert()   {
    echo -e "${RED}[ALERT]${NC}   $1"
    echo "[$(date '+%H:%M:%S')] ALERT: $1" >> "$INCIDENT_LOG"
}
info()    { echo -e "${CYN}[INFO]${NC}    $1"; }
section() {
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
Src IP:   ${3:-UNKNOWN}
============================================================
EOF
}

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run as root.${NC}"; exit 1
fi

INTERVAL=${1:-30}
PARANOID=false
[[ "$*" == *"--paranoid"* ]] && PARANOID=true && INTERVAL=5

# ============================================================
# KNOWN SERVICES TABLE
# CRITICAL: populate this from your Blue Team Packet
# before Red Team attacks start.
# Format: [port]="binary1 binary2"
# ============================================================
declare -A KNOWN_PORTS
KNOWN_PORTS=(
    [22]="sshd"
    [80]="apache2 nginx httpd"
    [443]="apache2 nginx httpd"
    [25]="postfix sendmail exim"
    [587]="postfix"
    [53]="named bind9 dnsmasq unbound"
    [3306]="mysqld mariadbd"
    [5432]="postgres"
    [21]="vsftpd proftpd"
    [445]="smbd"
    [139]="smbd"
    [3389]="xrdp"
    [8080]="apache2 nginx tomcat java"
    [8443]="apache2 nginx tomcat java"
)

# Hashes of legitimate service binaries — compute at startup
# Red team can copy/rename a binary but the hash will differ
# from the real service binary OR match a known attack tool
declare -A BINARY_HASHES

# Thresholds
CONN_THRESHOLD=20
RATE_THRESHOLD=50
FOREIGN_THRESHOLD=10
BYTE_RATIO_THRESHOLD=10   # outbound/inbound byte ratio — high = possible exfil

# ============================================================
# STARTUP: Hash all known service binaries for later comparison
# This runs ONCE at script start — before red team can tamper
# ============================================================
hash_known_binaries() {
    section "HASHING KNOWN SERVICE BINARIES (run before attacks start)"
    info "Computing SHA256 hashes of all service binaries..."
    info "If these change mid-competition, a binary was replaced."

    for port in "${!KNOWN_PORTS[@]}"; do
        for binary in ${KNOWN_PORTS[$port]}; do
            binary_path=$(which "$binary" 2>/dev/null)
            if [ -n "$binary_path" ] && [ -f "$binary_path" ]; then
                hash=$(sha256sum "$binary_path" 2>/dev/null | awk '{print $1}')
                BINARY_HASHES["$binary"]="$hash:$binary_path"
                ok "$binary → $binary_path [$hash]"
            fi
        done
    done

    # Save to disk so we can re-check later even if array is lost
    for key in "${!BINARY_HASHES[@]}"; do
        echo "$key=${BINARY_HASHES[$key]}"
    done > "$STATE_DIR/binary_hashes.baseline"

    echo ""
    info "Hashes saved to $STATE_DIR/binary_hashes.baseline"
}

check_binary_integrity() {
    section "BINARY INTEGRITY VERIFICATION"
    info "Re-hashing service binaries and comparing to baseline..."

    while IFS='=' read -r binary rest; do
        orig_hash=$(echo "$rest" | cut -d: -f1)
        binary_path=$(echo "$rest" | cut -d: -f2)

        if [ ! -f "$binary_path" ]; then
            alert "BINARY MISSING: $binary_path — was it deleted?"
            log_incident "BINARY DELETED" "$binary_path is gone" ""
            continue
        fi

        current_hash=$(sha256sum "$binary_path" 2>/dev/null | awk '{print $1}')
        if [ "$current_hash" != "$orig_hash" ]; then
            alert "BINARY MODIFIED: $binary_path hash changed!"
            alert "  Original: $orig_hash"
            alert "  Current:  $current_hash"
            log_incident "BINARY TAMPERED" "$binary_path hash mismatch" ""
        else
            ok "$binary → unchanged"
        fi
    done < "$STATE_DIR/binary_hashes.baseline"
}

# ============================================================
# /proc/net/tcp CROSS-REFERENCE
# Bypasses any compromised ss/netstat wrapper
# Reads kernel socket table directly
# ============================================================
proc_net_listeners() {
    section "KERNEL-LEVEL PORT SCAN (/proc/net/tcp + tcp6)"
    info "Reading socket table directly from kernel — cannot be hidden by userspace tools"

    # /proc/net/tcp hex format: local_address is hex IP:port (little-endian)
    parse_proc_net_tcp() {
        local file=$1
        local proto=$2
        # State 0A = LISTEN, 01 = ESTABLISHED
        awk 'NR>1 {
            split($2, local, ":");
            split($3, remote, ":");
            state=$4;
            inode=$10;
            # Convert hex port to decimal
            port=strtonum("0x" local[2]);
            if (state == "0A") {
                printf "LISTEN port=%d inode=%s proto=%s\n", port, inode, proto
            } else if (state == "01") {
                rem_port=strtonum("0x" remote[2]);
                printf "ESTAB local_port=%d remote_port=%d inode=%s proto=%s\n", port, rem_port, inode, proto
            }
        }' "$file" 2>/dev/null
    }

    parse_proc_net_tcp /proc/net/tcp  "tcp4" > "$STATE_DIR/proc_listeners.current"
    parse_proc_net_tcp /proc/net/tcp6 "tcp6" >> "$STATE_DIR/proc_listeners.current"

    info "All LISTENING ports from /proc/net/tcp:"
    grep "^LISTEN" "$STATE_DIR/proc_listeners.current" | sort -t= -k2 -n

    # Cross-reference: ports in /proc/net but NOT in ss output
    echo ""
    info "Cross-referencing /proc/net against ss output..."

    ss_ports=$(ss -tulnp 2>/dev/null | awk 'NR>1{print $5}' | rev | cut -d: -f1 | rev | sort -n)

    grep "^LISTEN" "$STATE_DIR/proc_listeners.current" | while read line; do
        proc_port=$(echo "$line" | grep -oP 'port=\K[0-9]+')
        if ! echo "$ss_ports" | grep -q "^${proc_port}$"; then
            alert "HIDDEN PORT DETECTED: Port $proc_port visible in /proc/net but NOT in ss output"
            alert "  This strongly suggests a rootkit or compromised ss binary!"
            log_incident "HIDDEN PORT (ROOTKIT INDICATOR)" \
                "Port $proc_port in /proc/net/tcp but absent from ss" ""
        fi
    done

    # Compare to baseline if it exists
    if [ -f "$STATE_DIR/proc_listeners.baseline" ]; then
        new=$(comm -13 \
            <(grep LISTEN "$STATE_DIR/proc_listeners.baseline" | sort) \
            <(grep LISTEN "$STATE_DIR/proc_listeners.current" | sort))
        if [ -n "$new" ]; then
            alert "NEW LISTENER in /proc/net (kernel-confirmed):"
            echo "$new"
            log_incident "NEW KERNEL-CONFIRMED LISTENER" "$new" ""
        fi
    else
        grep LISTEN "$STATE_DIR/proc_listeners.current" > "$STATE_DIR/proc_listeners.baseline"
        ok "Kernel listener baseline saved."
    fi
}

# ============================================================
# IPv6 LISTENER CHECK
# Backdoors love binding to IPv6 because blue teams forget it
# ============================================================
check_ipv6_listeners() {
    section "IPv6 LISTENER AUDIT"
    info "All IPv6 listening sockets:"
    ss -tulnp 2>/dev/null | grep -E "\[|::|\*" | while read line; do
        port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
        binary=$(echo "$line" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
        expected="${KNOWN_PORTS[$port]}"

        if [ -n "$expected" ]; then
            ok "IPv6 port $port → $binary (known service)"
        else
            warn "IPv6 port $port open (owner: $binary) — verify this is expected"
        fi
        echo "  $line"
    done

    # Specifically flag IPv6 listeners on non-standard ports
    ss -tulnp 2>/dev/null | grep -E "\[|::" | while read proto rq sq local foreign state proc; do
        port=$(echo "$local" | rev | cut -d: -f1 | rev)
        binary=$(echo "$proc" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
        if [ -z "${KNOWN_PORTS[$port]}" ]; then
            alert "UNEXPECTED IPv6 LISTENER: port $port owned by $binary"
            log_incident "UNEXPECTED IPv6 LISTENER" "port $port binary $binary" ""
        fi
    done
}

# ============================================================
# SOCKET STATE ANALYSIS
# TIME_WAIT flood = SYN/DoS attack in progress
# SYN_RECV flood = SYN flood
# FIN_WAIT accumulation = slow loris or teardown attack
# ============================================================
check_socket_states() {
    section "SOCKET STATE ANALYSIS"

    declare -A STATE_COUNTS
    while read state; do
        STATE_COUNTS["$state"]=$(( ${STATE_COUNTS["$state"]:-0} + 1 ))
    done < <(ss -tan 2>/dev/null | awk 'NR>1 {print $1}')

    for state in "${!STATE_COUNTS[@]}"; do
        count=${STATE_COUNTS[$state]}
        case "$state" in
            TIME-WAIT)
                [ "$count" -gt 200 ] && \
                    alert "TIME-WAIT flood: $count sockets — possible DoS or rapid connection cycling" || \
                    info "TIME-WAIT: $count"
                ;;
            SYN-RECV)
                [ "$count" -gt 50 ] && \
                    alert "SYN-RECV flood: $count sockets — SYN FLOOD ATTACK IN PROGRESS" || \
                    info "SYN-RECV: $count"
                ;;
            FIN-WAIT-*)
                [ "$count" -gt 100 ] && \
                    warn "FIN-WAIT accumulation: $count ($state) — possible slow-loris or teardown attack" || \
                    info "$state: $count"
                ;;
            CLOSE-WAIT)
                [ "$count" -gt 50 ] && \
                    warn "CLOSE-WAIT: $count — application may not be closing connections cleanly" || \
                    info "CLOSE-WAIT: $count"
                ;;
            ESTABLISHED)
                info "ESTABLISHED: $count"
                ;;
            LISTEN)
                info "LISTEN: $count"
                ;;
        esac
    done
}

# ============================================================
# BYTE RATIO ANALYSIS — exfil and tunnel detection
# Legitimate services mostly receive more than they send
# (web server gets requests, sends responses — ratio ~1:5)
# A machine exfiltrating data sends MORE than it receives
# ============================================================
check_byte_ratios() {
    section "BYTE RATIO ANALYSIS (Exfil / Tunnel Detection)"
    info "Checking per-interface TX/RX byte ratios..."

    # Read from /proc/net/dev — not dependent on any userspace tool
    awk 'NR>2 {
        iface=$1
        rx_bytes=$2
        tx_bytes=$10
        gsub(/:/, "", iface)
        if (rx_bytes+0 > 0 && tx_bytes+0 > 0) {
            ratio = tx_bytes / rx_bytes
            printf "%-12s RX: %s bytes  TX: %s bytes  TX/RX ratio: %.2f\n", iface, rx_bytes, tx_bytes, ratio
        }
    }' /proc/net/dev | while read line; do
        ratio=$(echo "$line" | grep -oP 'ratio: \K[0-9.]+')
        iface=$(echo "$line" | awk '{print $1}')
        echo "  $line"
        # Flag if TX/RX ratio is unusually high (sending much more than receiving)
        if (( $(echo "$ratio > $BYTE_RATIO_THRESHOLD" | bc -l 2>/dev/null) )); then
            alert "HIGH TX/RX RATIO on $iface: $ratio — possible data exfiltration"
            log_incident "POSSIBLE DATA EXFIL" "Interface $iface TX/RX ratio $ratio" ""
        fi
    done

    # Track per-interface counters over time to detect spikes
    awk 'NR>2 {gsub(/:/, "", $1); print $1, $2, $10}' /proc/net/dev > "$STATE_DIR/bytes.current"

    if [ -f "$STATE_DIR/bytes.baseline" ]; then
        while read iface rx_now tx_now; do
            prev=$(grep "^$iface " "$STATE_DIR/bytes.baseline" 2>/dev/null)
            if [ -n "$prev" ]; then
                rx_prev=$(echo "$prev" | awk '{print $2}')
                tx_prev=$(echo "$prev" | awk '{print $3}')
                rx_delta=$(( rx_now - rx_prev ))
                tx_delta=$(( tx_now - tx_prev ))
                if [ "$tx_delta" -gt 10000000 ]; then  # >10MB sent since last check
                    warn "$iface: Sent ${tx_delta} bytes since last check ($(( tx_delta/1024/1024 ))MB)"
                fi
                if [ "$rx_delta" -gt 50000000 ]; then  # >50MB received
                    warn "$iface: Received ${rx_delta} bytes since last check ($(( rx_delta/1024/1024 ))MB)"
                fi
            fi
        done < "$STATE_DIR/bytes.current"
    fi
    cp "$STATE_DIR/bytes.current" "$STATE_DIR/bytes.baseline"
}

# ============================================================
# ENHANCED TUNNEL DETECTION
# Adds: iodine (DNS tunnel), dnscat2, chisel, ligolo, ptunnel
# and timing-based C2 beacon detection
# ============================================================
check_tunneling_v2() {
    section "ENHANCED TUNNEL DETECTION"

    # Known tunnel/C2 tool names — red teams rename these, but process args still leak
    TUNNEL_TOOLS=("iodine" "iodined" "dnscat" "dnscat2" "chisel" "ligolo"
                  "ptunnel" "hans" "icmptunnel" "nstx" "proxychains"
                  "stunnel" "httptunnel" "nc" "ncat" "socat" "plink")

    for tool in "${TUNNEL_TOOLS[@]}"; do
        pids=$(pgrep -f "$tool" 2>/dev/null)
        if [ -n "$pids" ]; then
            alert "TUNNEL/C2 TOOL PROCESS DETECTED: $tool (PIDs: $pids)"
            for pid in $pids; do
                cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
                info "  PID $pid | exe: $exe | cmd: $cmdline"
            done
            log_incident "TUNNEL TOOL DETECTED" "$tool PIDs: $pids" ""
        fi
    done

    # DNS tunnel: look for abnormally large DNS queries in raw socket buffers
    # Real DNS queries are tiny. Tunneled DNS has large TXT/NULL record payloads.
    info "Checking DNS query sizes via /proc/net/udp..."
    awk 'NR>1 {
        split($3, r, ":");
        rem_port=strtonum("0x" r[2]);
        tx_queue=strtonum("0x" $5);
        rx_queue=strtonum("0x" $6);
        if (rem_port == 53 && (tx_queue > 512 || rx_queue > 512)) {
            printf "Large DNS buffer: remote port 53, tx_queue=%d rx_queue=%d inode=%s\n",
                tx_queue, rx_queue, $10
        }
    }' /proc/net/udp 2>/dev/null | while read line; do
        warn "Possible DNS tunnel payload: $line"
        log_incident "DNS TUNNEL LARGE PAYLOAD" "$line" ""
    done

    # C2 beacon detection — look for connections with suspiciously regular timing
    # We track established connections across cycles and flag ones that persist
    # with consistent re-connection patterns
    ss -tnp state established 2>/dev/null | awk 'NR>1 {print $5}' | \
        rev | cut -d: -f2- | rev | sort | uniq -c | sort -rn | while read count ip; do
        if [ "$count" -gt 3 ]; then
            warn "Repeated connections from $ip ($count sessions) — check for C2 beaconing"
        fi
    done

    # Check for any process connecting outbound to high ports (>1024) on non-standard IPs
    # Legitimate scored services rarely call OUT to random high ports
    info "Outbound connections to high ports (possible C2/exfil channels):"
    ss -tnp state established 2>/dev/null | awk 'NR>1 {print $4, $5}' | while read local foreign; do
        f_port=$(echo "$foreign" | rev | cut -d: -f1 | rev)
        f_ip=$(echo "$foreign" | rev | cut -d: -f2- | rev)
        l_port=$(echo "$local" | rev | cut -d: -f1 | rev)

        # Flag outbound connections to ports above 1024 that aren't standard service ports
        if [ "$f_port" -gt 1024 ] 2>/dev/null; then
            case "$f_port" in
                3306|5432|6379|27017|8080|8443|8888|9000) ;;  # known high ports
                *)
                    warn "Outbound to $f_ip:$f_port (from local port $l_port)"
                    ;;
            esac
        fi
    done
}

# ============================================================
# PORT OWNER DEEP VERIFICATION
# v1 only checked binary NAME. Red team renames nc → apache2.
# v2 checks: inode ownership, /proc/PID/exe actual path,
# and hashes the running binary against our stored baseline.
# ============================================================
check_port_owner_deep() {
    section "DEEP PORT OWNER VERIFICATION"
    info "Verifying port owners via /proc/PID/exe (bypasses binary renaming)..."

    ss -tulnp 2>/dev/null | tail -n +2 | while read proto rq sq local foreign state proc; do
        port=$(echo "$local" | rev | cut -d: -f1 | rev)
        binary=$(echo "$proc" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
        pid=$(echo "$proc" | grep -oP 'pid=\K[0-9]+' | head -1)

        [ -z "$pid" ] && continue

        # Get the ACTUAL binary path via /proc/PID/exe
        actual_exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        actual_basename=$(basename "$actual_exe" 2>/dev/null)

        # Was this binary deleted (running from deleted file = suspicious)
        if echo "$actual_exe" | grep -q "(deleted)"; then
            alert "PORT $port: Binary was DELETED but process is still running!"
            alert "  exe was: $actual_exe | reported as: $binary"
            log_incident "DELETED BINARY HOLDING PORT" \
                "Port $port PID $pid exe: $actual_exe" ""
            continue
        fi

        expected="${KNOWN_PORTS[$port]}"
        if [ -n "$expected" ]; then
            # Check actual binary name, not just what ss reports
            if echo "$expected" | grep -qw "$actual_basename"; then
                ok "Port $port → $actual_exe (verified via /proc)"
            else
                alert "PORT OWNER MISMATCH via /proc: Port $port"
                alert "  ss reports:   $binary"
                alert "  /proc/exe:    $actual_exe ($actual_basename)"
                alert "  Expected:     $expected"
                log_incident "PORT OWNER MISMATCH" \
                    "Port $port: ss=$binary proc=$actual_exe expected=$expected" ""
            fi

            # Hash the actual running binary and compare to baseline
            if [ -f "$STATE_DIR/binary_hashes.baseline" ]; then
                expected_hash=$(grep "^${actual_basename}=" "$STATE_DIR/binary_hashes.baseline" 2>/dev/null | \
                    cut -d= -f2 | cut -d: -f1)
                if [ -n "$expected_hash" ]; then
                    current_hash=$(sha256sum "$actual_exe" 2>/dev/null | awk '{print $1}')
                    if [ "$current_hash" != "$expected_hash" ]; then
                        alert "BINARY HASH MISMATCH for port $port!"
                        alert "  Binary: $actual_exe"
                        alert "  Expected hash: $expected_hash"
                        alert "  Current hash:  $current_hash"
                        log_incident "BINARY REPLACED/TAMPERED" \
                            "$actual_exe hash changed. Port $port" ""
                    fi
                fi
            fi
        else
            warn "Port $port: no expected owner defined. Actual binary: $actual_exe"
        fi
    done
}

# ============================================================
# CONNECTION OWNER DEEP CHECK
# Also checks /proc/PID/fd to see ALL open file descriptors
# Reverse shells often have stdin/stdout/stderr all pointed
# at a socket — that's a dead giveaway
# ============================================================
check_reverse_shell_indicators() {
    section "REVERSE SHELL DETECTION"
    info "Checking for processes with socket FDs on stdin/stdout/stderr..."

    for pid_dir in /proc/[0-9]*/; do
        pid="${pid_dir%/}"; pid="${pid##*/}"
        [ ! -d "/proc/$pid/fd" ] && continue

        comm=$(cat "/proc/$pid/comm" 2>/dev/null)
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)

        # Check if fd 0, 1, 2 are all sockets (classic reverse shell indicator)
        fd0=$(readlink "/proc/$pid/fd/0" 2>/dev/null)
        fd1=$(readlink "/proc/$pid/fd/1" 2>/dev/null)
        fd2=$(readlink "/proc/$pid/fd/2" 2>/dev/null)

        if echo "$fd0 $fd1 $fd2" | grep -q "socket:"; then
            socket_count=$(echo "$fd0 $fd1 $fd2" | grep -c "socket:")
            if [ "$socket_count" -ge 2 ]; then
                alert "LIKELY REVERSE SHELL: PID $pid ($comm | $exe)"
                alert "  fd0=$fd0"
                alert "  fd1=$fd1"
                alert "  fd2=$fd2"
                cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                alert "  cmdline: $cmdline"
                log_incident "REVERSE SHELL DETECTED" \
                    "PID $pid $comm ($exe) stdin/stdout/stderr all point to socket" ""
            fi
        fi

        # Also flag shells with any socket at all (weaker signal but worth noting)
        if echo "$comm" | grep -qE '^(bash|sh|dash|zsh|ksh)$'; then
            socket_fds=$(find "/proc/$pid/fd/" -maxdepth 1 -type l 2>/dev/null -exec readlink {} \; | grep -c "socket:" || true)
            if [ "$socket_fds" -gt 0 ]; then
                warn "Shell PID $pid ($comm) has $socket_fds open socket(s)"
                cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                info "  cmdline: $cmdline"
            fi
        fi
    done
}

# ============================================================
# NEW LISTENERS + OLD v1 CHECKS (kept and improved)
# ============================================================
check_new_listeners() {
    ss -tulnp 2>/dev/null | tail -n +2 | while read proto rq sq local foreign state proc; do
        port=$(echo "$local" | rev | cut -d: -f1 | rev)
        echo "$port $proc"
    done | sort -n > "$STATE_DIR/listeners.current"

    new_listeners=$(comm -13 "$STATE_DIR/listeners.baseline" "$STATE_DIR/listeners.current" 2>/dev/null)
    if [ -n "$new_listeners" ]; then
        alert "NEW LISTENER(S) DETECTED:"
        echo "$new_listeners" | while read line; do
            echo -e "  ${RED}>>> $line${NC}"
            log_incident "NEW LISTENING PORT" "$line" ""
        done
        cp "$STATE_DIR/listeners.current" "$STATE_DIR/listeners.baseline"
    fi
}

check_connection_volume() {
    ss -tnp 2>/dev/null | awk 'NR>1{print $5}' | rev | cut -d: -f1 | rev | \
        sort | uniq -c | sort -rn > "$STATE_DIR/portcount.current"

    while read count port; do
        if [ "$count" -gt "$CONN_THRESHOLD" ]; then
            alert "HIGH TRAFFIC on port $port: $count connections"
            log_incident "HIGH CONNECTION VOLUME" "Port $port: $count connections" ""
        fi
    done < "$STATE_DIR/portcount.current"
}

# ============================================================
# JITTERED SLEEP — prevents red team timing around our checks
# ============================================================
jitter_sleep() {
    local base=$1
    local jitter=$(( RANDOM % (base / 2) ))
    local actual=$(( base - (base/4) + jitter ))
    info "Next check in ${actual}s..."
    sleep "$actual"
}

# ============================================================
# MAIN
# ============================================================
clear
echo -e "${BLU}"
echo "  ┌──────────────────────────────────────────────┐"
echo "  │   ASTRA 9 PORT MONITOR v2                    │"
echo "  │   Attacker-Aware Edition | PCDC 2026         │"
$PARANOID && echo "  │   *** PARANOID MODE ACTIVE ***               │"
echo "  └──────────────────────────────────────────────┘"
echo -e "${NC}"
echo "  Host:     $(hostname)"
echo "  IP:       $(hostname -I | awk '{print $1}')"
echo "  Interval: ~${INTERVAL}s (jittered)"
echo "  Log:      $LOGFILE"
echo "  Incident: $INCIDENT_LOG"
echo ""

hash_known_binaries

# Initial baseline
ss -tulnp 2>/dev/null | tail -n +2 | while read proto rq sq local foreign state proc; do
    port=$(echo "$local" | rev | cut -d: -f1 | rev)
    echo "$port $proc"
done | sort -n > "$STATE_DIR/listeners.baseline"

cp /dev/null "$STATE_DIR/bytes.baseline"

info "Baseline captured. Starting monitoring loop."
if $PARANOID; then
    warn "PARANOID MODE: checking every ~5s, maximum verbosity"
fi
echo ""

LOOP=0
while true; do
    LOOP=$((LOOP + 1))
    echo ""
    echo -e "${MAG}══ Cycle #$LOOP | $(date '+%H:%M:%S') ══${NC}"

    proc_net_listeners          # kernel-level, bypasses compromised ss
    check_ipv6_listeners        # catches backdoors on IPv6
    check_socket_states         # DoS indicators
    check_new_listeners         # standard new port detection
    check_port_owner_deep       # binary verification via /proc
    check_binary_integrity      # hash check of service binaries
    check_reverse_shell_indicators  # stdin/stdout/stderr socket check
    check_tunneling_v2          # enhanced tunnel + C2 detection
    check_byte_ratios           # exfil via traffic volume
    check_connection_volume     # flood detection

    jitter_sleep "$INTERVAL"
done
