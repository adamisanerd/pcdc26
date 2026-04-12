#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Port Traffic Monitor & Anomaly Detector
#
#  Detects:
#  - Unusual traffic volume on any port (flood/exfil)
#  - Services on unexpected ports
#  - Port reuse (legit service port used by attacker binary)
#  - Connections to unexpected foreign IPs
#  - Tunneling (SSH, DNS, ICMP used as covert channels)
#  - New listeners that weren't there at baseline
#
#  Requires: ss, iptables, tcpdump (optional), netstat
#  Run as root.
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
LOGFILE="$LOGDIR/portmon_$TIMESTAMP.log"
INCIDENT_LOG="$LOGDIR/incidents_$TIMESTAMP.log"
STATE_DIR="$LOGDIR/portstate"

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

# ============================================================
# KNOWN SERVICES TABLE
# Edit this to match your scored services!
# Format: PORT:PROTOCOL:EXPECTED_BINARY
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
    [8080]="apache2 nginx tomcat"
    [8443]="apache2 nginx tomcat"
)

# Traffic thresholds — connections per port before alerting
CONN_THRESHOLD=20      # alert if >N connections on a single port
RATE_THRESHOLD=50      # alert if >N new connections in one check cycle
FOREIGN_THRESHOLD=10   # alert if >N distinct foreign IPs on one port

# ============================================================
# BASELINE: snapshot of ports and their expected owners
# ============================================================
capture_baseline() {
    section "CAPTURING BASELINE"

    info "Snapshotting all listening sockets and their owning processes..."

    # Format: port -> "pid/binary"
    ss -tulnp 2>/dev/null | tail -n +2 | while read -r _proto _recvq _sendq local _foreign _state proc; do
        port=$(echo "$local" | rev | cut -d: -f1 | rev)
        echo "$port $proc"
    done | sort -n > "$STATE_DIR/listeners.baseline"

    info "Snapshotting established connections..."
    ss -tnp state established 2>/dev/null | tail -n +2 | sort > "$STATE_DIR/connections.baseline"

    info "Counting connections per port..."
    ss -tnp 2>/dev/null | awk 'NR>1 {print $5}' | rev | cut -d: -f1 | rev | \
        sort | uniq -c | sort -rn > "$STATE_DIR/portcount.baseline"

    ok "Baseline captured."
    cat "$STATE_DIR/listeners.baseline"
    echo ""
}

# ============================================================
# CHECK 1: NEW LISTENERS
# Any port that wasn't open at baseline
# ============================================================
check_new_listeners() {
    ss -tulnp 2>/dev/null | tail -n +2 | while read -r _proto _recvq _sendq local _foreign _state proc; do
        port=$(echo "$local" | rev | cut -d: -f1 | rev)
        echo "$port $proc"
    done | sort -n > "$STATE_DIR/listeners.current"

    new_listeners=$(comm -13 "$STATE_DIR/listeners.baseline" "$STATE_DIR/listeners.current")

    if [ -n "$new_listeners" ]; then
        alert "NEW LISTENER(S) DETECTED:"
        echo "$new_listeners" | while read line; do
            echo -e "  ${RED}>>> $line${NC}"
            log_incident "NEW LISTENING PORT" "$line" ""
        done
        cp "$STATE_DIR/listeners.current" "$STATE_DIR/listeners.baseline"
    fi
}

# ============================================================
# CHECK 2: PORT/BINARY MISMATCH
# Red team runs their tool ON a legitimate port (e.g., netcat on :80)
# The port is open but the binary isn't what should be there
# ============================================================
check_port_binary_mismatch() {
    section "PORT → BINARY MISMATCH CHECK"
    info "Verifying that each known port is owned by the expected binary..."

    ss -tulnp 2>/dev/null | tail -n +2 | while read -r _proto _recvq _sendq local foreign _state proc; do
        port=$(echo "$local" | rev | cut -d: -f1 | rev)
        # Extract binary name from proc field (format: users:(("sshd",pid=1234,...)))
        binary=$(echo "$proc" | grep -oP '"[^"]*"' | head -1 | tr -d '"')

        if [ -z "$binary" ]; then continue; fi

        expected="${KNOWN_PORTS[$port]}"

        if [ -n "$expected" ]; then
            if echo "$expected" | grep -qw "$binary"; then
                ok "Port $port → $binary (expected)"
            else
                alert "PORT HIJACK: Port $port expected ($expected) but found ($binary)"
                log_incident "PORT HIJACK / BINARY MISMATCH" \
                    "Port $port: expected [$expected] but found [$binary]" ""
            fi
        else
            warn "Port $port open, owned by '$binary' — not in known ports list"
        fi
    done
}

# ============================================================
# CHECK 3: CONNECTION VOLUME PER PORT
# Detects flooding (DoS), data exfiltration, or C2 beaconing
# ============================================================
check_connection_volume() {
    section "CONNECTION VOLUME ANALYSIS"

    ss -tnp 2>/dev/null | awk 'NR>1 {print $5}' | rev | cut -d: -f1 | rev | \
        sort | uniq -c | sort -rn > "$STATE_DIR/portcount.current"

    info "Current connection counts per port (top 20):"
    head -20 "$STATE_DIR/portcount.current"

    echo ""
    # Alert on ports with too many connections
    while read count port; do
        if [ "$count" -gt "$CONN_THRESHOLD" ]; then
            alert "HIGH TRAFFIC on port $port: $count connections (threshold: $CONN_THRESHOLD)"
            # Who's connecting?
            info "Top sources on port $port:"
            ss -tnp 2>/dev/null | awk -v p=":$port" '$5 ~ p || $4 ~ p {print $5}' | \
                sort | uniq -c | sort -rn | head -10
            log_incident "HIGH CONNECTION VOLUME" \
                "Port $port has $count connections" "$(ss -tnp 2>/dev/null | awk -v p=":$port" '$5 ~ p {print $5}' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')"
        fi
    done < "$STATE_DIR/portcount.current"

    # Detect new connections since last check
    ss -tnp state established 2>/dev/null | tail -n +2 | sort > "$STATE_DIR/connections.current"
    new_conns=$(comm -13 "$STATE_DIR/connections.baseline" "$STATE_DIR/connections.current" | wc -l)
    if [ "$new_conns" -gt "$RATE_THRESHOLD" ]; then
        alert "CONNECTION RATE SPIKE: $new_conns new connections since last check"
        log_incident "CONNECTION RATE SPIKE" "$new_conns new connections in ${INTERVAL}s" ""
    fi
    cp "$STATE_DIR/connections.current" "$STATE_DIR/connections.baseline"
}

# ============================================================
# CHECK 4: FOREIGN IP DIVERSITY PER PORT
# Many distinct IPs on one port = scan/attack
# One persistent unexpected IP = C2
# ============================================================
check_foreign_ip_diversity() {
    section "FOREIGN IP ANALYSIS"

    info "Distinct foreign IPs per local port:"
    ss -tnp 2>/dev/null | awk 'NR>1 {print $4, $5}' | while read local foreign; do
        local_port=$(echo "$local" | rev | cut -d: -f1 | rev)
        foreign_ip=$(echo "$foreign" | rev | cut -d: -f2- | rev)
        echo "$local_port $foreign_ip"
    done | sort | uniq | awk '{print $1}' | sort | uniq -c | sort -rn | while read count port; do
        if [ "$count" -gt "$FOREIGN_THRESHOLD" ]; then
            alert "MANY DISTINCT IPs on port $port: $count unique sources (possible scan/attack)"
            info "Top IPs connecting to port $port:"
            ss -tnp 2>/dev/null | awk -v p=":$port" '{print $4, $5}' | \
                grep "^.*:$port " | awk '{print $2}' | \
                rev | cut -d: -f2- | rev | sort | uniq -c | sort -rn | head -10
        elif [ "$count" -gt 1 ]; then
            info "Port $port: $count distinct foreign IPs"
        fi
    done
}

# ============================================================
# CHECK 5: DETECT TUNNELING
# SSH tunneling: SSH connections with unusual byte counts
# DNS tunneling: high query volume or large DNS payloads
# ICMP tunneling: oversized ICMP or high ICMP volume
# ============================================================
check_tunneling() {
    section "TUNNEL DETECTION"

    # SSH tunnel detection — look for SSH connections with port forwarding
    info "Checking for SSH port forwards (local and remote):"
    ss -tnp state established 2>/dev/null | grep ":22 " | while read line; do
        info "Active SSH connection: $line"
    done

    # Check if ssh is listening on non-standard ports (could be tunnel endpoint)
    ss -tulnp 2>/dev/null | grep -i "ssh\|sshd" | while read line; do
        port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
        if [ "$port" != "22" ]; then
            alert "SSH/SSHD listening on NON-STANDARD PORT: $port"
            log_incident "SSH TUNNELING" "SSHD on port $port" ""
        fi
    done

    # DNS tunneling — check for excessive DNS traffic
    if command -v ss &>/dev/null; then
        dns_conns=$(ss -unp 2>/dev/null | grep ":53 " | wc -l)
        if [ "$dns_conns" -gt 20 ]; then
            alert "EXCESSIVE DNS TRAFFIC: $dns_conns UDP connections to port 53 — possible DNS tunnel"
            log_incident "DNS TUNNELING SUSPECTED" "$dns_conns DNS connections" ""
        else
            info "DNS connections: $dns_conns (normal)"
        fi
    fi

    # ICMP — use /proc/net/icmp if available
    if [ -f /proc/net/icmp ]; then
        icmp_count=$(wc -l < /proc/net/icmp)
        if [ "$icmp_count" -gt 10 ]; then
            warn "Elevated ICMP entries in /proc/net/icmp: $icmp_count — possible ICMP tunnel"
        fi
    fi

    # Check for socat, ncat, netcat used as relay (common tunneling tools)
    for tool in socat ncat nc netcat; do
        pids=$(pgrep -x "$tool" 2>/dev/null)
        if [ -n "$pids" ]; then
            alert "TUNNELING TOOL RUNNING: $tool (PIDs: $pids)"
            ps aux | grep -w "$tool" | grep -v grep
            log_incident "TUNNEL TOOL DETECTED" "$tool running: PIDs $pids" ""
        fi
    done
}

# ============================================================
# CHECK 6: PROCESS BEHIND EACH CONNECTION
# For every established connection, show what process owns it
# Flags connections owned by shells or unexpected binaries
# ============================================================
check_connection_owners() {
    section "CONNECTION OWNER AUDIT"
    info "All established connections and their owning process:"

    SUSPICIOUS_PROCS=("bash" "sh" "dash" "zsh" "python" "python3" "perl" "ruby" "nc" "ncat" "netcat" "socat" "curl" "wget")

    ss -tnp state established 2>/dev/null | tail -n +2 | while read -r _state _recvq _sendq local foreign proc; do
        binary=$(echo "$proc" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
        pid=$(echo "$proc" | grep -oP 'pid=\K[0-9]+' | head -1)
        foreign_ip=$(echo "$foreign" | rev | cut -d: -f2- | rev)
        foreign_port=$(echo "$foreign" | rev | cut -d: -f1 | rev)

        # Flag shell or tool owning a network connection
        for sus in "${SUSPICIOUS_PROCS[@]}"; do
            if [[ "$binary" == "$sus" ]]; then
                alert "SUSPICIOUS BINARY HAS NETWORK CONNECTION: $binary (PID $pid) → $foreign_ip:$foreign_port"
                if [ -n "$pid" ]; then
                    info "Full command: $(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
                fi
                log_incident "SHELL/TOOL NETWORK CONNECTION" \
                    "$binary (PID $pid) connected to $foreign_ip:$foreign_port" "$foreign_ip"
            fi
        done

        echo "  $local → $foreign | $binary (PID: $pid)"
    done
}

# ============================================================
# CHECK 7: IPTABLES TRAFFIC COUNTERS
# Shows per-rule byte/packet counts — high numbers on unexpected
# rules indicate traffic you should know about
# ============================================================
check_iptables_counters() {
    section "IPTABLES TRAFFIC COUNTERS"
    info "Rules with significant traffic (>1000 packets):"

    iptables -L INPUT -n -v 2>/dev/null | awk 'NR>2 && $1+0 > 1000 {print}' | while read line; do
        warn "High traffic rule: $line"
    done

    echo ""
    info "Full INPUT chain with counters:"
    iptables -L INPUT -n -v 2>/dev/null

    echo ""
    info "Full OUTPUT chain with counters:"
    iptables -L OUTPUT -n -v 2>/dev/null
}

# ============================================================
# MAIN LOOP
# ============================================================
clear
echo -e "${BLU}"
echo "  ┌─────────────────────────────────────────┐"
echo "  │   ASTRA 9 PORT TRAFFIC MONITOR          │"
echo "  │   PCDC 2026 Blue Team                   │"
echo "  │   Interval: ${INTERVAL}s                        │"
echo "  └─────────────────────────────────────────┘"
echo -e "${NC}"
echo "  Host:     $(hostname)"
echo "  IP:       $(hostname -I | awk '{print $1}')"
echo "  Log:      $LOGFILE"
echo "  Incident: $INCIDENT_LOG"
echo ""
echo -e "${YLW}  Edit KNOWN_PORTS at top of script to match your scored services!${NC}"
echo ""

capture_baseline

echo ""
info "Starting port monitoring loop. Ctrl+C to stop."
echo ""

LOOP=0
while true; do
    LOOP=$((LOOP + 1))
    echo ""
    echo -e "${MAG}══ Cycle #$LOOP | $(date '+%H:%M:%S') ══${NC}"

    check_new_listeners
    check_port_binary_mismatch
    check_connection_volume
    check_foreign_ip_diversity
    check_tunneling
    check_connection_owners
    check_iptables_counters

    sleep "$INTERVAL"
done
