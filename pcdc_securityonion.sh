#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Security Onion Integration Bridge
#
#  Polls SO alerts, deploys custom detection rules,
#  and correlates host-based IOCs with network evidence.
#
#  Usage:
#    bash pcdc_securityonion.sh status   ← verify SO connectivity & auth
#    bash pcdc_securityonion.sh monitor  ← stream live alerts (30s poll)
#    bash pcdc_securityonion.sh rules    ← deploy 25 PCDC detection rules
#    bash pcdc_securityonion.sh hunt     ← correlate host IOC with network
#
#  Config (set before running):
#    export SO_HOST=10.0.1.x    # Security Onion IP
#    export SO_USER=analyst     # SO web UI username
#    export SO_PASS=yourpass    # SO web UI password
#
#  Requires: curl  (jq optional — improves alert parsing)
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
INCIDENT_LOG="$LOGDIR/so_incidents_${TIMESTAMP}.log"
RULES_FILE="/tmp/pcdc_local_${TIMESTAMP}.rules"
POLL_INTERVAL=30

mkdir -p "$LOGDIR"

# ── SO connection settings (override via env) ────────────────
SO_HOST="${SO_HOST:-}"
SO_USER="${SO_USER:-}"
SO_PASS="${SO_PASS:-}"
SO_API="https://${SO_HOST}:9200"
SO_INDEX="so-*"

ok()      { echo -e "${GRN}[OK]${NC}      $1"; }
warn()    { echo -e "${YLW}[WARN]${NC}    $1"; }
alert()   {
    echo -e "${RED}[ALERT]${NC}   $1"
    echo "[$(date '+%H:%M:%S')] ALERT: $1" >> "$INCIDENT_LOG"
}
info()    { echo -e "${CYN}[INFO]${NC}    $1"; }
so_high() {
    echo -e "${RED}[SO-HIGH]${NC}  $1"
    echo "[$(date '+%H:%M:%S')] SO-HIGH: $1" >> "$INCIDENT_LOG"
}
so_med()  { echo -e "${YLW}[SO-MED]${NC}   $1"; }
so_low()  { echo -e "${BLU}[SO-LOW]${NC}   $1"; }
section() { echo -e "\n${MAG}══════ $1 ══════${NC}"; }
header()  {
    clear
    echo -e "${CYN}╔════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYN}║    PCDC 2026 │ Security Onion Bridge               ║${NC}"
    echo -e "${CYN}╚════════════════════════════════════════════════════╝${NC}"
    echo ""
}

check_config() {
    local missing=0
    [ -z "$SO_HOST" ] && { warn "SO_HOST not set — export SO_HOST=10.0.x.x"; missing=1; }
    [ -z "$SO_USER" ] && { warn "SO_USER not set — export SO_USER=analyst";   missing=1; }
    [ -z "$SO_PASS" ] && { warn "SO_PASS not set — export SO_PASS=yourpass";  missing=1; }
    [ "$missing" -eq 1 ] && exit 1
    return 0
}

so_query() {
    local query="$1"
    curl -sk -u "${SO_USER}:${SO_PASS}" \
        -H "Content-Type: application/json" \
        -d "$query" \
        "${SO_API}/${SO_INDEX}/_search" 2>/dev/null
}

# Print one alert line; severity 1=high 2=med else low
print_alert() {
    local severity="$1"
    local sig="$2"
    local src="$3"
    local dst="$4"
    local ts
    ts=$(date '+%Y-%m-%dT%H:%M:%S')
    case "$severity" in
        1) so_high "${ts} | ${sig}"; echo -e "           ${src} → ${dst}" ;;
        2) so_med  "${ts} | ${sig}"; echo -e "           ${src} → ${dst}" ;;
        *) so_low  "${ts} | ${sig}"; echo -e "           ${src} → ${dst}" ;;
    esac
}

# Parse raw JSON blob for one Suricata alert event
parse_hit() {
    local raw="$1"
    local severity src_ip src_port dst_ip dst_port sig
    severity=$(echo "$raw" | grep -oP '"severity":\K[0-9]+' | head -1)
    sig=$(echo "$raw"      | grep -oP '"signature":"\K[^"]+' | head -1)
    src_ip=$(echo "$raw"   | grep -oP '"src_ip":"\K[^"]+' | head -1)
    src_port=$(echo "$raw" | grep -oP '"src_port":\K[0-9]+' | head -1)
    dst_ip=$(echo "$raw"   | grep -oP '"dest_ip":"\K[^"]+' | head -1)
    dst_port=$(echo "$raw" | grep -oP '"dest_port":\K[0-9]+' | head -1)
    [ -z "$sig" ] && return
    print_alert "${severity:-3}" "$sig" \
        "${src_ip:-?}:${src_port:-?}" "${dst_ip:-?}:${dst_port:-?}"
}

# ============================================================
# STATUS
# ============================================================
cmd_status() {
    header
    section "SECURITY ONION STATUS"
    check_config

    echo -e "${CYN}SO Instance:${NC} ${SO_HOST}"
    echo -e "${CYN}API URL:${NC}     ${SO_API}"
    echo ""

    info "Testing Elasticsearch connectivity..."
    local es_resp
    es_resp=$(curl -sk --max-time 5 -u "${SO_USER}:${SO_PASS}" "${SO_API}" 2>/dev/null)
    if echo "$es_resp" | grep -q '"tagline"'; then
        ok "Elasticsearch reachable and authenticated"
    else
        warn "Cannot reach Elasticsearch — trying SOC web UI..."
        if curl -sk --max-time 5 "https://${SO_HOST}/" 2>/dev/null | grep -qi "security.onion"; then
            ok "SO web UI reachable at https://${SO_HOST}/"
        else
            alert "Cannot reach Security Onion at ${SO_HOST}"
        fi
    fi

    info "Checking index access..."
    local count
    count=$(curl -sk -u "${SO_USER}:${SO_PASS}" \
        "${SO_API}/${SO_INDEX}/_count" 2>/dev/null \
        | grep -oP '"count":\K[0-9]+' | head -1)
    if [ -n "$count" ]; then
        ok "Index ${SO_INDEX} accessible — ${count} total documents"
    else
        warn "Could not query index ${SO_INDEX}"
    fi

    echo ""
    echo -e "${BLU}Quick links:${NC}"
    echo "  Alerts:     https://${SO_HOST}/app/alerts"
    echo "  Hunt:       https://${SO_HOST}/app/hunt"
    echo "  Dashboards: https://${SO_HOST}/app/dashboards"
    echo "  PCAP:       https://${SO_HOST}/app/pcap"
    echo ""
    info "Incident log: ${INCIDENT_LOG}"
}

# ============================================================
# MONITOR
# ============================================================
cmd_monitor() {
    header
    section "LIVE ALERT STREAM (${POLL_INTERVAL}s poll)"
    check_config

    echo -e "${YLW}Streaming alerts from ${SO_HOST} — Ctrl+C to stop${NC}"
    echo -e "${YLW}High alerts logged to: ${INCIDENT_LOG}${NC}"
    echo ""

    local last_ts
    last_ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

    while true; do
        local query
        query=$(printf '{
            "size": 50,
            "sort": [{"@timestamp":"desc"}],
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "alert.signature"}},
                        {"range": {"@timestamp": {"gte": "%s"}}}
                    ]
                }
            }
        }' "$last_ts")

        local response
        response=$(so_query "$query")

        if [ -z "$response" ] || echo "$response" | grep -q '"error"'; then
            warn "[$(date '+%H:%M:%S')] No response from SO — retrying in ${POLL_INTERVAL}s"
        else
            local new_events=0
            while IFS= read -r hit; do
                [ -n "$hit" ] && parse_hit "$hit" && new_events=$((new_events + 1))
            done < <(echo "$response" | grep -oP '"_source":\{[^}]*\}')

            if [ "$new_events" -eq 0 ]; then
                echo -e "${GRN}[$(date '+%H:%M:%S')]${NC} No new alerts"
            fi
            last_ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
        fi

        sleep "$POLL_INTERVAL"
    done
}

# ============================================================
# RULES
# ============================================================
cmd_rules() {
    header
    section "PCDC CUSTOM DETECTION RULES"
    check_config

    info "Writing 25 PCDC-tuned Suricata/Snort3 rules to ${RULES_FILE}..."

    cat > "$RULES_FILE" << 'RULES_EOF'
# PCDC 2026 - ASTRA 9 Custom Detection Rules
# Generated by pcdc_securityonion.sh

# --- Reverse Shells over Common Ports ---
alert tcp any any -> $HOME_NET 80 (msg:"PCDC Reverse Shell over HTTP Port"; flow:established,to_server; content:"/bin/sh"; nocase; sid:9000001; rev:1;)
alert tcp any any -> $HOME_NET 443 (msg:"PCDC Reverse Shell over HTTPS Port"; flow:established,to_server; content:"/bin/bash"; nocase; sid:9000002; rev:1;)
alert tcp any any -> $HOME_NET 8080 (msg:"PCDC Reverse Shell over Alt-HTTP"; flow:established,to_server; content:"/bin/sh"; nocase; sid:9000003; rev:1;)
alert tcp $HOME_NET any -> any any (msg:"PCDC Outbound Bash Reverse Shell"; flow:established,to_client; content:"bash -i"; nocase; sid:9000004; rev:1;)

# --- PHP Webshell POST Patterns ---
alert http any any -> $HTTP_SERVERS any (msg:"PCDC PHP Webshell POST cmd param"; flow:established,to_server; http.method; content:"POST"; http.uri; content:".php"; content:"cmd="; nocase; sid:9000005; rev:1;)
alert http any any -> $HTTP_SERVERS any (msg:"PCDC PHP Webshell system() call"; flow:established,to_server; http.client_body; content:"system("; nocase; sid:9000006; rev:1;)
alert http any any -> $HTTP_SERVERS any (msg:"PCDC PHP Webshell exec upload"; flow:established,to_server; http.client_body; content:"passthru("; nocase; sid:9000007; rev:1;)
alert http any any -> $HTTP_SERVERS any (msg:"PCDC Path Traversal Attempt"; flow:established,to_server; http.uri; content:"../"; content:"etc/passwd"; sid:9000008; rev:1;)

# --- SSH Brute Force ---
alert tcp any any -> $HOME_NET 22 (msg:"PCDC SSH Brute Force Detected"; flow:to_server,established; threshold:type threshold,track by_src,count 5,seconds 30; sid:9000009; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"PCDC SSH Port Scan to Multiple Hosts"; flow:to_server; threshold:type threshold,track by_src,count 10,seconds 10; sid:9000010; rev:1;)

# --- DNS Tunneling ---
alert udp any any -> any 53 (msg:"PCDC DNS Tunneling - Large Query"; dsize:>100; sid:9000011; rev:1;)
alert udp any any -> any 53 (msg:"PCDC DNS High-Frequency Query"; threshold:type threshold,track by_src,count 50,seconds 10; sid:9000012; rev:1;)
alert tcp any any -> any 53 (msg:"PCDC DNS over TCP Exfil"; flow:established,to_server; dsize:>200; sid:9000013; rev:1;)

# --- Oversized ICMP / Tunneling ---
alert icmp any any -> $HOME_NET any (msg:"PCDC Oversized ICMP (possible tunnel)"; itype:8; dsize:>1000; sid:9000014; rev:1;)
alert icmp any any -> any any (msg:"PCDC ICMP Flood"; threshold:type threshold,track by_src,count 100,seconds 10; sid:9000015; rev:1;)

# --- RDP & DB Brute Force ---
alert tcp any any -> $HOME_NET 3389 (msg:"PCDC RDP Brute Force"; flow:to_server; threshold:type threshold,track by_src,count 5,seconds 30; sid:9000016; rev:1;)
alert tcp any any -> $HOME_NET 3306 (msg:"PCDC MySQL Brute Force"; flow:to_server; threshold:type threshold,track by_src,count 5,seconds 30; sid:9000017; rev:1;)

# --- Port Scan Detection ---
alert tcp any any -> $HOME_NET any (msg:"PCDC TCP Port Scan"; flags:S; threshold:type threshold,track by_src,count 20,seconds 5; sid:9000018; rev:1;)
alert udp any any -> $HOME_NET any (msg:"PCDC UDP Port Scan"; threshold:type threshold,track by_src,count 20,seconds 5; sid:9000019; rev:1;)

# --- Lateral Movement ---
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"PCDC SMB Lateral Movement"; flow:established,to_server; content:"|FF|SMB"; sid:9000020; rev:1;)
alert tcp $HOME_NET any -> $HOME_NET 135 (msg:"PCDC RPC Lateral Movement"; flow:established,to_server; sid:9000021; rev:1;)

# --- Data Exfiltration ---
alert tcp $HOME_NET any -> !$HOME_NET any (msg:"PCDC Large Outbound Transfer (exfil)"; flow:established,to_server; dsize:>60000; threshold:type threshold,track by_src,count 3,seconds 60; sid:9000022; rev:1;)

# --- Netcat / Credential Harvest / Scanner UA ---
alert tcp any any -> $HOME_NET any (msg:"PCDC Netcat Connection Attempt"; flow:established; content:"Ncat:"; sid:9000023; rev:1;)
alert http any any -> $HTTP_SERVERS any (msg:"PCDC POST Credential Harvest"; flow:established,to_server; http.client_body; content:"password="; nocase; dsize:>500; sid:9000024; rev:1;)
alert http any any -> $HTTP_SERVERS any (msg:"PCDC SQLMap Scanner UA"; flow:established,to_server; http.user_agent; content:"sqlmap"; nocase; sid:9000025; rev:1;)
RULES_EOF

    local rule_count
    rule_count=$(grep -c "^alert" "$RULES_FILE")
    ok "Generated ${rule_count} rules → ${RULES_FILE}"
    echo ""
    echo -e "${CYN}Categories covered:${NC}"
    echo "  • Reverse shell (ports 80/443/8080, outbound bash)"
    echo "  • PHP webshell POST patterns + path traversal"
    echo "  • SSH/RDP/MySQL brute force thresholds"
    echo "  • DNS tunneling (large queries, high freq, DNS-over-TCP)"
    echo "  • Oversized ICMP + ICMP flood"
    echo "  • TCP/UDP port scan detection"
    echo "  • SMB/RPC lateral movement"
    echo "  • Large outbound transfer (exfil)"
    echo "  • Netcat, credential harvest, sqlmap UA"
    echo ""

    info "Deploying to Security Onion via SSH..."
    if ssh -n -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
           "${SO_USER}@${SO_HOST}" "test -d /opt/so/rules" 2>/dev/null; then
        scp -q "$RULES_FILE" \
            "${SO_USER}@${SO_HOST}:/opt/so/rules/pcdc_local.rules" 2>/dev/null
        ssh -n -o StrictHostKeyChecking=no "${SO_USER}@${SO_HOST}" \
            "sudo so-rule reload 2>/dev/null || sudo systemctl reload suricata 2>/dev/null" \
            2>/dev/null
        ok "Rules deployed and detection engine reloaded"
    else
        warn "SSH to SO unavailable — manual deployment:"
        echo "  scp ${RULES_FILE} ${SO_HOST}:/opt/so/rules/pcdc_local.rules"
        echo "  ssh ${SO_HOST} 'sudo so-rule reload'"
    fi
}

# ============================================================
# HUNT
# ============================================================
cmd_hunt() {
    header
    section "IOC HUNT — Correlate Host Artifact with Network Evidence"
    check_config

    echo -e "${YLW}What IOC did you find in your host-based alert?${NC}"
    echo "  1) Suspicious IP address"
    echo "  2) Suspicious port number"
    echo "  3) Alert signature keyword"
    echo ""
    read -rp "Choice [1-3]: " choice

    local value query
    case "$choice" in
        1)
            read -rp "IP address: " value
            query=$(printf '{
                "size":20,"sort":[{"@timestamp":"desc"}],
                "query":{"bool":{"should":[
                    {"term":{"src_ip":"%s"}},
                    {"term":{"dest_ip":"%s"}}
                ]}}
            }' "$value" "$value")
            ;;
        2)
            read -rp "Port number: " value
            query=$(printf '{
                "size":20,"sort":[{"@timestamp":"desc"}],
                "query":{"bool":{"should":[
                    {"term":{"src_port":%s}},
                    {"term":{"dest_port":%s}}
                ]}}
            }' "$value" "$value")
            ;;
        3)
            read -rp "Signature keyword: " value
            query=$(printf '{
                "size":20,"sort":[{"@timestamp":"desc"}],
                "query":{"match":{"alert.signature":"%s"}}
            }' "$value")
            ;;
        *)
            warn "Invalid choice"
            return 1
            ;;
    esac

    info "Querying Security Onion for: ${value} ..."
    echo ""

    local response
    response=$(so_query "$query")

    if [ -z "$response" ] || echo "$response" | grep -q '"error"'; then
        warn "No response or query error from SO"
        return 1
    fi

    local total
    total=$(echo "$response" | grep -oP '"value":\K[0-9]+' | head -1)
    echo -e "${CYN}Found ${total:-0} matching events (showing latest 20)${NC}"
    echo ""

    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        local sig src_ip src_port dst_ip dst_port
        sig=$(echo "$hit"      | grep -oP '"signature":"\K[^"]+' | head -1)
        src_ip=$(echo "$hit"   | grep -oP '"src_ip":"\K[^"]+' | head -1)
        src_port=$(echo "$hit" | grep -oP '"src_port":\K[0-9]+' | head -1)
        dst_ip=$(echo "$hit"   | grep -oP '"dest_ip":"\K[^"]+' | head -1)
        dst_port=$(echo "$hit" | grep -oP '"dest_port":\K[0-9]+' | head -1)
        [ -z "$sig" ] && sig="(network event)"
        echo -e "  ${YLW}${sig}${NC}"
        echo -e "  ${src_ip:-?}:${src_port:-?} → ${dst_ip:-?}:${dst_port:-?}"
        echo ""
    done < <(echo "$response" | grep -oP '"_source":\{[^}]*\}')

    echo ""
    info "Full hunt: https://${SO_HOST}/app/hunt?q=${value}"
}

# ============================================================
# DISPATCH
# ============================================================
case "${1:-}" in
    status)  cmd_status  ;;
    monitor) cmd_monitor ;;
    rules)   cmd_rules   ;;
    hunt)    cmd_hunt    ;;
    *)
        echo -e "${CYN}pcdc_securityonion.sh${NC} — Security Onion Integration Bridge"
        echo ""
        echo "  bash pcdc_securityonion.sh status   — verify SO connectivity & auth"
        echo "  bash pcdc_securityonion.sh monitor  — stream live alerts (${POLL_INTERVAL}s poll)"
        echo "  bash pcdc_securityonion.sh rules    — deploy 25 custom PCDC detection rules"
        echo "  bash pcdc_securityonion.sh hunt     — correlate host IOC with network evidence"
        echo ""
        echo "  Required env vars:"
        echo "    export SO_HOST=10.0.1.x    # Security Onion IP"
        echo "    export SO_USER=analyst     # SO web UI username"
        echo "    export SO_PASS=yourpass    # SO web UI password"
        ;;
esac
