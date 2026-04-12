#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Network Enumeration & Asset Discovery
#
#  PURPOSE — DEFENSIVE MAPPING:
#  You cannot defend what you don't know exists.
#  This script maps YOUR network from YOUR machines so you
#  have a complete picture of the environment BEFORE the
#  Red Team finishes doing the same thing offensively.
#
#  The goal is to answer:
#  - What machines are on this network?
#  - What services are running on each?
#  - What OS are they running?
#  - Which ones are unaccounted for in your Blue Team Packet?
#  - Which ones look like scoring engine / Gold Team infrastructure?
#  - Which ones have services that shouldn't be exposed?
#
#  Run this FIRST during your golden window, BEFORE hardening.
#  Then run it again periodically to detect new hosts appearing
#  (Red Team pivot boxes, rogue VMs, etc.)
#
#  Requires: nmap (most likely available or installable)
#  Run as root for best results (enables OS detection, SYN scan)
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
LOGFILE="$LOGDIR/network_map_$TIMESTAMP.log"
STATE_DIR="$LOGDIR/netstate"

mkdir -p "$LOGDIR" "$STATE_DIR"
exec > >(tee -a "$LOGFILE") 2>&1

# ============================================================
# COMPETITION CONFIG (load if available — sets OOB trust rules)
# ============================================================
is_trusted_infrastructure() { return 1; }           # stub — overridden by config
infra_note() { echo -e "${CYN}[INFO]${NC}     [INFRA] $1"; }
OOB_PREFIX="${OOB_PREFIX:-192.168.40}"
SCORING_ENGINE_IP="${SCORING_ENGINE_IP:-192.168.20.10}"

_CONF_FILE="$(dirname "$(readlink -f "$0")")/pcdc_competition_config.sh"
# shellcheck source=pcdc_competition_config.sh
[ -f "$_CONF_FILE" ] && source "$_CONF_FILE"
unset _CONF_FILE

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

if [[ $EUID -ne 0 ]]; then
    echo -e "${YLW}Warning: Running without root. OS detection and SYN scan unavailable.${NC}"
    echo -e "${YLW}Re-run with sudo for full results.${NC}"
    echo ""
fi

# ============================================================
# STEP 0: UNDERSTAND YOUR OWN INTERFACES FIRST
# Before scanning anything, know what YOU look like on the network
# ============================================================
section "STEP 0: LOCAL INTERFACE & ROUTING AUDIT"

info "Your network interfaces:"
ip addr show 2>/dev/null | grep -E "^[0-9]+:|inet " | while read line; do
    echo "  $line"
done

echo ""
info "Your routing table (what networks can you reach directly?):"
ip route 2>/dev/null

echo ""
info "Your ARP cache (hosts you've recently talked to):"
arp -n 2>/dev/null || ip neigh 2>/dev/null

echo ""
# Determine local subnets from interfaces
LOCAL_SUBNETS=()
while read iface addr prefix; do
    if [[ "$addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        # Calculate network address from IP and prefix
        subnet="${addr%.*}.0/$prefix"
        LOCAL_SUBNETS+=("$addr/$prefix")
        info "Detected local network: $subnet (interface: $iface)"
    fi
done < <(ip addr show 2>/dev/null | awk '/inet / {split($2,a,"/"); print $NF, a[1], a[2]}' | grep -v "^lo\|127\.")

echo ""
MY_IP=$(hostname -I | awk '{print $1}')
info "Primary IP: $MY_IP"
info "Hostname: $(hostname)"

# ============================================================
# STEP 1: FAST HOST DISCOVERY
# Find all live hosts on the network quickly
# Don't do a full port scan first — find who's alive, then go deeper
# ============================================================
section "STEP 1: HOST DISCOVERY (Fast Ping Sweep)"

# Check for nmap
if ! command -v nmap &>/dev/null; then
    warn "nmap not found. Attempting to install..."
    apt-get install -y nmap 2>/dev/null || yum install -y nmap 2>/dev/null
    if ! command -v nmap &>/dev/null; then
        warn "nmap unavailable. Falling back to manual ping sweep."
        NMAP_AVAILABLE=false
    else
        NMAP_AVAILABLE=true
    fi
else
    NMAP_AVAILABLE=true
    info "nmap version: $(nmap --version | head -1)"
fi

# Determine target subnet
# Try to get it from your Blue Team Packet — if not, derive from your interface
echo ""
echo -e "${YLW}What subnet should we scan?${NC}"
echo "  Your detected subnets:"
ip route 2>/dev/null | grep -v "default\|kernel" | while read line; do
    echo "    $line"
done
echo ""
read -rp "Enter target subnet (e.g., 10.0.0.0/24) or press Enter to auto-detect: " TARGET_SUBNET

if [ -z "$TARGET_SUBNET" ]; then
    # Auto-detect from default route interface
    DEFAULT_IF=$(ip route 2>/dev/null | grep "^default" | awk '{print $5}' | head -1)
    TARGET_SUBNET=$(ip addr show "$DEFAULT_IF" 2>/dev/null | \
        awk '/inet / {print $2}' | head -1)
    info "Auto-detected: $TARGET_SUBNET"
fi

# Save for repeated use
echo "$TARGET_SUBNET" > "$STATE_DIR/target_subnet"

echo ""
info "Running fast host discovery on $TARGET_SUBNET..."
info "This finds live hosts only — no port scanning yet."
echo ""

LIVE_HOSTS_FILE="$STATE_DIR/live_hosts_$TIMESTAMP.txt"

if $NMAP_AVAILABLE; then
    # -sn = ping scan only (no port scan)
    # -PE = ICMP echo, -PP = ICMP timestamp, -PM = ICMP netmask
    # -PS22,80,443 = TCP SYN to common ports (in case ICMP is blocked)
    # --min-hostgroup 64 = scan in parallel groups
    nmap -sn -PE -PP -PS22,80,443,3306,8080 \
         --min-hostgroup 64 \
         --min-parallelism 64 \
         -oN "$LIVE_HOSTS_FILE" \
         "$TARGET_SUBNET" 2>/dev/null

    # Extract just the IPs
    grep "Nmap scan report" "$LIVE_HOSTS_FILE" | \
        grep -oP '\d+\.\d+\.\d+\.\d+' > "$STATE_DIR/live_ips_$TIMESTAMP.txt"

    HOST_COUNT=$(wc -l < "$STATE_DIR/live_ips_$TIMESTAMP.txt")
    ok "Found $HOST_COUNT live hosts"
    echo ""
    cat "$STATE_DIR/live_ips_$TIMESTAMP.txt"
else
    # Manual ping sweep fallback
    SUBNET_BASE=$(echo "$TARGET_SUBNET" | cut -d'/' -f1 | cut -d'.' -f1-3)
    info "Manual ping sweep of $SUBNET_BASE.0/24..."
    : > "$STATE_DIR/live_ips_$TIMESTAMP.txt"
    for i in $(seq 1 254); do
        ip="$SUBNET_BASE.$i"
        if ping -c 1 -W 1 "$ip" &>/dev/null 2>&1; then
            echo "$ip" | tee -a "$STATE_DIR/live_ips_$TIMESTAMP.txt"
        fi
    done
fi

# Save as baseline for later comparison
cp "$STATE_DIR/live_ips_$TIMESTAMP.txt" "$STATE_DIR/live_ips.baseline" 2>/dev/null

# ============================================================
# STEP 2: COMPARE TO BLUE TEAM PACKET
# The packet will list your machines. Anything else is either
# Gold Team/scoring infrastructure, or it's unexpected.
# ============================================================
section "STEP 2: HOST ACCOUNTING vs BLUE TEAM PACKET"

# Pre-populate with known competition infrastructure from config.
# These are always present and must not be flagged as unexpected.
KNOWN_HOSTS=()
if [ -n "${COMP_TRUSTED_HOSTS[*]:-}" ]; then
    for _th in "${COMP_TRUSTED_HOSTS[@]}"; do
        KNOWN_HOSTS+=("$_th")
    done
    infra_note "Pre-loaded ${#COMP_TRUSTED_HOSTS[@]} trusted host(s) from competition config."
fi

echo -e "${YLW}Enter IP addresses listed in your Blue Team Packet (your own machines).${NC}"
echo -e "${YLW}One per line. Empty line when done.${NC}"
[ -n "$OOB_NETWORK" ] && \
    echo -e "${CYN}Note: OOB network $OOB_NETWORK is auto-trusted — do not re-enter those IPs.${NC}"
echo ""

while true; do
    read -rp "  Known host IP (or Enter to finish): " host
    [ -z "$host" ] && break
    KNOWN_HOSTS+=("$host")
done

# Also always exclude yourself
KNOWN_HOSTS+=("$MY_IP")

echo ""
info "Accounting for discovered hosts..."

UNKNOWN_COUNT=0
while read discovered_ip; do
    is_known=false
    for known in "${KNOWN_HOSTS[@]}"; do
        if [ "$discovered_ip" = "$known" ]; then
            is_known=true
            break
        fi
    done

    if $is_known; then
        ok "ACCOUNTED FOR: $discovered_ip"
    elif is_trusted_infrastructure "$discovered_ip"; then
        infra_note "COMPETITION INFRASTRUCTURE: $discovered_ip (OOB/scoring — expected, do not block)"
    else
        warn "UNACCOUNTED HOST: $discovered_ip — not in your Blue Team Packet"
        warn "  Could be: Gold Team scoring engine, White Team, other Blue Teams,"
        warn "  competition infrastructure, OR something that shouldn't be here."
        warn "  DO NOT scan aggressively — competition rules prohibit scanning other teams."
        UNKNOWN_COUNT=$((UNKNOWN_COUNT + 1))
    fi
done < "$STATE_DIR/live_ips_$TIMESTAMP.txt"

echo ""
if [ "$UNKNOWN_COUNT" -gt 0 ]; then
    warn "$UNKNOWN_COUNT unaccounted hosts found."
    warn "Ask your White Team liaison what infrastructure belongs to competition officials."
    warn "Do NOT port-scan hosts you don't own — this will get you disqualified."
else
    ok "All discovered hosts accounted for."
fi

# ============================================================
# STEP 3: DETAILED SCAN OF YOUR OWN HOSTS
# Now do a proper port/service/OS scan — but ONLY on machines
# listed in your Blue Team Packet.
# Rules are clear: only scan your own systems.
# ============================================================
section "STEP 3: DETAILED SERVICE SCAN — YOUR MACHINES ONLY"

echo -e "${YLW}Which of your own hosts should we do a detailed scan on?${NC}"
echo -e "${YLW}(Enter IPs from your Blue Team Packet — your machines only)${NC}"
echo ""

YOUR_HOSTS=()
for known in "${KNOWN_HOSTS[@]}"; do
    [ "$known" = "$MY_IP" ] && continue
    if is_trusted_infrastructure "$known"; then
        infra_note "Skipping trusted infrastructure in detailed scan selection: $known"
        continue
    fi
    read -rp "  Include $known in detailed scan? [y/N]: " ans
    [[ "$ans" =~ ^[Yy]$ ]] && YOUR_HOSTS+=("$known")
done

# Always include yourself
YOUR_HOSTS+=("$MY_IP")

echo ""
info "Scanning ${#YOUR_HOSTS[@]} hosts in detail..."

FULL_SCAN_FILE="$STATE_DIR/full_scan_$TIMESTAMP.txt"
: > "$FULL_SCAN_FILE"

for target_ip in "${YOUR_HOSTS[@]}"; do
    echo ""
    section "Detailed Scan: $target_ip"

    if $NMAP_AVAILABLE; then
        if [[ $EUID -eq 0 ]]; then
            # Full scan with root: SYN scan + OS detection + version detection + scripts
            info "Running full scan (SYN + OS + version + common scripts)..."
            nmap -sS -sV -O \
                 --script="banner,http-title,http-server-header,ssh-hostkey,ftp-anon,smtp-open-relay,mysql-empty-password,mysql-info" \
                 -p- \
                 --min-rate 1000 \
                 --max-retries 2 \
                 -T4 \
                 "$target_ip" \
                 -oN "$STATE_DIR/scan_${target_ip//./_}_$TIMESTAMP.txt" \
                 2>/dev/null | tee -a "$FULL_SCAN_FILE"
        else
            # Without root: TCP connect scan (slower but no root needed)
            info "Running connect scan (no root — OS detection unavailable)..."
            nmap -sT -sV \
                 --script="banner,http-title,smtp-open-relay,ftp-anon" \
                 -p 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443 \
                 --min-rate 500 \
                 "$target_ip" \
                 -oN "$STATE_DIR/scan_${target_ip//./_}_$TIMESTAMP.txt" \
                 2>/dev/null | tee -a "$FULL_SCAN_FILE"
        fi
    else
        # Manual port check without nmap
        info "Manual port scan (nmap unavailable)..."
        COMMON_PORTS=(21 22 23 25 53 80 110 143 443 445 3306 3389 5432 8080 8443)
        for port in "${COMMON_PORTS[@]}"; do
            if timeout 2 bash -c "echo >/dev/tcp/$target_ip/$port" 2>/dev/null; then
                ok "Port $port OPEN on $target_ip"
            fi
        done
    fi
done

# ============================================================
# STEP 4: PARSE RESULTS AND FLAG SECURITY ISSUES
# ============================================================
section "STEP 4: SECURITY ANALYSIS OF SCAN RESULTS"

info "Analyzing scan results for security issues..."
echo ""

# Parse nmap output files for each host
for scan_file in "$STATE_DIR"/scan_*_"$TIMESTAMP".txt; do
    [ ! -f "$scan_file" ] && continue
    host_ip=$(echo "$scan_file" | grep -oP '\d+_\d+_\d+_\d+' | tr '_' '.')
    echo ""
    echo -e "${MAG}── Analysis: $host_ip ──${NC}"

    # Flag dangerous open ports
    while read line; do
        port=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
        state=$(echo "$line" | awk '{print $2}')
        service=$(echo "$line" | awk '{print $3}')
        _version=$(echo "$line" | cut -d' ' -f4-)

        [ "$state" != "open" ] && continue

        case "$port" in
            23)
                alert "TELNET open on $host_ip:$port — plaintext protocol, disable immediately"
                ;;
            21)
                warn "FTP open on $host_ip:$port — check if anonymous login is enabled"
                # Check for anonymous FTP in nmap scripts
                if grep -q "Anonymous FTP login allowed" "$scan_file" 2>/dev/null; then
                    alert "ANONYMOUS FTP LOGIN ALLOWED on $host_ip — anyone can connect"
                fi
                ;;
            3306)
                warn "MySQL exposed on $host_ip:$port — should only be on localhost"
                if grep -q "mysql-empty-password" "$scan_file" 2>/dev/null; then
                    alert "MYSQL EMPTY/NO PASSWORD on $host_ip — critical vulnerability"
                fi
                ;;
            5432)
                warn "PostgreSQL exposed on $host_ip:$port — verify access controls"
                ;;
            3389)
                warn "RDP open on $host_ip:$port — ensure strong auth, NLA enabled"
                ;;
            445|139)
                warn "SMB open on $host_ip:$port — check for null sessions and shares"
                ;;
            25)
                info "SMTP open on $host_ip:$port — check for open relay"
                if grep -q "open-relay\|OPEN RELAY" "$scan_file" 2>/dev/null; then
                    alert "OPEN SMTP RELAY on $host_ip — red team can spam through you"
                fi
                ;;
            111|2049)
                alert "NFS/RPC open on $host_ip:$port — likely unintended exposure"
                ;;
            6379)
                alert "Redis exposed on $host_ip:$port — often has no auth by default"
                ;;
            27017)
                alert "MongoDB exposed on $host_ip:$port — older versions have no auth"
                ;;
            8080|8443|8888|9000|9090)
                warn "Alternative web port open on $host_ip:$port — check what's running"
                ;;
            4444|1234|5555|6666|7777|31337)
                alert "SUSPICIOUS PORT on $host_ip:$port — classic backdoor/shell port"
                ;;
            *)
                info "Port $port/$service open on $host_ip"
                ;;
        esac
    done < <(grep "^[0-9]" "$scan_file" 2>/dev/null)

    # Extract and show OS detection
    os_guess=$(grep "OS details\|Running:" "$scan_file" 2>/dev/null | head -3)
    [ -n "$os_guess" ] && info "OS: $os_guess"

    # Extract HTTP titles (tells you what web app is running)
    http_titles=$(grep "http-title\|http-server-header" "$scan_file" 2>/dev/null)
    [ -n "$http_titles" ] && info "Web info: $http_titles"

    # Extract SSH host keys (document these for verification)
    ssh_keys=$(grep "ssh-hostkey" -A 5 "$scan_file" 2>/dev/null | head -10)
    [ -n "$ssh_keys" ] && info "SSH keys: document these for later verification"
done

# ============================================================
# STEP 5: NETWORK MAP SUMMARY
# Produce a human-readable map of your environment
# ============================================================
section "STEP 5: NETWORK MAP SUMMARY"

MAP_FILE="$LOGDIR/network_map_summary_$TIMESTAMP.txt"

cat > "$MAP_FILE" << EOF
============================================================
ASTRA 9 BLUE TEAM — NETWORK MAP
Generated: $(date)
Scanner: $(hostname) [$MY_IP]
Target subnet: $TARGET_SUBNET
============================================================

LIVE HOSTS ($(wc -l < "$STATE_DIR/live_ips_$TIMESTAMP.txt" 2>/dev/null) total):
$(cat "$STATE_DIR/live_ips_$TIMESTAMP.txt" 2>/dev/null)

YOUR MACHINES (from Blue Team Packet):
$(for h in "${KNOWN_HOSTS[@]}"; do echo "  $h"; done)

DETAILED SCAN RESULTS:
EOF

for scan_file in "$STATE_DIR"/scan_*_"$TIMESTAMP".txt; do
    [ ! -f "$scan_file" ] && continue
    host_ip=$(echo "$scan_file" | grep -oP '\d+_\d+_\d+_\d+' | tr '_' '.')
    echo "" >> "$MAP_FILE"
    echo "── $host_ip ──" >> "$MAP_FILE"
    grep "^[0-9].*open" "$scan_file" 2>/dev/null >> "$MAP_FILE"
    grep "OS details\|Running:" "$scan_file" 2>/dev/null >> "$MAP_FILE"
    grep "http-title" "$scan_file" 2>/dev/null >> "$MAP_FILE"
done

cat "$MAP_FILE"

ok "Network map saved to: $MAP_FILE"

# ============================================================
# STEP 6: NEW HOST DETECTION (run periodically after baseline)
# ============================================================
section "STEP 6: NEW HOST DETECTION vs BASELINE"

if [ -f "$STATE_DIR/live_ips.baseline" ]; then
    info "Comparing current host list to baseline..."

    # Quick re-scan for live hosts
    CURRENT_IPS="$STATE_DIR/live_ips_current.txt"
    if $NMAP_AVAILABLE; then
        nmap -sn -PE -PS22,80,443 \
             --min-hostgroup 64 \
             --min-parallelism 64 \
             "$TARGET_SUBNET" 2>/dev/null | \
             grep "Nmap scan report" | \
             grep -oP '\d+\.\d+\.\d+\.\d+' > "$CURRENT_IPS"
    fi

    new_hosts=$(comm -13 \
        <(sort "$STATE_DIR/live_ips.baseline") \
        <(sort "$CURRENT_IPS" 2>/dev/null))

    gone_hosts=$(comm -23 \
        <(sort "$STATE_DIR/live_ips.baseline") \
        <(sort "$CURRENT_IPS" 2>/dev/null))

    if [ -n "$new_hosts" ]; then
        alert "NEW HOSTS APPEARED since baseline:"
        echo "$new_hosts" | while read -r ip; do
            if is_trusted_infrastructure "$ip"; then
                infra_note "  $ip — trusted OOB/scoring infrastructure"
            else
                alert "  $ip — investigate immediately"
            fi
        done
    else
        ok "No new hosts appeared"
    fi

    if [ -n "$gone_hosts" ]; then
        warn "Hosts that disappeared since baseline:"
        echo "$gone_hosts" | while read ip; do
            warn "  $ip — may be down or reconfigured"
        done
    fi
fi

# ============================================================
# STEP 7: INTERNAL SERVICE EXPOSURE REVIEW
# Which of your services are exposed to the whole network
# vs only where they need to be
# ============================================================
section "STEP 7: SERVICE EXPOSURE REVIEW (THIS HOST)"

info "Services listening on ALL interfaces (0.0.0.0 or *) — visible to whole network:"
ss -tulnp 2>/dev/null | grep -E "0\.0\.0\.0|\*|\[::\]" | while read line; do
    port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
    proto=$(echo "$line" | awk '{print $1}')
    binary=$(echo "$line" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
    echo "  :$port ($proto) → $binary"

    # Flag services that should be localhost-only
    case "$port" in
        3306) warn "    MySQL exposed to network — should be 127.0.0.1 only" ;;
        5432) warn "    PostgreSQL exposed to network — should be 127.0.0.1 only" ;;
        6379) alert "    Redis exposed to network — likely no auth" ;;
        11211) alert "    Memcached exposed to network — no auth, can be abused" ;;
        27017) alert "    MongoDB exposed to network — check auth" ;;
    esac
done

echo ""
info "Services listening on localhost ONLY (127.0.0.1) — not network-accessible:"
ss -tulnp 2>/dev/null | grep "127\.0\.0\.1" | while read line; do
    port=$(echo "$line" | awk '{print $5}' | rev | cut -d: -f1 | rev)
    binary=$(echo "$line" | grep -oP '"[^"]*"' | head -1 | tr -d '"')
    ok "  :$port → $binary (localhost only — good)"
done

# ============================================================
# DONE
# ============================================================
section "ENUMERATION COMPLETE"

echo -e "${GRN}Network map: $MAP_FILE${NC}"
echo -e "${GRN}Full log:    $LOGFILE${NC}"
echo -e "${GRN}Scan files:  $STATE_DIR/scan_*.txt${NC}"
echo ""
echo -e "${YLW}IMPORTANT COMPETITION REMINDERS:${NC}"
echo "  ✓ Only scan systems listed in YOUR Blue Team Packet"
echo "  ✓ Do not port scan unknown hosts — ask White Team what they are"
echo "  ✓ Do not scan other Blue Teams — immediate disqualification"
echo "  ✓ Share your network map with your whole team immediately"
echo "  ✓ Keep the map file — it becomes your incident response reference"
echo ""
echo -e "${YLW}NEXT STEPS:${NC}"
echo "  1. Review every open port against what your packet says should be there"
echo "  2. Close or restrict anything not in scope"
echo "  3. Pass the network map to your hardening team"
echo "  4. Set a reminder to re-run Step 6 (new host detection) every 30 minutes"
echo ""
