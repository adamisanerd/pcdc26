#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Container Entrypoint
#
#  Runs every time the container starts.
#  Handles first-run setup automatically.
# ============================================================

BLU='\033[0;34m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
NC='\033[0m'

# ── Banner ────────────────────────────────────────────────────
clear
echo -e "${BLU}"
cat << 'BANNER'
    ██████╗ ██╗     ██╗   ██╗███████╗    ████████╗███████╗ █████╗ ███╗   ███╗
    ██╔══██╗██║     ██║   ██║██╔════╝    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
    ██████╔╝██║     ██║   ██║█████╗         ██║   █████╗  ███████║██╔████╔██║
    ██╔══██╗██║     ██║   ██║██╔══╝         ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
    ██████╔╝███████╗╚██████╔╝███████╗       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
    ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝       ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝

                     Astra 9 Cyber Defense Division
                     PCDC 2026 | Blue Team Admin Container
BANNER
echo -e "${NC}"

echo -e "  Container started: $(date)"
echo -e "  Scripts:    /opt/blueTeam/scripts/"
echo -e "  Keys:       /opt/blueTeam/keys/"
echo -e "  Logs:       /opt/blueTeam/logs/"
echo ""

# ── SSH Key Generation (first run only) ──────────────────────
KEY_PATH="/opt/blueTeam/keys/pcdc_admin"

if [ ! -f "$KEY_PATH" ]; then
    echo -e "${YLW}[SETUP]${NC} Generating competition SSH key pair..."
    ssh-keygen -t ed25519 \
               -f "$KEY_PATH" \
               -C "pcdc2026_blueteam_admin_$(hostname)" \
               -N "" 2>/dev/null
    chmod 600 "$KEY_PATH"
    chmod 644 "${KEY_PATH}.pub"
    echo -e "${GRN}[OK]${NC}    Key generated: $KEY_PATH"
    echo ""
    echo -e "${YLW}  Your public key (copy to target machines):${NC}"
    cat "${KEY_PATH}.pub"
    echo ""
else
    echo -e "${GRN}[OK]${NC}    SSH key found: $KEY_PATH"
fi

# ── Symlink key into root's SSH dir ──────────────────────────
ln -sf "$KEY_PATH" /root/.ssh/pcdc_admin 2>/dev/null
ln -sf "${KEY_PATH}.pub" /root/.ssh/pcdc_admin.pub 2>/dev/null

# ── Hosts file check ─────────────────────────────────────────
HOSTS_FILE="/opt/blueTeam/hosts.txt"
if [ ! -f "$HOSTS_FILE" ]; then
    cat > "$HOSTS_FILE" << 'EOF'
# PCDC 2026 Blue Team Fleet
# Format: user@ip   # optional label
# Example:
#   root@10.0.1.10   # web server
#   root@10.0.1.11   # mail server
#
# Add hosts with: bt_add_host root@10.0.1.10 "web server"
# Or edit this file directly
EOF
    echo -e "${YLW}[SETUP]${NC} Created hosts file: $HOSTS_FILE"
    echo -e "${YLW}        Edit it or use bt_add_host to add your machines${NC}"
else
    HOST_COUNT=$(grep -v '^#\|^$' "$HOSTS_FILE" | wc -l)
    echo -e "${GRN}[OK]${NC}    Fleet: $HOST_COUNT host(s) in $HOSTS_FILE"
fi

# ── Update profile to use container paths ────────────────────
# The profile was written for ~/blueTeam — repoint to /opt/blueTeam
sed -i 's|$HOME/blueTeam|/opt/blueTeam|g' /root/.blueTeam_profile 2>/dev/null
sed -i 's|~/blueTeam|/opt/blueTeam|g' /root/.blueTeam_profile 2>/dev/null

# ── Tool verification ─────────────────────────────────────────
echo ""
echo -e "${CYN}[TOOLS]${NC} Verifying installed tools..."
TOOLS=("nmap" "sshpass" "ssh" "tmux" "tcpdump" "nc" "curl" "tshark")
ALL_OK=true
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        printf "  ${GRN}✓${NC} %-12s %s\n" "$tool" "$(command -v $tool)"
    else
        printf "  ${YLW}✗${NC} %-12s NOT FOUND\n" "$tool"
        ALL_OK=false
    fi
done

echo ""
if $ALL_OK; then
    echo -e "${GRN}[OK]${NC}    All tools available."
else
    echo -e "${YLW}[WARN]${NC}  Some tools missing — rebuild container."
fi

# ── Quick reminder ────────────────────────────────────────────
echo ""
echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${GRN}Quick start:${NC}"
echo ""
echo -e "  ${YLW}bt_help${NC}                          ← all available commands"
echo -e "  ${YLW}bt_add_host root@10.0.1.10${NC}       ← add a machine to your fleet"
echo -e "  ${YLW}bt_push_key_all 'password'${NC}       ← deploy SSH keys to all hosts"
echo -e "  ${YLW}bt_run_all pcdc_linux_audit.sh${NC}   ← audit every host at once"
echo -e "  ${YLW}bt_dashboard${NC}                     ← live log view all hosts"
echo -e "  ${YLW}bt_status_all${NC}                    ← quick service health check"
echo ""
echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# ── Execute the command passed to the container ───────────────
exec "$@"
