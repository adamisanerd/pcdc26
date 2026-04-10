#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Recovery Access Setup
#
#  PURPOSE:
#  Red team establishes persistence and changes passwords.
#  You get locked out of a machine you're supposed to defend.
#  Game over — unless you set this up first.
#
#  This script establishes LAYERED recovery access on your
#  OWN assigned machines BEFORE the red team attacks:
#
#  Layer 1: Backup admin account with a password ONLY YOU know
#  Layer 2: SSH key auth for that account (survives password changes)
#  Layer 3: Secondary SSH key on root (survives account lockouts)
#  Layer 4: A hidden but legitimate sudo path back to root
#
#  The logic: red team will find and attack the obvious accounts
#  from your Blue Team Packet. They'll change passwords on those.
#  Your recovery account has a name they won't guess, a password
#  that was never in the packet, and SSH key access that doesn't
#  depend on passwords at all.
#
#  If they lock out every account you know about, you still have
#  a key-based login path they don't know exists.
#
#  RUN THIS: during your golden window, on every assigned machine,
#  via bt_run_covert from your admin machine so nothing about
#  the setup is visible in target process history.
#
#  Run as root on target.
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

ok()     { echo -e "${GRN}[OK]${NC}     $1"; }
warn()   { echo -e "${YLW}[WARN]${NC}   $1"; }
alert()  { echo -e "${RED}[ALERT]${NC}  $1"; }
info()   { echo -e "${CYN}[INFO]${NC}   $1"; }
section(){
    echo ""
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run as root.${NC}"; exit 1
fi

HOSTNAME=$(hostname)
MY_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${BLU}PCDC 2026 | Recovery Access Setup${NC}"
echo -e "Target: $HOSTNAME [$MY_IP]"
echo ""

# ============================================================
# CONFIGURATION — Set these before deploying
# These are the values you control and only you know
# ============================================================

# Your recovery account name — pick something realistic
# that blends into a Linux system but isn't in your packet
# Good examples: syslog, netadmin, monitor, logrotate, svcacct
# Bad examples: backdoor, hacker, recovery, blueteam
RECOVERY_USER="svcmon"

# Recovery password — strong, memorable, NEVER write in packet
# You need to remember this without writing it down anywhere obvious
# Generate one: openssl rand -base64 12
RECOVERY_PASS=""   # Set this before deploying — see prompt below

# Your admin machine's SSH public key
# Get this from: cat ~/blueTeam/keys/pcdc_admin.pub
# Paste the full "ssh-ed25519 AAAA..." string here
ADMIN_PUBKEY=""    # Set this before deploying — see prompt below

# ============================================================
# PROMPT FOR VALUES IF NOT SET IN SCRIPT
# Keeps sensitive values out of the script file itself
# ============================================================
if [ -z "$RECOVERY_PASS" ]; then
    echo -e "${YLW}Enter the recovery account password.${NC}"
    echo -e "${YLW}This should be something you memorize — not written in your packet.${NC}"
    read -rsp "Recovery password: " RECOVERY_PASS
    echo ""
fi

if [ -z "$ADMIN_PUBKEY" ]; then
    echo ""
    echo -e "${YLW}Paste your admin machine's SSH public key.${NC}"
    echo -e "${YLW}Get it from: cat ~/blueTeam/keys/pcdc_admin.pub${NC}"
    read -rp "Public key (ssh-ed25519 AAAA...): " ADMIN_PUBKEY
    echo ""
fi

if [ -z "$RECOVERY_PASS" ] || [ -z "$ADMIN_PUBKEY" ]; then
    echo -e "${RED}Password and public key are required. Exiting.${NC}"
    exit 1
fi

# ============================================================
# LAYER 1: CREATE RECOVERY ACCOUNT
# Looks like a legitimate service account
# UID range 900-999 — below normal user range (1000+)
# but above system accounts, blends in naturally
# ============================================================
section "LAYER 1: RECOVERY ACCOUNT"

if id "$RECOVERY_USER" &>/dev/null; then
    warn "Account $RECOVERY_USER already exists — updating"
    usermod -s /bin/bash "$RECOVERY_USER" 2>/dev/null
else
    # Create account in the service account UID range
    useradd -m \
            -s /bin/bash \
            -c "System Monitor Service" \
            -u $(shuf -i 900-999 -n 1) \
            "$RECOVERY_USER" 2>/dev/null

    if id "$RECOVERY_USER" &>/dev/null; then
        ok "Account created: $RECOVERY_USER (UID: $(id -u $RECOVERY_USER))"
    else
        # UID conflict — let system assign
        useradd -m -s /bin/bash -c "System Monitor Service" "$RECOVERY_USER"
        ok "Account created: $RECOVERY_USER"
    fi
fi

# Set the password
echo "${RECOVERY_USER}:${RECOVERY_PASS}" | chpasswd
ok "Password set for $RECOVERY_USER"

# ============================================================
# LAYER 2: SSH KEY AUTH FOR RECOVERY ACCOUNT
# Key auth survives password changes completely
# Even if red team changes the password via passwd,
# your key still works
# ============================================================
section "LAYER 2: SSH KEY AUTH"

RECOVERY_HOME=$(getent passwd "$RECOVERY_USER" | cut -d: -f6)
SSH_DIR="$RECOVERY_HOME/.ssh"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
chown "$RECOVERY_USER:$RECOVERY_USER" "$SSH_DIR"

# Write your admin public key to authorized_keys
echo "$ADMIN_PUBKEY" > "$SSH_DIR/authorized_keys"
chmod 600 "$SSH_DIR/authorized_keys"
chown "$RECOVERY_USER:$RECOVERY_USER" "$SSH_DIR/authorized_keys"

ok "SSH key installed for $RECOVERY_USER"

# ============================================================
# LAYER 3: ALSO ADD KEY TO ROOT'S AUTHORIZED_KEYS
# Belt and suspenders — if recovery account gets deleted,
# you can still key-auth directly as root
# ============================================================
section "LAYER 3: ROOT SSH KEY BACKUP"

ROOT_SSH_DIR="/root/.ssh"
mkdir -p "$ROOT_SSH_DIR"
chmod 700 "$ROOT_SSH_DIR"

# Add key without overwriting existing entries
if [ -f "$ROOT_SSH_DIR/authorized_keys" ]; then
    # Only add if not already present
    if ! grep -qF "$ADMIN_PUBKEY" "$ROOT_SSH_DIR/authorized_keys" 2>/dev/null; then
        echo "$ADMIN_PUBKEY" >> "$ROOT_SSH_DIR/authorized_keys"
        ok "Admin key appended to root authorized_keys"
    else
        ok "Admin key already in root authorized_keys"
    fi
else
    echo "$ADMIN_PUBKEY" > "$ROOT_SSH_DIR/authorized_keys"
    chmod 600 "$ROOT_SSH_DIR/authorized_keys"
    ok "Admin key added to root authorized_keys"
fi

# ============================================================
# LAYER 4: SUDO ACCESS FOR RECOVERY ACCOUNT
# Drop a sudoers file for the recovery account
# Using /etc/sudoers.d/ — cleaner than editing sudoers directly
# and survives if red team edits the main sudoers file
# ============================================================
section "LAYER 4: SUDO ACCESS"

SUDOERS_FILE="/etc/sudoers.d/99-${RECOVERY_USER}"

cat > "$SUDOERS_FILE" << EOF
# System monitor service account — do not remove
$RECOVERY_USER ALL=(ALL) NOPASSWD:ALL
EOF

chmod 440 "$SUDOERS_FILE"

# Validate the sudoers syntax
if visudo -cf "$SUDOERS_FILE" &>/dev/null; then
    ok "Sudo access configured: $RECOVERY_USER can sudo without password"
else
    warn "Sudoers syntax issue — removing and using manual entry"
    rm -f "$SUDOERS_FILE"
    echo "$RECOVERY_USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
    ok "Sudo access added directly to /etc/sudoers"
fi

# ============================================================
# LAYER 5: PROTECT SSHD CONFIG
# Ensure SSH allows key auth and doesn't get locked down
# in a way that breaks your recovery path
# Red team may try to set PasswordAuthentication no AND
# remove your keys — make sure PubkeyAuthentication stays on
# ============================================================
section "LAYER 5: SSHD CONFIG PROTECTION"

SSHD_CONFIG="/etc/ssh/sshd_config"

# Ensure public key auth stays enabled
if grep -q "^PubkeyAuthentication" "$SSHD_CONFIG" 2>/dev/null; then
    sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' "$SSHD_CONFIG"
else
    echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
fi
ok "PubkeyAuthentication yes enforced in sshd_config"

# Ensure authorized_keys is looked for in the right place
if ! grep -q "^AuthorizedKeysFile" "$SSHD_CONFIG" 2>/dev/null; then
    echo "AuthorizedKeysFile .ssh/authorized_keys" >> "$SSHD_CONFIG"
fi

# Restart sshd to apply
systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
ok "sshd restarted"

# ============================================================
# LAYER 6: PROTECT AUTHORIZED_KEYS FROM TAMPERING
# Use chattr to make authorized_keys immutable
# Even root can't modify it without first removing the flag
# Red team with root can still remove it — but it buys time
# and they have to know it's there first
# ============================================================
section "LAYER 6: FILE IMMUTABILITY"

if command -v chattr &>/dev/null; then
    chattr +i "$SSH_DIR/authorized_keys" 2>/dev/null && \
        ok "authorized_keys set immutable (chattr +i)" || \
        warn "chattr failed — filesystem may not support it"

    # Also protect root's authorized_keys
    chattr +i "$ROOT_SSH_DIR/authorized_keys" 2>/dev/null && \
        ok "root authorized_keys set immutable" || \
        warn "chattr on root key failed"

    # And protect the sudoers drop file
    chattr +i "$SUDOERS_FILE" 2>/dev/null && \
        ok "sudoers file set immutable" || \
        warn "chattr on sudoers failed"

    info "To remove immutability if YOU need to modify: chattr -i <file>"
else
    warn "chattr not available — skipping immutability protection"
fi

# ============================================================
# VERIFY EVERYTHING WORKS BEFORE TRUSTING IT
# ============================================================
section "VERIFICATION"

info "Testing recovery account setup..."

# Test password auth works
if echo "$RECOVERY_PASS" | su -c "whoami" "$RECOVERY_USER" &>/dev/null; then
    ok "Password auth: WORKING for $RECOVERY_USER"
else
    warn "Password auth test inconclusive — verify manually"
fi

# Test sudo works
if su -c "sudo whoami" "$RECOVERY_USER" 2>/dev/null | grep -q root; then
    ok "Sudo access: WORKING for $RECOVERY_USER"
else
    warn "Sudo test inconclusive — test manually after setup"
fi

# Show final state
echo ""
info "Recovery account summary:"
echo "  Account:  $RECOVERY_USER"
echo "  UID:      $(id -u $RECOVERY_USER 2>/dev/null)"
echo "  Home:     $RECOVERY_HOME"
echo "  Shell:    $(getent passwd $RECOVERY_USER | cut -d: -f7)"
echo "  SSH key:  $SSH_DIR/authorized_keys"
echo "  Sudo:     NOPASSWD:ALL"
echo ""

# ============================================================
# DONE — Print recovery instructions to save
# ============================================================
section "RECOVERY ACCESS SUMMARY — SAVE THIS"

cat << EOF
╔══════════════════════════════════════════════════════════════╗
║  RECOVERY ACCESS: $HOSTNAME [$MY_IP]
╠══════════════════════════════════════════════════════════════╣
║
║  METHOD 1 — SSH KEY (works even if password changed)
║    ssh -i ~/blueTeam/keys/pcdc_admin ${RECOVERY_USER}@${MY_IP}
║
║  METHOD 2 — PASSWORD (if key fails for some reason)
║    ssh ${RECOVERY_USER}@${MY_IP}
║    Password: [the one you entered — memorize it]
║
║  METHOD 3 — ROOT KEY DIRECT (if recovery account deleted)
║    ssh -i ~/blueTeam/keys/pcdc_admin root@${MY_IP}
║
║  ONCE IN — regain full control:
║    sudo passwd root           # reset root password
║    sudo passwd <locked_user>  # reset any locked account
║    sudo usermod -U <user>     # unlock a locked account
║    sudo chage -E -1 <user>    # unexpire an account
║
║  IF KEY AUTH BLOCKED:
║    sudo sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
║    sudo systemctl restart sshd
║
╚══════════════════════════════════════════════════════════════╝
EOF

echo ""
echo -e "${YLW}IMPORTANT:${NC}"
echo "  1. Run this on every machine in your fleet"
echo "  2. Use bt_run_covert to deploy — keeps this off target process list"
echo "  3. The recovery password should be memorized, not written in your packet"
echo "  4. Verify key auth from your admin machine after deploying to each host"
echo ""
