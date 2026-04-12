#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Linux Hardening Script
#  Run IMMEDIATELY during your golden window.
#  Run as root. Prompts before destructive actions.
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="$LOGDIR/harden_$TIMESTAMP.log"

mkdir -p "$LOGDIR"
exec > >(tee -a "$LOGFILE") 2>&1

ok()     { echo -e "${GRN}[OK]${NC}      $1"; }
warn()   { echo -e "${YLW}[WARN]${NC}    $1"; }
bad()    { echo -e "${RED}[BAD]${NC}     $1"; }
info()   { echo -e "${CYN}[INFO]${NC}    $1"; }
action() { echo -e "${BLU}[ACTION]${NC}  $1"; }

confirm() {
    read -rp "$(echo -e "${YLW}$1 [y/N]: ${NC}")" ans
    [[ "$ans" =~ ^[Yy]$ ]]
}

banner() {
    echo ""
    echo -e "${BLU}============================================================${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}============================================================${NC}"
    echo ""
}

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run this script as root.${NC}"
    exit 1
fi

echo ""
echo -e "${BLU}PCDC 2026 | Astra 9 Blue Team Linux Hardening${NC}"
echo -e "Host: $(hostname) | IP: $(hostname -I | awk '{print $1}') | Time: $(date)"
echo "Log: $LOGFILE"
echo ""

# ============================================================
# STEP 1: CHANGE ALL PASSWORDS
# ============================================================
banner "STEP 1: PASSWORD RESET"

info "This will prompt you to set a new password for each login-capable account."
info "Use a STRONG, CONSISTENT password scheme. Write them down — on paper."
echo ""

# Get all accounts that can log in
LOGIN_USERS=$(grep -v '/nologin\|/false\|/sync' /etc/passwd | awk -F: '$3 >= 0 {print $1}')

for user in $LOGIN_USERS; do
    if confirm "Change password for user: $user?"; then
        passwd "$user"
        ok "Password changed for $user"
    else
        warn "Skipped password change for $user"
    fi
done

# ============================================================
# STEP 2: LOCK/REMOVE SUSPICIOUS ACCOUNTS
# ============================================================
banner "STEP 2: ACCOUNT LOCKDOWN"

info "Accounts with UID >= 1000 (regular users):"
awk -F: '$3 >= 1000 && $1 != "nobody" {print $1, "UID="$3}' /etc/passwd

echo ""
info "For each unexpected account, you can lock it (safe) or delete it."

awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | while read user; do
    echo ""
    warn "User: $user"
    echo "  1) Lock account (safe, reversible)"
    echo "  2) Delete account"
    echo "  3) Skip"
    read -rp "Choice [1/2/3]: " choice
    case $choice in
        1)
            usermod -L "$user"
            chage -E 0 "$user" 2>/dev/null
            ok "Locked account: $user"
            ;;
        2)
            if confirm "PERMANENTLY delete $user and their home directory?"; then
                userdel -r "$user" 2>/dev/null
                ok "Deleted user: $user"
            fi
            ;;
        3)
            warn "Skipped: $user"
            ;;
    esac
done

echo ""
info "Checking for UID 0 accounts other than root:"
awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd | while read user; do
    bad "CRITICAL: UID 0 account found: $user"
    if confirm "Remove UID 0 from $user (change to next available UID)?"; then
        # Safer than deleting — change their UID
        NEW_UID=$(awk -F: '$3 >= 1000 {uid=$3} END {print uid+1}' /etc/passwd)
        usermod -u "$NEW_UID" "$user"
        ok "Changed $user UID to $NEW_UID"
    fi
done

# ============================================================
# STEP 3: SSH HARDENING
# ============================================================
banner "STEP 3: SSH HARDENING"

SSHCFG="/etc/ssh/sshd_config"
info "Backing up SSH config to ${SSHCFG}.bak.$TIMESTAMP"
cp "$SSHCFG" "${SSHCFG}.bak.${TIMESTAMP}"

apply_ssh_setting() {
    local key=$1
    local val=$2
    # Remove existing lines for this key (commented or not)
    sed -i "/^#\?${key}/d" "$SSHCFG"
    # Append new setting
    echo "$key $val" >> "$SSHCFG"
    ok "SSH: $key = $val"
}

if confirm "Harden SSH configuration?"; then
    apply_ssh_setting "PermitRootLogin" "no"
    apply_ssh_setting "PermitEmptyPasswords" "no"
    apply_ssh_setting "X11Forwarding" "no"
    apply_ssh_setting "MaxAuthTries" "3"
    apply_ssh_setting "LoginGraceTime" "30"
    apply_ssh_setting "ClientAliveInterval" "300"
    apply_ssh_setting "ClientAliveCountMax" "2"
    apply_ssh_setting "Protocol" "2"
    # NOTE: Leaving PasswordAuthentication as-is — scoring engine may need it
    warn "PasswordAuthentication NOT changed — verify scoring engine doesn't need it first"

    info "Restarting SSH service..."
    systemctl restart sshd 2>/dev/null || service ssh restart 2>/dev/null
    ok "SSH restarted"
fi

# ============================================================
# STEP 4: REMOVE SUSPICIOUS AUTHORIZED_KEYS
# ============================================================
banner "STEP 4: AUTHORIZED_KEYS AUDIT"

info "Searching for authorized_keys files..."
find /home /root -name "authorized_keys" 2>/dev/null | while read keyfile; do
    echo ""
    warn "Found: $keyfile"
    echo "Contents:"
    cat "$keyfile"
    echo ""
    if confirm "Clear authorized_keys at $keyfile?"; then
        # Back it up first
        cp "$keyfile" "${keyfile}.bak.${TIMESTAMP}"
        : > "$keyfile"
        chmod 600 "$keyfile"
        ok "Cleared $keyfile (backup saved)"
    fi
done

# ============================================================
# STEP 5: KILL SUSPICIOUS CRON JOBS
# ============================================================
banner "STEP 5: CRON JOB AUDIT & CLEANUP"

info "System crontabs in /etc/cron.d:"
ls /etc/cron.d/ 2>/dev/null

echo ""
info "User crontabs:"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab_content=$(crontab -u "$user" -l 2>/dev/null)
    if [ -n "$crontab_content" ]; then
        echo ""
        warn "Crontab for $user:"
        echo "$crontab_content"
        if confirm "Clear crontab for $user?"; then
            crontab -r -u "$user" 2>/dev/null
            ok "Cleared crontab for $user"
        fi
    fi
done

echo ""
info "Checking /etc/rc.local for persistence:"
if [ -f /etc/rc.local ]; then
    warn "Contents of /etc/rc.local:"
    cat /etc/rc.local
    if confirm "Review and edit /etc/rc.local?"; then
        "${EDITOR:-nano}" /etc/rc.local
    fi
fi

# ============================================================
# STEP 6: FIREWALL SETUP
# ============================================================
banner "STEP 6: FIREWALL HARDENING"

warn "DANGER ZONE: Firewall rules can break scored services."
warn "Only apply rules you fully understand."
echo ""

if confirm "Set up a basic restrictive firewall with iptables?"; then
    info "Backing up current iptables rules..."
    iptables-save > "$LOGDIR/iptables_backup_$TIMESTAMP.rules"
    ok "Backup saved to $LOGDIR/iptables_backup_$TIMESTAMP.rules"

    info "Flushing existing rules..."
    iptables -F
    iptables -X
    iptables -Z

    info "Setting default policies..."
    # Default DENY for INPUT and FORWARD, ALLOW OUTPUT
    # WARNING: Adjust these to match your scored services!
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

    info "Allowing established/related connections..."
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    info "Allowing loopback..."
    iptables -A INPUT -i lo -j ACCEPT

    info "Allowing SSH (port 22)..."
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT

    echo ""
    warn "You need to manually add rules for your scored services."
    echo "Common examples:"
    echo "  HTTP:    iptables -A INPUT -p tcp --dport 80 -j ACCEPT"
    echo "  HTTPS:   iptables -A INPUT -p tcp --dport 443 -j ACCEPT"
    echo "  DNS:     iptables -A INPUT -p udp --dport 53 -j ACCEPT"
    echo "  MySQL:   iptables -A INPUT -p tcp --dport 3306 -j ACCEPT"
    echo "  FTP:     iptables -A INPUT -p tcp --dport 21 -j ACCEPT"
    echo "  SMTP:    iptables -A INPUT -p tcp --dport 25 -j ACCEPT"
    echo "  ICMP:    iptables -A INPUT -p icmp -j ACCEPT"
    echo ""
    echo "To restore backup if something breaks:"
    echo "  iptables-restore < $LOGDIR/iptables_backup_$TIMESTAMP.rules"
    echo ""
    info "Current rules:"
    iptables -L -n -v
fi

# ============================================================
# STEP 7: DISABLE UNNECESSARY SERVICES
# ============================================================
banner "STEP 7: UNNECESSARY SERVICE REMOVAL"

warn "ONLY disable services you are SURE are not being scored."
echo ""

RISKY_SERVICES=("telnet" "rsh" "rlogin" "rexec" "finger" "talk" "ntalk" "rpcbind" "nfs" "ypbind")

for svc in "${RISKY_SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        warn "Potentially unnecessary service running: $svc"
        if confirm "Stop and disable $svc?"; then
            systemctl stop "$svc"
            systemctl disable "$svc"
            ok "Stopped and disabled: $svc"
        fi
    fi
done

# ============================================================
# STEP 8: PATCHING
# ============================================================
banner "STEP 8: SYSTEM PATCHING"

if command -v apt &>/dev/null; then
    if confirm "Run apt update && apt upgrade -y?"; then
        apt update
        apt upgrade -y
        ok "System updated"
    fi
elif command -v yum &>/dev/null; then
    if confirm "Run yum update -y?"; then
        yum update -y
        ok "System updated"
    fi
elif command -v dnf &>/dev/null; then
    if confirm "Run dnf update -y?"; then
        dnf update -y
        ok "System updated"
    fi
fi

# ============================================================
# STEP 9: CLEAN UP TEMP DIRS
# ============================================================
banner "STEP 9: TEMP DIRECTORY CLEANUP"

info "Checking for suspicious executables in temp directories..."
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | while read f; do
    bad "Executable found: $f"
    if confirm "Delete $f?"; then
        rm -f "$f"
        ok "Deleted: $f"
    fi
done

find /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null | while read f; do
    warn "Hidden file in temp: $f"
    ls -la "$f"
    if confirm "Delete $f?"; then
        rm -f "$f"
        ok "Deleted: $f"
    fi
done

# ============================================================
# DONE
# ============================================================
banner "HARDENING COMPLETE"
echo -e "${GRN}Log saved to: $LOGFILE${NC}"
echo ""
echo -e "${YLW}REMINDER:${NC}"
echo "  - Test ALL scored services are still reachable"
echo "  - SSH back in from a second terminal BEFORE closing current session"
echo "  - Check the scoreboard — if services drop, check your firewall rules"
echo "  - Run pcdc_monitor.sh next for ongoing detection"
echo ""
