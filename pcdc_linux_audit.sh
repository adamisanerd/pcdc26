#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Linux Audit & Hardening Script
#  Run as root. Logs everything to /var/log/blueTeam/
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="$LOGDIR/audit_$TIMESTAMP.log"

mkdir -p "$LOGDIR"
exec > >(tee -a "$LOGFILE") 2>&1

banner() {
    echo -e "${BLU}"
    echo "============================================================"
    echo "  $1"
    echo "============================================================"
    echo -e "${NC}"
}

ok()   { echo -e "${GRN}[OK]${NC}    $1"; }
warn() { echo -e "${YLW}[WARN]${NC}  $1"; }
bad()  { echo -e "${RED}[BAD]${NC}   $1"; }
info() { echo -e "${CYN}[INFO]${NC}  $1"; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run this script as root.${NC}"
    exit 1
fi

echo ""
echo -e "${BLU}PCDC 2026 | Astra 9 Blue Team Linux Audit${NC}"
echo -e "Host: $(hostname) | IP: $(hostname -I | awk '{print $1}') | Time: $(date)"
echo "Log: $LOGFILE"
echo ""

# ============================================================
# SECTION 1: USER & ACCOUNT AUDIT
# ============================================================
banner "SECTION 1: USER & ACCOUNT AUDIT"

info "All user accounts (UID >= 1000 or UID = 0):"
awk -F: '($3 == 0 || $3 >= 1000) && $1 != "nobody" {print $1, "UID="$3, "Shell="$7, "Home="$6}' /etc/passwd

echo ""
info "Accounts with UID 0 (root-equivalent) — SHOULD ONLY BE root:"
awk -F: '$3 == 0 {print $1}' /etc/passwd | while read u; do
    if [ "$u" != "root" ]; then
        bad "UID 0 account found: $u — INVESTIGATE IMMEDIATELY"
    else
        ok "root is the only UID 0 account"
    fi
done

echo ""
info "Accounts with empty passwords — these are open doors:"
awk -F: '($2 == "" || $2 == "!!" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | while read u; do
    bad "Empty/locked password: $u"
done

echo ""
info "Users with login shells (can log in):"
grep -v '/nologin\|/false' /etc/passwd | awk -F: '{print $1, $7}'

echo ""
info "Sudoers — who can escalate:"
grep -v '^#\|^$' /etc/sudoers 2>/dev/null
ls /etc/sudoers.d/ 2>/dev/null && cat /etc/sudoers.d/* 2>/dev/null

echo ""
info "Currently logged-in users:"
who
w

echo ""
info "Last logins (last 20):"
last -n 20

echo ""
info "Failed login attempts:"
lastb -n 20 2>/dev/null || grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20

# ============================================================
# SECTION 2: PASSWORD & AUTH HARDENING CHECK
# ============================================================
banner "SECTION 2: PASSWORD & AUTH HARDENING"

info "Checking SSH config (/etc/ssh/sshd_config):"
SSHCFG="/etc/ssh/sshd_config"

check_ssh() {
    local key=$1 good_val=$2
    val=$(grep -i "^$key" $SSHCFG 2>/dev/null | awk '{print $2}')
    if [[ "$val" == "$good_val" ]]; then
        ok "$key = $val"
    else
        warn "$key = '${val:-not set}' (recommended: $good_val)"
    fi
}

check_ssh "PermitRootLogin" "no"
check_ssh "PasswordAuthentication" "no"
check_ssh "PermitEmptyPasswords" "no"
check_ssh "X11Forwarding" "no"
check_ssh "Protocol" "2"
check_ssh "MaxAuthTries" "3"

echo ""
info "Password policy (/etc/login.defs):"
grep -E "^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_MIN_LEN|^PASS_WARN_AGE" /etc/login.defs

echo ""
info "PAM password strength config:"
cat /etc/pam.d/common-password 2>/dev/null | grep -v '^#' | grep -v '^$'

# ============================================================
# SECTION 3: NETWORK & OPEN PORTS
# ============================================================
banner "SECTION 3: NETWORK & OPEN PORTS"

info "Listening ports and associated processes:"
ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null

echo ""
info "Established connections:"
ss -tnp state established 2>/dev/null || netstat -tnp 2>/dev/null | grep ESTABLISHED

echo ""
info "Network interfaces:"
ip addr show

echo ""
info "Routing table:"
ip route

echo ""
info "ARP table (look for duplicates — could indicate ARP spoofing):"
arp -n 2>/dev/null || ip neigh

echo ""
info "DNS config (/etc/resolv.conf):"
cat /etc/resolv.conf

echo ""
info "/etc/hosts (look for suspicious entries):"
cat /etc/hosts

# ============================================================
# SECTION 4: RUNNING PROCESSES
# ============================================================
banner "SECTION 4: RUNNING PROCESSES"

info "All running processes:"
ps auxf

echo ""
info "Processes running as root (non-standard ones are suspicious):"
ps aux | awk '$1 == "root" {print $1, $2, $11, $12}' | grep -v -E 'ps|awk|grep|sshd|cron|init|systemd|kernel|bash|tee|script'

echo ""
info "Processes with no associated binary path (common malware indicator):"
ps aux | awk '$11 ~ /^\[/ {print "Kernel thread:", $0}' 
ls -la /proc/*/exe 2>/dev/null | grep deleted | while read line; do
    bad "Deleted binary still running: $line"
done

# ============================================================
# SECTION 5: SCHEDULED TASKS (PERSISTENCE CHECK)
# ============================================================
banner "SECTION 5: SCHEDULED TASKS & PERSISTENCE"

info "Root crontab:"
crontab -l 2>/dev/null || echo "(none)"

echo ""
info "System-wide cron directories:"
for dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    echo "--- $dir ---"
    ls -la "$dir" 2>/dev/null && cat "$dir"/* 2>/dev/null
done

echo ""
info "All user crontabs:"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab_content=$(crontab -u "$user" -l 2>/dev/null)
    if [ -n "$crontab_content" ]; then
        warn "Crontab found for user: $user"
        echo "$crontab_content"
    fi
done

echo ""
info "Systemd timers (can be used for persistence):"
systemctl list-timers --all 2>/dev/null

echo ""
info "At jobs:"
atq 2>/dev/null

echo ""
info "Checking for common persistence locations:"
for f in /etc/rc.local /etc/rc.d/rc.local /etc/init.d/rc.local; do
    if [ -f "$f" ]; then
        warn "Found: $f"
        cat "$f"
    fi
done

info "Systemd service units (look for unusual ones):"
systemctl list-units --type=service --all 2>/dev/null | grep -v "systemd\|dbus\|network\|ssh\|cron\|rsyslog\|udev\|getty"

# ============================================================
# SECTION 6: SUID/SGID BINARIES (PRIVILEGE ESCALATION RISK)
# ============================================================
banner "SECTION 6: SUID/SGID BINARIES"

info "SUID binaries (can be abused for privilege escalation):"
find / -perm -4000 -type f 2>/dev/null | while read f; do
    # Flag anything not in standard locations
    if echo "$f" | grep -qv -E '^/(usr|bin|sbin)'; then
        bad "Unusual SUID binary: $f"
    else
        info "Standard SUID: $f"
    fi
done

echo ""
info "SGID binaries:"
find / -perm -2000 -type f 2>/dev/null

echo ""
info "World-writable files (excluding /tmp, /proc, /sys):"
find / -perm -o+w -type f \
    ! -path "/tmp/*" \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    ! -path "/dev/*" \
    2>/dev/null | head -30

echo ""
info "World-writable directories:"
find / -perm -o+w -type d \
    ! -path "/tmp" \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    ! -path "/dev/*" \
    2>/dev/null | head -20

# ============================================================
# SECTION 7: FIREWALL STATUS
# ============================================================
banner "SECTION 7: FIREWALL STATUS"

info "iptables rules:"
iptables -L -n -v 2>/dev/null

echo ""
info "iptables NAT table:"
iptables -t nat -L -n -v 2>/dev/null

echo ""
info "ufw status (if applicable):"
ufw status verbose 2>/dev/null

echo ""
info "firewalld status (if applicable):"
firewall-cmd --list-all 2>/dev/null

# ============================================================
# SECTION 8: INSTALLED PACKAGES & PATCHING
# ============================================================
banner "SECTION 8: INSTALLED PACKAGES & UPDATES"

info "Package manager detected, checking for updates:"
if command -v apt &>/dev/null; then
    info "Debian/Ubuntu system"
    apt list --upgradable 2>/dev/null | head -30
    echo ""
    info "Recently installed packages (last 20):"
    grep " install " /var/log/dpkg.log 2>/dev/null | tail -20
elif command -v yum &>/dev/null; then
    info "RHEL/CentOS system"
    yum check-update 2>/dev/null | head -30
elif command -v dnf &>/dev/null; then
    info "Fedora/RHEL system"
    dnf check-update 2>/dev/null | head -30
fi

echo ""
info "Kernel version:"
uname -a

# ============================================================
# SECTION 9: FILE INTEGRITY CHECKS
# ============================================================
banner "SECTION 9: FILE INTEGRITY & SUSPICIOUS FILES"

info "Files modified in the last 24 hours (outside /proc /sys /dev /run /tmp):"
find / -mtime -1 -type f \
    ! -path "/proc/*" \
    ! -path "/sys/*" \
    ! -path "/dev/*" \
    ! -path "/run/*" \
    ! -path "/tmp/*" \
    2>/dev/null | head -50

echo ""
info "Hidden files in /tmp, /var/tmp, /dev/shm (common malware staging):"
ls -la /tmp/ /var/tmp/ /dev/shm/ 2>/dev/null
find /tmp /var/tmp /dev/shm -name ".*" 2>/dev/null | while read f; do
    bad "Hidden file found: $f"
done

echo ""
info "Executable files in /tmp (very suspicious):"
find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | while read f; do
    bad "Executable in temp dir: $f"
done

echo ""
info "Checking /etc/passwd and /etc/shadow for recent modification:"
ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null

echo ""
info "SSH authorized_keys files (backdoor check):"
find /home /root -name "authorized_keys" 2>/dev/null | while read f; do
    warn "authorized_keys at: $f"
    cat "$f"
done

# ============================================================
# SECTION 10: SERVICE STATUS CHECK
# ============================================================
banner "SECTION 10: KEY SERVICE STATUS"

SERVICES=("ssh" "sshd" "apache2" "nginx" "mysql" "mariadb" "postgresql" "postfix" "named" "bind9" "vsftpd" "smbd" "docker")

for svc in "${SERVICES[@]}"; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        ok "Service running: $svc"
    elif systemctl list-unit-files 2>/dev/null | grep -q "^${svc}.service"; then
        warn "Service exists but not running: $svc"
    fi
done

# ============================================================
# SECTION 11: LOG REVIEW
# ============================================================
banner "SECTION 11: LOG REVIEW (Last 50 suspicious entries)"

info "Auth log — failed logins, sudo use, su attempts:"
grep -E "Failed|sudo|su\[|Invalid user|ROOT LOGIN|session opened" \
    /var/log/auth.log /var/log/secure 2>/dev/null | tail -50

echo ""
info "Syslog — errors and warnings:"
grep -E "error|warning|critical|alert" /var/log/syslog 2>/dev/null | tail -20

echo ""
info "Checking for signs of log tampering (last modified):"
ls -la /var/log/auth.log /var/log/syslog /var/log/messages 2>/dev/null

# ============================================================
# SECTION 12: DOCKER (if present)
# ============================================================
if command -v docker &>/dev/null; then
    banner "SECTION 12: DOCKER CONTAINERS"
    info "Running containers:"
    docker ps 2>/dev/null
    echo ""
    info "All containers (including stopped):"
    docker ps -a 2>/dev/null
    echo ""
    info "Docker networks:"
    docker network ls 2>/dev/null
    echo ""
    info "Docker images:"
    docker images 2>/dev/null
fi

# ============================================================
# DONE
# ============================================================
banner "AUDIT COMPLETE"
echo -e "${GRN}Full log saved to: $LOGFILE${NC}"
echo ""
echo -e "${YLW}NEXT STEPS:${NC}"
echo "  1. Review all [BAD] entries first"
echo "  2. Review all [WARN] entries"
echo "  3. Run pcdc_harden.sh to apply fixes"
echo "  4. Run pcdc_monitor.sh for continuous monitoring"
echo ""
