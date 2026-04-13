#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Scored Service Validator
#
#  PURPOSE:
#  Verify likely scored services are installed, running, listening,
#  and not obviously misconfigured in ways that will cost points.
#
#  This is a READ-ONLY validation script.
#  It does not change configs or restart services.
#
#  Run after hardening and again during recurring sweeps.
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
LOGFILE="$LOGDIR/scored_service_validate_$TIMESTAMP.log"
mkdir -p "$LOGDIR"
exec > >(tee -a "$LOGFILE") 2>&1

is_trusted_infrastructure() { return 1; }
infra_note() { echo -e "${CYN}[INFO]${NC}     [INFRA] $1"; }
COMP_SCORED_SERVICES=("apache2" "nginx" "sshd" "postfix" "named" "mysql" "mariadb" "vsftpd" "smbd")
_CONF_FILE="$(dirname "$(readlink -f "$0")")/pcdc_competition_config.sh"
# shellcheck source=pcdc_competition_config.sh
[ -f "$_CONF_FILE" ] && source "$_CONF_FILE"
unset _CONF_FILE

ok()    { echo -e "${GRN}[OK]${NC}      $1"; }
warn()  { echo -e "${YLW}[WARN]${NC}    $1"; }
alert() { echo -e "${RED}[ALERT]${NC}   $1"; }
info()  { echo -e "${CYN}[INFO]${NC}    $1"; }
section() {
    echo ""
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLU}  $1${NC}"
    echo -e "${BLU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

service_exists() {
    local svc="$1"
    systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service" || \
    service --status-all 2>/dev/null | grep -q "[[:space:]]$svc$"
}

service_running() {
    local svc="$1"
    systemctl is-active --quiet "$svc" 2>/dev/null || service "$svc" status >/dev/null 2>&1
}

expected_ports() {
    case "$1" in
        apache2|nginx) echo "80 443" ;;
        sshd) echo "22" ;;
        postfix) echo "25" ;;
        named) echo "53" ;;
        mysql|mariadb) echo "3306" ;;
        vsftpd) echo "21" ;;
        smbd) echo "139 445" ;;
        *) echo "" ;;
    esac
}

port_is_listening() {
    local port="$1"
    ss -tuln 2>/dev/null | awk '{print $5}' | grep -Eq "(^|:)${port}$"
}

service_port_exposure() {
    local port="$1"
    ss -tuln 2>/dev/null | awk -v p="$port" '$5 ~ (":" p "$") {print $5}'
}

check_common_status() {
    local svc="$1"
    local ports port found_any=false

    if ! service_exists "$svc"; then
        info "$svc not installed on this host — likely not this host's scored role"
        return 0
    fi

    if service_running "$svc"; then
        ok "$svc is running"
    else
        alert "$svc is installed but NOT running"
        warn "  Action: verify this service is actually required on this host, then restore it if scored"
    fi

    ports=$(expected_ports "$svc")
    for port in $ports; do
        if port_is_listening "$port"; then
            found_any=true
            ok "$svc expected port $port is listening"
            service_port_exposure "$port" | while read -r bind; do
                case "$svc:$port:$bind" in
                    mysql:3306:0.0.0.0:3306|mariadb:3306:0.0.0.0:3306|mysql:3306:*:3306|mariadb:3306:*:3306)
                        warn "$svc is exposed on all interfaces via $bind"
                        warn "  Action: bind to localhost or the required internal interface only"
                        ;;
                    smbd:445:0.0.0.0:445|smbd:139:0.0.0.0:139|vsftpd:21:0.0.0.0:21)
                        warn "$svc is broadly exposed via $bind — confirm this is required"
                        ;;
                esac
            done
        fi
    done

    if [ "$found_any" = false ] && [ -n "$ports" ]; then
        warn "$svc has no detected listening ports among expected set: $ports"
    fi
}

check_apache2() {
    check_common_status apache2
    if command -v apache2ctl >/dev/null 2>&1; then
        if apache2ctl -M 2>/dev/null | grep -q "autoindex_module"; then
            warn "apache2 autoindex module enabled"
            warn "  Action: disable directory listing if not explicitly required"
        fi
    fi
    if grep -RiqE '^\s*Options\s+.*Indexes' /etc/apache2 2>/dev/null; then
        warn "apache2 config appears to allow directory indexing"
    fi
}

check_nginx() {
    check_common_status nginx
    if grep -Riq 'autoindex on;' /etc/nginx 2>/dev/null; then
        warn "nginx autoindex is enabled"
        warn "  Action: set autoindex off unless the service explicitly needs listings"
    fi
    if grep -Riq 'server_tokens on;' /etc/nginx 2>/dev/null; then
        warn "nginx server_tokens is on"
    fi
}

check_sshd() {
    check_common_status sshd
    if command -v sshd >/dev/null 2>&1; then
        sshd -T 2>/dev/null | while read -r key value _; do
            case "$key $value" in
                'permitrootlogin yes') warn "sshd allows direct root login" ;;
                'passwordauthentication yes') warn "sshd still allows password authentication — acceptable only if competition access requires it" ;;
                'maxauthtries 6'|'maxauthtries 5'|'maxauthtries 4') warn "sshd MaxAuthTries is permissive ($value)" ;;
            esac
        done
    fi
}

check_postfix() {
    check_common_status postfix
    if command -v postconf >/dev/null 2>&1; then
        local mynetworks relay_restrictions
        mynetworks=$(postconf -h mynetworks 2>/dev/null)
        relay_restrictions=$(postconf -h smtpd_relay_restrictions 2>/dev/null)
        if echo "$mynetworks" | grep -Eq '0\.0\.0\.0/0|/0'; then
            alert "postfix mynetworks is too broad: $mynetworks"
        fi
        if [ -z "$relay_restrictions" ]; then
            warn "postfix smtpd_relay_restrictions not set"
        fi
    fi
}

check_named() {
    check_common_status named
    if grep -Riq 'recursion yes' /etc/bind /etc/named* 2>/dev/null; then
        warn "named appears to allow recursion"
        warn "  Action: restrict recursion to trusted internal clients only"
    fi
    if grep -RiqE 'allow-transfer\s*\{\s*any;\s*\}' /etc/bind /etc/named* 2>/dev/null; then
        alert "named allows zone transfer to any host"
    fi
}

check_mysql_family() {
    local svc="$1"
    check_common_status "$svc"
    if grep -RiqE '^\s*bind-address\s*=\s*0\.0\.0\.0' /etc/mysql /etc/my.cnf* 2>/dev/null; then
        warn "$svc bind-address is 0.0.0.0"
    fi
    if command -v mysql >/dev/null 2>&1; then
        local anon_users
        anon_users=$(mysql -NBe "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE User='';" 2>/dev/null)
        if [ -n "$anon_users" ]; then
            alert "$svc has anonymous database account(s): $anon_users"
        fi
    else
        info "mysql client not present — skipping database auth checks"
    fi
}

check_vsftpd() {
    check_common_status vsftpd
    if grep -qE '^\s*anonymous_enable=YES' /etc/vsftpd.conf 2>/dev/null; then
        alert "vsftpd anonymous login is enabled"
    fi
    if ! grep -qE '^\s*chroot_local_user=YES' /etc/vsftpd.conf 2>/dev/null; then
        warn "vsftpd chroot_local_user is not enabled"
    fi
}

check_smbd() {
    check_common_status smbd
    if command -v testparm >/dev/null 2>&1; then
        local config
        config=$(testparm -s 2>/dev/null)
        echo "$config" | grep -qi 'server min protocol = NT1' && alert "smbd allows SMB1/NT1"
        echo "$config" | grep -qi 'map to guest = .*bad user' && warn "smbd maps unknown users to guest"
        echo "$config" | grep -qi 'guest ok = yes' && warn "One or more SMB shares allow guest access"
    fi
}

main() {
    section "SCORED SERVICE VALIDATION"
    info "Host: $(hostname)"
    info "Log:  $LOGFILE"
    echo ""

    local targets
    if [ "$#" -gt 0 ]; then
        targets=("$@")
    else
        targets=("${COMP_SCORED_SERVICES[@]}")
    fi

    for svc in "${targets[@]}"; do
        echo ""
        echo -e "${MAG}── $svc ──${NC}"
        case "$svc" in
            apache2) check_apache2 ;;
            nginx) check_nginx ;;
            sshd) check_sshd ;;
            postfix) check_postfix ;;
            named) check_named ;;
            mysql|mariadb) check_mysql_family "$svc" ;;
            vsftpd) check_vsftpd ;;
            smbd) check_smbd ;;
            *) check_common_status "$svc" ;;
        esac
    done

    echo ""
    ok "Validation complete. Review warnings/alerts before making service changes."
}

main "$@"
