#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Web Application & Service Integrity Monitor
#
#  WHY THIS SCRIPT EXISTS:
#  The packet explicitly scores HTTP/HTTPS services and email.
#  Red teams LOVE web apps because:
#  1. They're complex and easy to misconfigure
#  2. Webshells give persistent access that survives password changes
#  3. SQL injection can dump your entire database (scored service)
#  4. They can deface your site to lose business ops points
#
#  This script detects:
#  - Webshells planted in web root directories
#  - Recently modified web files (post-compromise injection)
#  - Dangerous PHP/Python/Perl functions in web files
#  - Database exposure (open ports, weak credentials)
#  - Directory listing enabled (information disclosure)
#  - Sensitive files accessible via web (/.git, /etc/passwd, etc.)
#  - Email relay open (lets red team spam through your server)
#  - Suspicious outbound email (credential exfil via mail)
#
#  Run as root.
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
NC='\033[0m'

LOGDIR="/var/log/blueTeam"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOGFILE="$LOGDIR/webapp_$TIMESTAMP.log"
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

# Web roots to scan — add yours from the Blue Team Packet
WEB_ROOTS=("/var/www/html" "/var/www" "/srv/www" "/usr/share/nginx/html"
           "/var/www/html/wordpress" "/opt/www" "/home/*/public_html")

# ============================================================
# SECTION 1: WEBSHELL DETECTION
# Webshells are the #1 red team persistence mechanism
# They survive password changes, firewall rule changes,
# and user account lockouts
# ============================================================
section "SECTION 1: WEBSHELL DETECTION"

# Dangerous function patterns in web files
# These are the building blocks of every webshell
WEBSHELL_PATTERNS=(
    # PHP webshell indicators
    'eval\s*(\s*base64_decode'
    'eval\s*(\s*gzinflate'
    'eval\s*(\s*str_rot13'
    'eval\s*(\s*gzuncompress'
    '\$_POST\s*\[.*\]\s*.*eval'
    '\$_GET\s*\[.*\]\s*.*eval'
    '\$_REQUEST\s*\[.*\]\s*.*eval'
    'system\s*(\s*\$_'
    'exec\s*(\s*\$_'
    'passthru\s*(\s*\$_'
    'shell_exec\s*(\s*\$_'
    'popen\s*(\s*\$_'
    'proc_open\s*(\s*\$_'
    'assert\s*(\s*\$_'
    'preg_replace.*\/e.*\$_'    # preg_replace with /e modifier = code exec
    'create_function.*\$_'
    'call_user_func.*\$_'
    # Python webshell indicators
    'os\.system.*request'
    'subprocess.*request'
    'exec.*request\.args'
    'eval.*request\.'
    # Generic indicators
    'base64_decode.*eval'
    'str_replace.*base64'
    '\$GLOBALS\[.*\]\(\$_'     # variable function call from global
)

info "Scanning web directories for webshell indicators..."

for webroot_pattern in "${WEB_ROOTS[@]}"; do
    for webroot in $webroot_pattern; do
        [ ! -d "$webroot" ] && continue
        info "Scanning: $webroot"

        for pattern in "${WEBSHELL_PATTERNS[@]}"; do
            matches=$(grep -rn -iP "$pattern" "$webroot" \
                --include="*.php" \
                --include="*.php5" \
                --include="*.phtml" \
                --include="*.py" \
                --include="*.pl" \
                --include="*.cgi" \
                --include="*.asp" \
                --include="*.aspx" \
                2>/dev/null)
            if [ -n "$matches" ]; then
                alert "WEBSHELL PATTERN '$pattern':"
                echo "$matches" | head -5 | while read line; do
                    echo -e "  ${RED}$line${NC}"
                done
                log_incident "WEBSHELL DETECTED" "$pattern in $webroot"
            fi
        done

        # Check for PHP files with suspicious names
        find $webroot -name "*.php" 2>/dev/null | grep -iE \
            'shell|cmd|exec|hack|backdoor|c99|r57|b374k|wso|bypass|upload|tmp[0-9]|[0-9]{6,}' | \
        while read f; do
            alert "SUSPICIOUS FILENAME: $f"
            log_incident "SUSPICIOUS WEB FILE" "$f"
        done

        # Files with unusual permissions in web root (executable PHP is suspicious)
        find $webroot -name "*.php" -perm /111 2>/dev/null | while read f; do
            warn "Executable PHP file: $f"
        done
    done
done

# ============================================================
# SECTION 2: RECENTLY MODIFIED WEB FILES
# After red team plants a webshell or modifies a page,
# the file's mtime changes. Track this.
# ============================================================
section "SECTION 2: RECENTLY MODIFIED WEB FILES"

STATE_DIR="$LOGDIR/webstate"
mkdir -p "$STATE_DIR"

for webroot_pattern in "${WEB_ROOTS[@]}"; do
    for webroot in $webroot_pattern; do
        [ ! -d "$webroot" ] && continue

        # Hash all web files for integrity baseline
        HASH_FILE="$STATE_DIR/$(echo $webroot | tr '/' '_').hashes"

        if [ ! -f "$HASH_FILE" ]; then
            info "Creating file integrity baseline for $webroot..."
            find "$webroot" -type f \( -name "*.php" -o -name "*.html" \
                -o -name "*.js" -o -name "*.py" -o -name "*.conf" \) \
                2>/dev/null | sort | xargs sha256sum 2>/dev/null > "$HASH_FILE"
            ok "Baseline saved: $HASH_FILE ($(wc -l < "$HASH_FILE") files)"
        else
            info "Checking file integrity for $webroot..."
            find "$webroot" -type f \( -name "*.php" -o -name "*.html" \
                -o -name "*.js" -o -name "*.py" -o -name "*.conf" \) \
                2>/dev/null | sort | xargs sha256sum 2>/dev/null > "$STATE_DIR/current.hashes"

            # Find modified files
            while read hash file; do
                expected=$(grep " $file$" "$HASH_FILE" 2>/dev/null | awk '{print $1}')
                if [ -z "$expected" ]; then
                    alert "NEW WEB FILE: $file"
                    log_incident "NEW WEB FILE" "$file"
                elif [ "$hash" != "$expected" ]; then
                    alert "WEB FILE MODIFIED: $file"
                    log_incident "WEB FILE MODIFIED" "$file"
                fi
            done < "$STATE_DIR/current.hashes"
        fi

        # Also show files modified in last 30 minutes (quick check)
        info "Files modified in last 30 minutes in $webroot:"
        recent=$(find "$webroot" -type f -mmin -30 2>/dev/null)
        if [ -n "$recent" ]; then
            warn "Recently modified:"
            echo "$recent" | while read f; do
                echo "  $(ls -la $f)"
                # Quick webshell scan on just this file
                if grep -qiP 'eval|system|exec|passthru|shell_exec' "$f" 2>/dev/null; then
                    alert "  ^ CONTAINS DANGEROUS FUNCTIONS — possible webshell"
                fi
            done
        else
            ok "No recent modifications"
        fi
    done
done

# ============================================================
# SECTION 3: WEB SERVER CONFIGURATION AUDIT
# ============================================================
section "SECTION 3: WEB SERVER CONFIG AUDIT"

# Apache
if command -v apache2 &>/dev/null || command -v httpd &>/dev/null; then
    info "Apache configuration check:"

    APACHE_CONFIGS=("/etc/apache2/apache2.conf" "/etc/apache2/sites-enabled/*"
                    "/etc/httpd/conf/httpd.conf" "/etc/httpd/conf.d/*.conf")

    for cfg_pattern in "${APACHE_CONFIGS[@]}"; do
        for cfg in $cfg_pattern; do
            [ ! -f "$cfg" ] && continue

            # Directory listing
            if grep -q "Options.*Indexes" "$cfg" 2>/dev/null; then
                alert "Directory listing ENABLED in $cfg (information disclosure)"
                log_incident "DIRECTORY LISTING ENABLED" "$cfg"
            fi

            # Server signature leaking version
            if grep -qi "ServerSignature On\|ServerTokens Full\|ServerTokens OS" "$cfg" 2>/dev/null; then
                warn "Server version disclosure in $cfg"
            fi

            # PHP dangerous functions (should be disabled)
            if grep -qi "disable_functions" "$cfg" 2>/dev/null; then
                info "PHP disable_functions set in $cfg:"
                grep -i "disable_functions" "$cfg"
            fi
        done
    done

    # Check PHP config
    for phpini in /etc/php*/*/php.ini /etc/php.ini /etc/php*/php.ini; do
        [ ! -f "$phpini" ] && continue
        info "PHP config: $phpini"

        # Dangerous settings
        if grep -q "^allow_url_fopen = On" "$phpini" 2>/dev/null; then
            warn "allow_url_fopen = On in $phpini (allows remote file inclusion)"
        fi
        if grep -q "^allow_url_include = On" "$phpini" 2>/dev/null; then
            alert "allow_url_include = On in $phpini — REMOTE FILE INCLUSION RISK"
            log_incident "RFI ENABLED" "$phpini"
        fi
        if ! grep -q "^disable_functions" "$phpini" 2>/dev/null; then
            warn "No disable_functions set in $phpini — exec/system/passthru available"
        else
            info "disable_functions: $(grep '^disable_functions' $phpini)"
        fi
    done
fi

# Nginx
if command -v nginx &>/dev/null; then
    info "Nginx configuration check:"
    nginx -T 2>/dev/null | grep -E "server_tokens|autoindex|root|listen" | while read line; do
        if echo "$line" | grep -qi "autoindex on"; then
            alert "Nginx directory listing ENABLED: $line"
        elif echo "$line" | grep -qi "server_tokens on"; then
            warn "Nginx version disclosure: $line"
        else
            info "$line"
        fi
    done
fi

# ============================================================
# SECTION 4: DATABASE SECURITY AUDIT
# ============================================================
section "SECTION 4: DATABASE SECURITY AUDIT"

# MySQL/MariaDB
if command -v mysql &>/dev/null; then
    info "MySQL/MariaDB checks:"

    # Check if MySQL is listening on external interfaces
    if ss -tlnp 2>/dev/null | grep ":3306" | grep -v "127.0.0.1\|::1"; then
        alert "MySQL listening on external interface — should be localhost only"
        log_incident "DB EXPOSED EXTERNALLY" "MySQL on external interface"
    else
        ok "MySQL bound to localhost only"
    fi

    # Try to connect without password (anonymous access)
    if mysql -u root --connect-timeout=3 -e "SELECT 1" &>/dev/null 2>&1; then
        alert "MySQL root login WITHOUT PASSWORD — critical vulnerability"
        log_incident "DB NO ROOT PASSWORD" "MySQL root has no password"
    fi

    # Check for anonymous MySQL users
    anon=$(mysql -u root --connect-timeout=3 -e \
        "SELECT user,host FROM mysql.user WHERE user='';" 2>/dev/null)
    if [ -n "$anon" ]; then
        alert "Anonymous MySQL users exist: $anon"
        log_incident "DB ANONYMOUS USER" "$anon"
    fi

    # Check for test database
    testdb=$(mysql -u root --connect-timeout=3 -e \
        "SHOW DATABASES LIKE 'test';" 2>/dev/null)
    if [ -n "$testdb" ]; then
        warn "MySQL 'test' database exists — should be removed"
    fi
fi

# PostgreSQL
if command -v psql &>/dev/null; then
    info "PostgreSQL checks:"

    # External listener check
    if ss -tlnp 2>/dev/null | grep ":5432" | grep -v "127.0.0.1\|::1"; then
        alert "PostgreSQL listening on external interface"
        log_incident "DB EXPOSED EXTERNALLY" "PostgreSQL on external interface"
    fi

    # Check pg_hba.conf for trust auth (no password)
    for hba in /etc/postgresql/*/main/pg_hba.conf; do
        [ ! -f "$hba" ] && continue
        if grep -v "^#\|^$" "$hba" | grep -q "\btrust\b"; then
            alert "PostgreSQL trust authentication in $hba — no password required"
            grep "\btrust\b" "$hba" | grep -v "^#"
            log_incident "DB TRUST AUTH" "$hba"
        fi
    done
fi

# ============================================================
# SECTION 5: EMAIL SERVER SECURITY (open relay check)
# Open relay = red team uses your mail server to exfil data
# or send phishing — costs you business ops points
# ============================================================
section "SECTION 5: EMAIL SERVER AUDIT"

if command -v postfix &>/dev/null || ss -tlnp 2>/dev/null | grep -q ":25 \|:587"; then
    info "Mail server detected. Checking for open relay..."

    # Check Postfix config
    for cfg in /etc/postfix/main.cf; do
        [ ! -f "$cfg" ] && continue

        info "Postfix main.cf key settings:"
        grep -E "^mynetworks|^relay_domains|^smtpd_recipient_restrictions|^inet_interfaces" "$cfg" 2>/dev/null

        # Open relay indicators
        mynetworks=$(grep "^mynetworks" "$cfg" 2>/dev/null)
        if echo "$mynetworks" | grep -q "0.0.0.0/0\|all"; then
            alert "OPEN RELAY: mynetworks allows all hosts: $mynetworks"
            log_incident "OPEN MAIL RELAY" "$mynetworks"
        fi

        inet=$(grep "^inet_interfaces" "$cfg" 2>/dev/null)
        if echo "$inet" | grep -q "^inet_interfaces = all"; then
            warn "Postfix listening on all interfaces: $inet"
        fi
    done

    # Check mail queue for suspicious volume
    if command -v mailq &>/dev/null; then
        queue_size=$(mailq 2>/dev/null | tail -1)
        info "Mail queue: $queue_size"
        queue_count=$(mailq 2>/dev/null | grep -c "^[A-Z0-9]" 2>/dev/null)
        if [ "$queue_count" -gt 50 ]; then
            alert "Large mail queue: $queue_count messages — possible spam relay or exfil"
            log_incident "LARGE MAIL QUEUE" "$queue_count messages queued"
        fi
    fi
fi

# ============================================================
# SECTION 6: SENSITIVE FILE EXPOSURE CHECK
# Checks if critical files are accessible from the web root
# ============================================================
section "SECTION 6: SENSITIVE FILE EXPOSURE"

SENSITIVE_PATTERNS=(
    ".git" ".svn" ".env" "wp-config.php" "config.php"
    ".htpasswd" "database.yml" "settings.py" "web.config"
    "backup" ".sql" ".bak" ".old" ".orig" "passwd" "shadow"
    "id_rsa" "id_dsa" ".pem" ".key" "secret"
)

for webroot_pattern in "${WEB_ROOTS[@]}"; do
    for webroot in $webroot_pattern; do
        [ ! -d "$webroot" ] && continue

        for pattern in "${SENSITIVE_PATTERNS[@]}"; do
            found=$(find "$webroot" -iname "*${pattern}*" 2>/dev/null)
            if [ -n "$found" ]; then
                alert "SENSITIVE FILE/DIR IN WEB ROOT: $found"
                log_incident "SENSITIVE FILE EXPOSED" "$found in $webroot"
            fi
        done
    done
done

section "WEB AUDIT COMPLETE"
echo -e "${GRN}Log: $LOGFILE${NC}"
