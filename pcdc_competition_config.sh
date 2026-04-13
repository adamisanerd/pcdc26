#!/bin/bash
# ============================================================
#  PCDC 2026 — ASTRA 9 BLUE TEAM
#  Central Competition Configuration
#
#  SOURCE this file — do not run it directly.
#  Each monitoring script sources it automatically when found
#  in the same directory.
#
#  BEFORE COMPETITION: update TEAM_NAME (and optional domain/
#  host/service lists) to match your Blue Team Packet exactly.
# ============================================================

# Guard against direct execution
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "This file must be sourced, not executed directly."
    echo "  source pcdc_competition_config.sh"
    exit 1
fi

# All variables in this file are intentionally used by sourcing scripts.
# shellcheck disable=SC2034

# ============================================================
# TEAM IDENTITY — UPDATE BEFORE COMPETITION
# ============================================================
# Optional numeric team ID (leave empty when your event uses only team/company names)
TEAM_NUMBER=""
# shellcheck disable=SC2034
TEAM_NAME="ASTRA 9"
# Optional: set your internal email/webmail domain if different
# shellcheck disable=SC2034
TEAM_EMAIL_DOMAIN="pcdc.local"

# ============================================================
# NETWORK TOPOLOGY (from Blue Team Packet)
#
# CRITICAL COMPETITION RULES:
#   - You MUST NOT drop/block traffic from OOB_NETWORK
#   - You MUST NOT block the scoring engine
#   - Doing so forfeits scored service points
# ============================================================

# Out-of-band (OOB) management network — Gold Team / White Team / Scoring
# shellcheck disable=SC2034
OOB_NETWORK="192.168.40.0/24"
OOB_PREFIX="192.168.40"          # prefix used for glob matching in trust checks

# Scoring engine — must remain reachable 24/7
SCORING_ENGINE_IP="192.168.20.10"

# ============================================================
# COMPETITION INFRASTRUCTURE URLs
# ============================================================
# shellcheck disable=SC2034
HELPDESK_URL="http://helpdesk.pcdc.local:8065/login"     # Mattermost help desk
# shellcheck disable=SC2034
PASSBOLT_URL="http://192.168.40.111"                     # OOB password vault
# shellcheck disable=SC2034
GOLDTEAM_EMAIL_SERVER_URL="http://192.168.40.13"         # OOB Gold Team email server
# shellcheck disable=SC2034
EMAIL_URL="https://mail.${TEAM_EMAIL_DOMAIN}"    # Webmail for your team
# shellcheck disable=SC2034
PCDC_DOMAIN="pcdc.local"

# ============================================================
# KNOWN DOMAIN ACCOUNTS (Org Chart — from Blue Team Packet)
#
# These are legitimate employee accounts.
# dark.helmet (CEO) is the primary social engineering target —
# any inject claiming to be from this account should be
# validated via the Mattermost help desk before acting on it.
# ============================================================
# shellcheck disable=SC2034
KNOWN_DOMAIN_USERS=(
    "dark.helmet"        # CEO — highest social engineering risk
    "dotmatrix"          # Packet/diagram credential breadcrumb account
    "princess"
    "jeffrey.sanders"
    "ziegler"
    "steven"
    "jordan"
    "sweeney"
)
# shellcheck disable=SC2034
CEO_USER="dark.helmet"
# shellcheck disable=SC2034
CEO_EMAIL="dark.helmet@${TEAM_EMAIL_DOMAIN}"
# shellcheck disable=SC2034
GOLDTEAM_PROTECTED_ACCOUNT="goldteam"                    # Explicitly off-limits account

# ============================================================
# INITIAL CREDENTIAL CANDIDATES (competition breadcrumbs / packet hints)
# Used only for defensive access validation on YOUR OWN hosts.
# Do NOT use against unaccounted hosts, OOB, or other teams.
# ============================================================
# shellcheck disable=SC2034
COMP_CRED_CANDIDATES=(
    "dotmatrix:Assword12345!"
    "dotmatrix:Password12345!"   # common intentional variant
)

# ============================================================
# SCORED SERVICES (from Blue Team Packet service list)
# Update to match exactly what your packet says is scored.
# These are pre-populated into the monitor's service watchlist.
# ============================================================
# shellcheck disable=SC2034
COMP_SCORED_SERVICES=(
    "apache2"      # HTTP web server
    "nginx"        # HTTP web server (alternate)
    "sshd"         # SSH remote access
    "postfix"      # SMTP mail
    "named"        # DNS
    "mysql"        # Database
    "mariadb"      # Database (MariaDB)
    "vsftpd"       # FTP
    "smbd"         # SMB/CIFS
)

# ============================================================
# LIKELY SCORED HOST ROLES (from provided network diagram)
# These are role hints, not authoritative service checks.
# Keep this aligned with packet clarifications from Gold Team.
# ============================================================
# shellcheck disable=SC2034
COMP_LIKELY_SCORED_HOST_ROLES=(
    "domain_controller"
    "workstation"
    "wsus"
    "mail_server"
    "web_server"
    "file_server"
)

# Windows role-based service hints for pcdc_win_monitor.ps1
# shellcheck disable=SC2034
WIN_DC_SCORED_SERVICES=("DNS" "NTDS" "Netlogon" "Kdc" "LanmanServer")
# shellcheck disable=SC2034
WIN_WSUS_SCORED_SERVICES=("WsusService" "W3SVC" "BITS")
# shellcheck disable=SC2034
WIN_WEB_SCORED_SERVICES=("W3SVC")
# shellcheck disable=SC2034
WIN_MAIL_SCORED_SERVICES=("MSExchangeIS" "MSExchangeTransport" "W3SVC" "SMTPSVC")
# shellcheck disable=SC2034
WIN_FILE_SCORED_SERVICES=("LanmanServer")
# shellcheck disable=SC2034
WIN_WORKSTATION_SCORED_SERVICES=("LanmanWorkstation" "Dnscache")

# ============================================================
# TRUSTED INFRASTRUCTURE HOST LIST
# Pre-populated into network enumeration as "known" hosts so
# they don't trigger "unaccounted host" alerts.
# ============================================================
COMP_TRUSTED_HOSTS=(
    "$SCORING_ENGINE_IP"
    "192.168.40.111"   # Passbolt (OOB)
    "192.168.40.13"    # Gold Team Email (OOB)
    # Add static OOB host IPs here as you discover them:
    # "192.168.40.1"   # OOB gateway
    # "192.168.40.10"  # White Team monitor
)

# ============================================================
# TRUST-CHECKING FUNCTIONS
# Sourced into monitoring scripts to suppress noise from
# known-good competition infrastructure.
# ============================================================

# Returns 0 (true) if IP belongs to OOB or scoring infrastructure.
# Per competition rules, connections from these IPs must not be blocked
# and alerts about them should be informational, not threat-level.
is_trusted_infrastructure() {
    local ip="$1"
    [[ -z "$ip" ]] && return 1
    [[ "$ip" == "${OOB_PREFIX}."* ]] && return 0
    [[ "$ip" == "$SCORING_ENGINE_IP" ]] && return 0

    # Explicitly trusted hosts (if defined in COMP_TRUSTED_HOSTS)
    for trusted in "${COMP_TRUSTED_HOSTS[@]}"; do
        [[ "$ip" == "$trusted" ]] && return 0
    done

    return 1
}

# Print an info-level note that an event involves known infrastructure.
# Uses cyan color matching the calling script's palette.
infra_note() {
    echo -e "\033[0;36m[INFO]\033[0m     \033[1;33m[INFRA]\033[0m $1"
}
