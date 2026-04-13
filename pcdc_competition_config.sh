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
# TRUSTED INFRASTRUCTURE HOST LIST
# Pre-populated into network enumeration as "known" hosts so
# they don't trigger "unaccounted host" alerts.
# ============================================================
COMP_TRUSTED_HOSTS=(
    "$SCORING_ENGINE_IP"
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
