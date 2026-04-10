#!/bin/bash
# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Container Build & Run Helper
#
#  Usage:
#    bash container_run.sh build    ← build the image
#    bash container_run.sh run      ← run interactively
#    bash container_run.sh attach   ← attach to running container
#    bash container_run.sh status   ← check container status
#    bash container_run.sh clean    ← remove container and image
#    bash container_run.sh logs     ← view container logs
# ============================================================

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

IMAGE_NAME="astra9-blueteam"
CONTAINER_NAME="astra9_admin"

ok()   { echo -e "${GRN}[OK]${NC}   $1"; }
info() { echo -e "${BLU}[INFO]${NC} $1"; }
warn() { echo -e "${YLW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC}  $1"; }

# Check Docker is available
if ! command -v docker &>/dev/null; then
    err "Docker not installed."
    echo "Install: https://docs.docker.com/engine/install/ubuntu/"
    exit 1
fi

case "${1:-run}" in

    # ── Build the image ───────────────────────────────────────
    build)
        info "Building $IMAGE_NAME image..."
        info "This installs all tools — takes 2-3 minutes on first build."
        info "Subsequent builds use cache and are much faster."
        echo ""
        docker build -t "$IMAGE_NAME:latest" . && \
            ok "Image built: $IMAGE_NAME:latest" || \
            { err "Build failed."; exit 1; }
        echo ""
        info "Image size: $(docker image inspect $IMAGE_NAME:latest \
            --format='{{.Size}}' | awk '{printf "%.0f MB\n", $1/1024/1024}')"
        ;;

    # ── Run interactively ─────────────────────────────────────
    run)
        # Stop existing container if running
        docker rm -f "$CONTAINER_NAME" 2>/dev/null

        info "Starting $CONTAINER_NAME..."
        echo ""
        docker run -it \
            --name "$CONTAINER_NAME" \
            --hostname "astra9-admin" \
            --network host \
            --cap-add NET_ADMIN \
            --cap-add NET_RAW \
            --cap-add SYS_PTRACE \
            -v blueteam-keys:/opt/blueTeam/keys \
            -v blueteam-logs:/opt/blueTeam/logs \
            -v blueteam-reports:/opt/blueTeam/reports \
            -v blueteam-config:/opt/blueTeam/config \
            -e TERM=xterm-256color \
            -e COLORTERM=truecolor \
            "$IMAGE_NAME:latest"
        ;;

    # ── Attach to running container ───────────────────────────
    attach)
        if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
            info "Attaching to $CONTAINER_NAME..."
            docker exec -it "$CONTAINER_NAME" /bin/bash --rcfile /root/.bashrc
        else
            warn "$CONTAINER_NAME is not running."
            echo "Start it with: bash container_run.sh run"
        fi
        ;;

    # ── Run in background then attach ─────────────────────────
    start)
        docker rm -f "$CONTAINER_NAME" 2>/dev/null
        info "Starting $CONTAINER_NAME in background..."
        docker run -d \
            --name "$CONTAINER_NAME" \
            --hostname "astra9-admin" \
            --network host \
            --cap-add NET_ADMIN \
            --cap-add NET_RAW \
            --cap-add SYS_PTRACE \
            -v blueteam-keys:/opt/blueTeam/keys \
            -v blueteam-logs:/opt/blueTeam/logs \
            -v blueteam-reports:/opt/blueTeam/reports \
            -v blueteam-config:/opt/blueTeam/config \
            -e TERM=xterm-256color \
            "$IMAGE_NAME:latest" sleep infinity

        ok "$CONTAINER_NAME started"
        info "Attach with: bash container_run.sh attach"
        ;;

    # ── Status ────────────────────────────────────────────────
    status)
        echo ""
        info "Image:"
        docker images "$IMAGE_NAME" 2>/dev/null || echo "  (not built)"
        echo ""
        info "Container:"
        docker ps -a --filter "name=$CONTAINER_NAME" \
            --format "table {{.Names}}\t{{.Status}}\t{{.CreatedAt}}" 2>/dev/null
        echo ""
        info "Volumes:"
        docker volume ls --filter "name=blueteam" 2>/dev/null
        ;;

    # ── View logs ─────────────────────────────────────────────
    logs)
        docker logs -f "$CONTAINER_NAME" 2>/dev/null || \
            warn "Container not running or no logs available."
        ;;

    # ── Clean up everything ───────────────────────────────────
    clean)
        warn "This will remove the container and image."
        warn "Volumes (keys and logs) will be PRESERVED."
        read -rp "Continue? [y/N]: " ans
        [[ ! "$ans" =~ ^[Yy]$ ]] && echo "Cancelled." && exit 0

        docker rm -f "$CONTAINER_NAME" 2>/dev/null && \
            ok "Container removed"
        docker rmi "$IMAGE_NAME:latest" 2>/dev/null && \
            ok "Image removed"
        echo ""
        info "Volumes preserved. To also remove volumes:"
        echo "  docker volume rm blueteam-keys blueteam-logs blueteam-reports blueteam-config"
        ;;

    # ── Export logs from container volume ─────────────────────
    export-logs)
        local dest="${2:-./blueteam-logs-export}"
        mkdir -p "$dest"
        info "Exporting logs to $dest..."
        docker run --rm \
            -v blueteam-logs:/logs:ro \
            -v "$(realpath $dest):/export" \
            ubuntu:22.04 \
            cp -r /logs/. /export/ && \
            ok "Logs exported to $dest"
        ;;

    # ── Rebuild without cache (full fresh build) ──────────────
    rebuild)
        info "Rebuilding without cache..."
        docker build --no-cache -t "$IMAGE_NAME:latest" . && \
            ok "Rebuild complete" || err "Rebuild failed"
        ;;

    *)
        echo ""
        echo -e "${BLU}Astra 9 Blue Team Container Helper${NC}"
        echo ""
        echo "  bash container_run.sh build         Build the image"
        echo "  bash container_run.sh run            Run interactively"
        echo "  bash container_run.sh start          Start in background"
        echo "  bash container_run.sh attach         Attach to running container"
        echo "  bash container_run.sh status         Show image/container/volume status"
        echo "  bash container_run.sh logs           View container logs"
        echo "  bash container_run.sh export-logs    Copy logs to host filesystem"
        echo "  bash container_run.sh rebuild        Full rebuild without cache"
        echo "  bash container_run.sh clean          Remove container and image"
        echo ""
        ;;
esac
