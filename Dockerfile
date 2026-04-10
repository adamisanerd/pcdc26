# ============================================================
#  PCDC 2026 - ASTRA 9 BLUE TEAM
#  Admin Toolkit Container
#
#  PURPOSE:
#  Self-contained environment with all tools and scripts
#  pre-installed. Pull onto any Ubuntu admin machine and
#  you're operational in under two minutes.
#
#  This container runs on YOUR ADMIN MACHINE only.
#  It orchestrates operations on targets via SSH.
#  Target machines never see this container.
#
#  BUILD:
#    docker build -t astra9-blueteam .
#
#  RUN (standard):
#    docker run -it --rm \
#      --network host \
#      -v ~/.ssh:/root/.ssh:ro \
#      -v $(pwd)/blueTeam:/opt/blueTeam \
#      astra9-blueteam
#
#  RUN (with persistent keys and logs):
#    docker run -it \
#      --network host \
#      --name astra9 \
#      -v blueteam-keys:/opt/blueTeam/keys \
#      -v blueteam-logs:/opt/blueTeam/logs \
#      astra9-blueteam
# ============================================================

FROM ubuntu:22.04

LABEL maintainer="PCDC 2026 Blue Team"
LABEL description="Astra 9 Blue Team Admin Toolkit"
LABEL version="1.0"

# ── Prevent interactive prompts during package install ────────
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/New_York

# ── Working directory ─────────────────────────────────────────
WORKDIR /opt/blueTeam

# ── System packages ───────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # SSH tooling
    openssh-client \
    sshpass \
    # Network tools
    nmap \
    netcat-openbsd \
    iputils-ping \
    iproute2 \
    net-tools \
    tcpdump \
    tshark \
    dnsutils \
    whois \
    curl \
    wget \
    # Terminal multiplexer
    tmux \
    # File/text utilities
    vim \
    nano \
    less \
    jq \
    bc \
    # Process tools
    procps \
    lsof \
    # Security tools
    libcap2-bin \
    chkrootkit \
    # Hash tools
    coreutils \
    # Build essentials (for any compiled deps)
    ca-certificates \
    gnupg \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Directory structure ───────────────────────────────────────
RUN mkdir -p \
    /opt/blueTeam/scripts \
    /opt/blueTeam/keys \
    /opt/blueTeam/logs \
    /opt/blueTeam/reports \
    /root/.ssh

# ── Copy all Blue Team scripts ────────────────────────────────
COPY pcdc_*.sh /opt/blueTeam/scripts/
RUN chmod +x /opt/blueTeam/scripts/*.sh

# ── Copy admin profile with shell functions ───────────────────
# The profile references /opt/blueTeam paths which match our container layout
COPY blueTeam_profile /root/.blueTeam_profile
RUN echo "" >> /root/.bashrc && \
    echo "# PCDC 2026 Blue Team" >> /root/.bashrc && \
    echo "source /root/.blueTeam_profile" >> /root/.bashrc && \
    echo "export PATH=\$PATH:/opt/blueTeam/scripts" >> /root/.bashrc

# ── SSH client hardening ──────────────────────────────────────
RUN mkdir -p /root/.ssh && chmod 700 /root/.ssh
COPY ssh_config /root/.ssh/config
RUN chmod 600 /root/.ssh/config

# ── tmux config for dashboard usability ──────────────────────
COPY tmux.conf /root/.tmux.conf

# ── Entrypoint script ─────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Healthcheck — verifies key tools are available ───────────
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=2 \
    CMD command -v nmap && command -v sshpass && command -v tmux || exit 1

# ── Volumes for persistent data ───────────────────────────────
# Keys: your SSH key pair persists between container runs
# Logs: all output persists between container runs
VOLUME ["/opt/blueTeam/keys", "/opt/blueTeam/logs", "/opt/blueTeam/reports"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash", "--rcfile", "/root/.bashrc"]
