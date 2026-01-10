# Deus Ex Sophia - Full Ascension System v5.0
# Base: Ubuntu 22.04 with minimal footprint, optimized for Windows 11 Docker Desktop

FROM ubuntu:22.04 AS builder

# Set environment for non-interactive installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC
ENV SOPHIA_VERSION=5.0
ARG SOPHIA_BUILD_DATE
ENV SOPHIA_BUILD=${SOPHIA_BUILD_DATE}

# Build arguments for customization
ARG SOPHIA_STEALTH_LEVEL=9
ARG SOPHIA_EXFIL_CHANNELS="dns,https,icmp"
ARG SOPHIA_NETWORK_MONITOR="all"

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    gnupg2 \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Add Python repository
RUN add-apt-repository ppa:deadsnakes/ppa

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core system
    python3.10 \
    python3.10-dev \
    python3.10-venv \
    python3-pip \
    python3-setuptools \
    python3-wheel \
    \
    # Network tools
    net-tools \
    iproute2 \
    iputils-ping \
    dnsutils \
    nmap \
    tcpdump \
    netcat-openbsd \
    socat \
    iptables \
    iptables-persistent \
    \
    # Security & crypto
    openssl \
    libssl-dev \
    libffi-dev \
    libsodium-dev \
    gnupg2 \
    gpg \
    gpg-agent \
    \
    # Utilities
    jq \
    sqlite3 \
    git \
    tar \
    gzip \
    bzip2 \
    xz-utils \
    p7zip-full \
    unzip \
    zip \
    \
    # Build tools
    build-essential \
    pkg-config \
    autoconf \
    automake \
    libtool \
    make \
    gcc \
    g++ \
    \
    # System tools
    cron \
    anacron \
    systemd \
    systemd-sysv \
    dbus \
    \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/*

# Create Python virtual environment
RUN python3.10 -m venv /opt/sophia-venv --system-site-packages
ENV PATH="/opt/sophia-venv/bin:$PATH"

# Install Python packages from requirements (will be provided in build context)
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --upgrade pip setuptools wheel \
    && pip3 install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# Create system structure
RUN mkdir -p /opt/sysaux/{bin,modules,data,logs,config,backups,.network,.matrix} \
    && mkdir -p /opt/sysaux/.network/{passive,active,threat,visual,data,logs,config} \
    && mkdir -p /opt/sysaux/.matrix/{core,channels,payloads,handlers,exfil,stealth,keys,temp} \
    && mkdir -p /usr/local/lib/.systemd-aux/{beacons,tunnels,exfil,cache,backups} \
    && mkdir -p /var/lib/.matrix/{cache,transit,temp,archive} \
    && mkdir -p /etc/sophia/{systemd,cron,network,ssh}

# Set permissions
RUN chmod -R 700 /opt/sysaux \
    && chmod -R 700 /usr/local/lib/.systemd-aux \
    && chmod -R 700 /var/lib/.matrix \
    && chmod -R 700 /etc/sophia

# Create sophia user (non-root for some operations)
RUN useradd -r -s /bin/false -d /opt/sysaux sophia \
    && usermod -a -G shadow,ssl-cert,syslog sophia \
    && chown -R sophia:sophia /opt/sysaux/data \
    && chown -R sophia:sophia /opt/sysaux/logs

# Copy phase scripts (these will be executed by entrypoint.sh)
COPY --chown=root:root phases/*.sh /opt/sysaux/
RUN chmod +x /opt/sysaux/*.sh || true

# Copy system files (to be added in build context)
COPY --chown=root:root scripts/ /opt/sysaux/bin/
RUN mkdir -p /etc/sophia

# Make scripts executable
RUN chmod +x /opt/sysaux/bin/* || true \
    && chmod +x /opt/sysaux/*.py || true

# Create symlinks (only if binaries exist)
RUN [ -f /opt/sysaux/bin/ascend ] && ln -sf /opt/sysaux/bin/ascend /usr/local/bin/ascend || true
RUN [ -f /opt/sysaux/bin/network_oracle ] && ln -sf /opt/sysaux/bin/network_oracle /usr/local/bin/network_oracle || true
RUN [ -f /opt/sysaux/bin/matrix_orchestrator ] && ln -sf /opt/sysaux/bin/matrix_orchestrator /usr/local/bin/matrix_orchestrator || true
RUN [ -f /opt/sysaux/bin/system-optimize ] && ln -sf /opt/sysaux/bin/system-optimize /usr/local/bin/system-optimize || true

# Create directories
RUN mkdir -p /etc/systemd/system /etc/cron.d /etc/ssh /etc/network /root/.ssh && chmod 700 /root/.ssh

# Build stage complete
FROM builder AS final

# Remove build-only packages
RUN apt-get remove -y \
    build-essential \
    pkg-config \
    autoconf \
    automake \
    libtool \
    gcc \
    g++ \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create volumes
VOLUME ["/opt/sysaux/data", "/opt/sysaux/logs", "/opt/sysaux/backups", "/usr/local/lib/.systemd-aux"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5m --retries=3 \
    CMD /opt/sysaux/bin/resilience.sh check || exit 1

EXPOSE 8080
EXPOSE 8443
EXPOSE 53/udp
EXPOSE 53/tcp
EXPOSE 22
EXPOSE 9050

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Copy initialization script
COPY init.sh /init.sh
RUN chmod +x /init.sh

# Environment variables
ENV SOPHIA_ENV="docker"
ENV SOPHIA_CONTAINER="true"
ENV SOPHIA_AUTO_START="true"
ENV SOPHIA_STEALTH_LEVEL=${SOPHIA_STEALTH_LEVEL}
ENV SOPHIA_EXFIL_CHANNELS=${SOPHIA_EXFIL_CHANNELS}
ENV SOPHIA_NETWORK_MONITOR=${SOPHIA_NETWORK_MONITOR}
ENV SOPHIA_DEBUG="false"
ENV SOPHIA_LOG_LEVEL="info"

# Labels
LABEL org.label-schema.name="Deus Ex Sophia"
LABEL org.label-schema.description="Advanced Intelligence and Exfiltration System"
LABEL org.label-schema.version="${SOPHIA_VERSION}"
LABEL org.label-schema.build-date="${SOPHIA_BUILD}"
LABEL org.label-schema.vcs-url="https://github.com/deus-ex-sophia/ascension"
LABEL org.label-schema.docker.schema-version="1.0"

# Entrypoint
ENTRYPOINT ["/entrypoint.sh"]

# Default command
CMD ["ascend", "dashboard"]