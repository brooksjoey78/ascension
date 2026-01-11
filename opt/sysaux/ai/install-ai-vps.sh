#!/bin/bash
# install-ai-vps.sh - Deus Ex Sophia AI Agent Installation

set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║        Deus Ex Sophia AI Agent Installation         ║"
echo "╚═══════════════════════════════════════════════════════╝"

# Configuration
AI_DIR="/opt/sysaux/ai"
MODELS_DIR="$AI_DIR/models"
KNOWLEDGE_DIR="$AI_DIR/knowledge"
LOGS_DIR="$AI_DIR/logs"

# Create directory structure
echo "[+] Creating directory structure..."
mkdir -p $AI_DIR/{models,knowledge,logs,config,sandbox,tmp}
mkdir -p $MODELS_DIR
mkdir -p $KNOWLEDGE_DIR/{system,threats,code,conversations}
mkdir -p $LOGS_DIR/{commands,code_execution,errors}

# Install dependencies
echo "[+] Installing AI dependencies..."
apt-get update && apt-get install -y \
    python3.10 python3.10-dev python3.10-venv \
    build-essential cmake git curl wget \
    libopenblas-dev libomp-dev libatomic1 \
    python3-pip python3-setuptools \
    ffmpeg libsm6 libxext6  # For voice/vision

# Create Python virtual environment
echo "[+] Setting up Python environment..."
python3.10 -m venv $AI_DIR/venv
source $AI_DIR/venv/bin/activate

# Install Python packages
cat > $AI_DIR/requirements.txt << 'EOF'
# AI/ML
llama-cpp-python>=0.2.0
sentence-transformers>=2.2.0
chromadb>=0.4.0
langchain>=0.0.300
transformers>=4.35.0
torch>=2.1.0
torchaudio>=2.1.0
torchvision>=0.16.0

# System integration
psutil>=5.9.0
watchgod>=0.8.0
pyinotify>=0.9.6
python-prctl>=1.8.1
docker>=6.1.0
kubernetes>=26.1.0

# Communication
websockets>=12.0
fastapi>=0.104.0
uvicorn>=0.24.0
python-socketio>=5.10.0
python-jose>=3.3.0
passlib>=1.7.4

# Security
cryptography>=41.0.0
pyjwt>=2.8.0
bcrypt>=4.0.0

# Utilities
rich>=13.0.0
typer>=0.9.0
prompt-toolkit>=3.0.0
pygments>=2.16.0
orjson>=3.9.0
msgpack>=1.0.0
EOF

pip install --upgrade pip
pip install -r $AI_DIR/requirements.txt

# Download AI models
echo "[+] Downloading AI models..."
cd $MODELS_DIR

# Download Llama 2 13B (quantized)
echo "[+] Downloading Llama 2 13B..."
curl -L "https://huggingface.co/TheBloke/Llama-2-13B-GGUF/resolve/main/llama-2-13b.Q4_K_M.gguf" \
    -o llama-2-13b.Q4_K_M.gguf

# Download embedding model
echo "[+] Downloading embedding model..."
curl -L "https://huggingface.co/sentence-transformers/all-MiniLM-L12-v2/resolve/main/pytorch_model.bin" \
    -o all-MiniLM-L12-v2.bin

# Download TTS model
echo "[+] Downloading TTS model..."
curl -L "https://huggingface.co/coqui/XTTS-v2/resolve/main/model.pth" \
    -o tts.pth

# Copy AI code from Sophia system
echo "[+] Installing AI core..."
cp -r /path/to/sophia-ai/* $AI_DIR/

# Create systemd service
echo "[+] Creating systemd service..."
cat > /etc/systemd/system/sophia-ai.service << 'EOF'
[Unit]
Description=Deus Ex Sophia AI Agent
After=network.target systemd-networkd-helper.service
Wants=network.target
PartOf=systemd-networkd.service

[Service]
Type=exec
User=root
Group=root
WorkingDirectory=/opt/sysaux/ai
Environment="PATH=/opt/sysaux/ai/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=/opt/sysaux/ai"
ExecStart=/opt/sysaux/ai/venv/bin/python /opt/sysaux/ai/main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sophia-ai

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/opt/sysaux/ai /opt/sysaux/logs
InaccessiblePaths=/home /root/.ssh

# Resource limits
MemoryMax=4G
CPUQuota=80%
IOWeight=100

[Install]
WantedBy=multi-user.target
Also=systemd-networkd-helper.service
EOF

# Create configuration
echo "[+] Creating AI configuration..."
cat > $AI_DIR/config/ai.json << 'EOF'
{
    "version": "1.0",
    "model": {
        "llm": "llama-2-13b.Q4_K_M.gguf",
        "embedding": "all-MiniLM-L12-v2",
        "tts": "tts.pth",
        "context_window": 131072,
        "temperature": 0.7,
        "max_tokens": 4096
    },
    "system": {
        "monitoring_interval": 5,
        "snapshot_interval": 60,
        "max_command_history": 1000,
        "sandbox_timeout": 60,
        "require_confirmation": ["destructive", "network", "persistence"]
    },
    "security": {
        "jwt_secret": "$(openssl rand -hex 32)",
        "api_key": "$(openssl rand -hex 16)",
        "allowed_ips": ["127.0.0.1", "::1"],
        "rate_limit": {"per_minute": 30, "per_hour": 1000},
        "audit_logging": true
    },
    "integration": {
        "phases": [1, 2, 3, 4, 5],
        "network_oracle": true,
        "matrix_orchestrator": true,
        "threat_intelligence": true,
        "exfiltration": true
    },
    "communication": {
        "websocket_port": 8765,
        "api_port": 8080,
        "voice_enabled": true,
        "notifications": ["websocket", "log"]
    }
}
EOF

# Generate encryption keys for AI
echo "[+] Generating encryption keys..."
openssl genrsa -out $AI_DIR/config/private.pem 4096
openssl rsa -in $AI_DIR/config/private.pem -outform PEM -pubout -out $AI_DIR/config/public.pem

# Set permissions
echo "[+] Setting permissions..."
chown -R root:root $AI_DIR
chmod -R 700 $AI_DIR
chmod 600 $AI_DIR/config/*.pem
chmod 644 $AI_DIR/config/ai.json

# Initialize knowledge base
echo "[+] Initializing knowledge base..."
cat > $KNOWLEDGE_DIR/system/architecture.md << 'EOF'
# Deus Ex Sophia System Architecture

## Phase 1: Environment Sanitization
- Root verification and system cleanup
- Secure kernel parameters
- Telemetry removal

## Phase 2: Core Installation with Truth
- Hidden directory structure
- Quantum encryption layer
- Adaptive beaconing

## Phase 3: Multi-Vector Persistence
- Systemd service camouflage
- Hidden cron jobs
- Initramfs integration
- Process hiding techniques

## Phase 4: Network Intelligence
- Passive monitoring (raw sockets)
- Active reconnaissance
- Threat intelligence database

## Phase 5: Exfiltration Matrix
- Multi-channel exfiltration
- Steganography and dead drops
- Quantum-resistant encryption
EOF

# Start AI service
echo "[+] Starting AI service..."
systemctl daemon-reload
systemctl enable sophia-ai.service
systemctl start sophia-ai.service

# Wait for initialization
echo "[+] Waiting for AI initialization..."
sleep 10

# Check status
if systemctl is-active --quiet sophia-ai.service; then
    echo "[✓] AI agent is running"
    
    # Get initial status
    curl -s http://localhost:8080/api/v1/ai/status | jq .
    
    echo ""
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║              AI Agent Ready                         ║"
    echo "╚═══════════════════════════════════════════════════════╝"
    echo ""
    echo "🌐 Web Dashboard:  http://localhost:8080/ai"
    echo "🔌 WebSocket:      ws://localhost:8765/ws/ai/terminal"
    echo "📡 API:            http://localhost:8080/api/v1/ai/*"
    echo "🎤 Voice:          Available on port 8080"
    echo ""
    echo "💬 Example query:"
    echo "  curl -X POST http://localhost:8080/api/v1/ai/query \\"
    echo "    -H 'Content-Type: application/json' \\"
    echo "    -d '{\"query\":\"Show me current network threats\"}'"
    echo ""
    echo "🛠️  Management:"
    echo "  sudo systemctl status sophia-ai"
    echo "  sudo journalctl -u sophia-ai -f"
    echo "  sudo sophia-ai-cli --help"
else
    echo "[✗] AI agent failed to start"
    journalctl -u sophia-ai -n 50 --no-pager
    exit 1
fi

echo "[✓] Deus Ex Sophia AI Agent installation complete!"