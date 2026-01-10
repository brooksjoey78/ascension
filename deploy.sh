#!/bin/bash
# deploy.sh - Deus Ex Sophia Quick Deployment for Ubuntu on WINDOWS

set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║         Deus Ex Sophia Quick Deploy v5.0            ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker not found. Please install Docker Desktop on Windows first."
    exit 1
fi

# Check for Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "[!] Docker Compose not found. Installing..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

# Create deployment directory
mkdir -p ~/sophia-deploy && cd ~/sophia-deploy

# Download minimal docker-compose
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  sophia:
    image: deusexsophia/ascension:latest
    container_name: deus-ex-sophia
    restart: unless-stopped
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_ADMIN
    ports:
      - "8080:8080"
      - "8443:8443"
      - "53:53/udp"
      - "53:53/tcp"
      - "2222:22"
    volumes:
      - sophia-data:/opt/sysaux
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - SOPHIA_ENV=production
      - SOPHIA_STEALTH_LEVEL=9
      - SOPHIA_AUTO_START=true

volumes:
  sophia-data:
EOF

# Pull and start
echo "[+] Pulling image..."
docker-compose pull

echo "[+] Starting container..."
docker-compose up -d

# Wait for initialization
echo "[+] Waiting for initialization (30 seconds)..."
sleep 30

# Display information
echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║                 Deployment Complete                  ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "📊 Dashboard:  http://localhost:8080"
echo "🔐 HTTPS:      https://localhost:8443"
echo "🌐 DNS:        Listening on port 53 (UDP/TCP)"
echo "🔧 SSH:        ssh root@localhost -p 2222"
echo "               Password: ascension"
echo ""
echo "🛠️  Management Commands:"
echo "   docker-compose logs -f      # View logs"
echo "   docker-compose restart      # Restart"
echo "   docker-compose down         # Stop"
echo ""
echo "🎮 Interactive Access:"
echo "   docker exec -it deus-ex-sophia ascend"
echo "   docker exec -it deus-ex-sophia network_oracle"
echo "   docker exec -it deus-ex-sophia matrix_orchestrator"
echo ""
echo "📁 Data Location: ~/sophia-deploy/"
echo ""
echo "[✓] Deus Ex Sophia is now active on Windows 11 Docker."