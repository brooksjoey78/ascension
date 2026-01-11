#!/bin/bash
# quick-deploy.sh - One-Command Sophia Deployment

# This script downloads and deploys Deus Ex Sophia in one command
# Usage: curl -sL https://sophia.local/deploy | bash

set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║         Deus Ex Sophia Quick Deploy v5.0            ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "[!] Docker not found. Installing..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
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

# Download Docker Compose file
echo "[+] Downloading configuration..."
curl -sL https://raw.githubusercontent.com/deus-ex-sophia/ascension/main/docker-compose.quick.yml \
    -o docker-compose.yml

# Download images
echo "[+] Pulling images..."
docker-compose pull

# Start services
echo "[+] Starting services..."
docker-compose up -d

# Wait for initialization
echo "[+] Waiting for initialization..."
sleep 30

# Check status
echo "[+] Checking status..."
docker-compose ps

# Display information
echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║                 Deployment Complete                  ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "📊 Dashboard:  http://localhost:8080"
echo "🔐 HTTPS:      https://localhost:8443 (self-signed)"
echo "🌐 Network:    Monitoring active on all interfaces"
echo "🚀 Matrix:     Exfiltration system ready"
echo ""
echo "🛠️  Management Commands:"
echo "   docker-compose logs -f      # View logs"
echo "   docker-compose restart      # Restart services"
echo "   docker-compose down         # Stop services"
echo ""
echo "🎮 Interactive Access:"
echo "   docker exec -it sophia-core ascend"
echo "   docker exec -it sophia-core network_oracle dashboard"
echo "   docker exec -it sophia-core matrix_orchestrator dashboard"
echo ""
echo "📁 Data Location: ~/sophia-deploy/"
echo ""
echo "⚠️  Warning: This is a research system. Use responsibly."
echo ""
echo "[✓] Deus Ex Sophia is now active."