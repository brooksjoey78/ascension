#!/bin/bash
# deploy-ai-docker.sh - Deus Ex Sophia AI Docker Deployment

set -e

echo "╔═══════════════════════════════════════════════════════╗"
echo "║      Deus Ex Sophia AI Docker Deployment            ║"
echo "╚═══════════════════════════════════════════════════════╝"

# Check if Sophia is already running
if ! docker-compose -f docker-compose.yml ps | grep -q "sophia-core"; then
    echo "[!] Deus Ex