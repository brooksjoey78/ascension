#!/bin/bash
# setup-registry.sh - Private Docker Registry for Sophia

set -e

echo "[+] Setting up private Docker registry for Deus Ex Sophia..."

# Create directories
mkdir -p ~/sophia-registry/{auth,certs,data}
cd ~/sophia-registry

# Generate SSL certificates
echo "[+] Generating SSL certificates..."
openssl req -newkey rsa:4096 -nodes -sha256 \
  -keyout certs/domain.key -x509 -days 365 \
  -out certs/domain.crt \
  -subj "/C=XX/ST=Hidden/L=Void/O=Deus Ex Sophia/CN=sophia-registry.local" \
  -addext "subjectAltName=DNS:sophia-registry.local,DNS:localhost"

# Create authentication
echo "[+] Setting up authentication..."
docker run --rm \
  --entrypoint htpasswd \
  httpd:2 -Bbn sophia "$(openssl rand -base64 32)" > auth/htpasswd

# Create Docker Compose for registry
cat > docker-compose.registry.yml << 'EOF'
version: '3.8'

services:
  registry:
    image: registry:2
    container_name: sophia-registry
    restart: unless-stopped
    ports:
      - "5000:5000"
    environment:
      REGISTRY_AUTH: htpasswd
      REGISTRY_AUTH_HTPASSWD_PATH: /auth/htpasswd
      REGISTRY_AUTH_HTPASSWD_REALM: Registry Realm
      REGISTRY_HTTP_TLS_CERTIFICATE: /certs/domain.crt
      REGISTRY_HTTP_TLS_KEY: /certs/domain.key
      REGISTRY_STORAGE_DELETE_ENABLED: "true"
    volumes:
      - ./data:/var/lib/registry
      - ./auth:/auth
      - ./certs:/certs
    networks:
      - registry-net

  registry-ui:
    image: joxit/docker-registry-ui:static
    container_name: registry-ui
    restart: unless-stopped
    ports:
      - "8081:80"
    environment:
      - REGISTRY_TITLE=Deus Ex Sophia Registry
      - REGISTRY_URL=https://sophia-registry:5000
      - DELETE_IMAGES=true
      - SINGLE_REGISTRY=true
    depends_on:
      - registry
    networks:
      - registry-net

networks:
  registry-net:
    driver: bridge
EOF

# Start registry
echo "[+] Starting registry..."
docker-compose -f docker-compose.registry.yml up -d

# Configure Docker daemon
echo "[+] Configuring Docker daemon..."
sudo mkdir -p /etc/docker/certs.d/sophia-registry.local:5000
sudo cp certs/domain.crt /etc/docker/certs.d/sophia-registry.local:5000/ca.crt

# Add to hosts if needed
if ! grep -q "sophia-registry.local" /etc/hosts; then
  echo "127.0.0.1 sophia-registry.local" | sudo tee -a /etc/hosts
fi

# Login to registry
echo "[+] Logging into registry..."
docker login sophia-registry.local:5000 -u sophia -p "$(cat auth/htpasswd | cut -d: -f2)"

# Create push script
cat > push-images.sh << 'EOF'
#!/bin/bash
# push-images.sh - Push Sophia images to private registry

REGISTRY="sophia-registry.local:5000"
VERSION="5.0"

# Tag images
for image in core network matrix dashboard; do
  docker tag deus-ex-sophia/$image:$VERSION $REGISTRY/deus-ex-sophia/$image:$VERSION
  docker tag deus-ex-sophia/$image:$VERSION $REGISTRY/deus-ex-sophia/$image:latest
done

# Push images
for image in core network matrix dashboard; do
  docker push $REGISTRY/deus-ex-sophia/$image:$VERSION
  docker push $REGISTRY/deus-ex-sophia/$image:latest
done

echo "[✓] Images pushed to $REGISTRY"
EOF

chmod +x push-images.sh

echo "[✓] Registry setup complete!"
echo "[*] Registry UI: https://localhost:8081"
echo "[*] Registry endpoint: https://sophia-registry.local:5000"
echo "[*] Username: sophia"
echo "[*] Password: $(cat auth/htpasswd | cut -d: -f2)"
echo ""
echo "To push images: ./push-images.sh"