# setup.ps1 - Deus Ex Sophia Windows 11 Docker Setup

Write-Host "Deus Ex Sophia Windows 11 Docker Setup" -ForegroundColor Cyan
Write-Host "=========================================="

# Check Docker Desktop
try {
    docker version 2>&1 | Out-Null
    Write-Host "[✓] Docker Desktop is running" -ForegroundColor Green
} catch {
    Write-Host "[!] Docker Desktop is not running. Please start it." -ForegroundColor Red
    exit 1
}

# Create directory
$sophiaDir = "C:\DeusExSophia"
if (-not (Test-Path $sophiaDir)) {
    New-Item -ItemType Directory -Path $sophiaDir | Out-Null
}
Set-Location $sophiaDir

# Create docker-compose.yml
@'
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
      - //var/run/docker.sock:/var/run/docker.sock
    environment:
      - SOPHIA_ENV=windows
      - SOPHIA_STEALTH_LEVEL=9
      - SOPHIA_AUTO_START=true

volumes:
  sophia-data:
'@ | Out-File -FilePath "docker-compose.yml" -Encoding UTF8

Write-Host "[*] Created docker-compose.yml" -ForegroundColor Yellow

# Pull and start
Write-Host "[*] Pulling Deus Ex Sophia image..." -ForegroundColor Yellow
docker-compose pull

Write-Host "[*] Starting container..." -ForegroundColor Yellow
docker-compose up -d

Start-Sleep -Seconds 30

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║                 Deployment Complete                  ║" -ForegroundColor Magenta
Write-Host "╚═══════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""
Write-Host "📊 Dashboard:  http://localhost:8080" -ForegroundColor Cyan
Write-Host "🔐 HTTPS:      https://localhost:8443" -ForegroundColor Cyan
Write-Host "🌐 DNS:        Port 53 (UDP/TCP)" -ForegroundColor Cyan
Write-Host "🔧 SSH:        ssh root@localhost -p 2222" -ForegroundColor Cyan
Write-Host "               Password: ascension" -ForegroundColor Cyan
Write-Host ""
Write-Host "🎮 Commands:" -ForegroundColor Green
Write-Host "   docker-compose logs -f" -ForegroundColor White
Write-Host "   docker exec -it deus-ex-sophia ascend" -ForegroundColor White
Write-Host ""
Write-Host "[✓] Deus Ex Sophia is now active on Windows 11" -ForegroundColor Green