@echo off
echo Deus Ex Sophia Deployment for Windows 11
echo ========================================

REM Check if Docker is running
docker version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not running. Please start Docker Desktop.
    pause
    exit /b 1
)

REM Create directories
if not exist "C:\sophia" mkdir C:\sophia
cd /d C:\sophia

REM Pull the image
echo [*] Pulling Deus Ex Sophia image...
docker pull deusexsophia/ascension:latest

REM Create docker-compose.yml
echo [*] Creating docker-compose.yml...
(
echo version: '3.8'
echo.
echo services:
echo   sophia:
echo     image: deusexsophia/ascension:latest
echo     container_name: deus-ex-sophia
echo     restart: unless-stopped
echo     privileged: true
echo     cap_add:
echo       - NET_ADMIN
echo       - NET_RAW
echo       - SYS_ADMIN
echo     ports:
echo       - "8080:8080"
echo       - "8443:8443"
echo       - "53:53/udp"
echo       - "53:53/tcp"
echo       - "2222:22"
echo     volumes:
echo       - sophia-data:/opt/sysaux
echo       - //var/run/docker.sock:/var/run/docker.sock
echo     environment:
echo       - SOPHIA_ENV=windows
echo       - SOPHIA_STEALTH_LEVEL=9
echo.
echo volumes:
echo   sophia-data:
) > docker-compose.yml

REM Start the container
echo [*] Starting Deus Ex Sophia...
docker-compose up -d

REM Wait for initialization
echo [*] Waiting for system to initialize...
timeout /t 30 /nobreak >nul

REM Show status
echo [*] Deployment complete!
echo.
echo Dashboard: http://localhost:8080
echo HTTPS: https://localhost:8443 (accept self-signed cert)
echo SSH: ssh root@localhost -p 2222 (password: ascension)
echo.
echo To access container: docker exec -it deus-ex-sophia ascend
echo.
pause