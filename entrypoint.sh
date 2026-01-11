#!/bin/bash
# entrypoint.sh - Deus Ex Sophia Docker Entrypoint

set -e

# Color definitions
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
NC='\033[0m'

log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "ERROR") echo -e "${RED}[✗] $message${NC}" >&2 ;;
        "WARN") echo -e "${YELLOW}[!] $message${NC}" ;;
        "INFO") echo -e "${CYAN}[*] $message${NC}" ;;
        "SUCCESS") echo -e "${GREEN}[✓] $message${NC}" ;;
        *) echo -e "[*] $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> /opt/sysaux/logs/docker.log
}

# Initialize on first run
init_system() {
    if [ ! -f /opt/sysaux/.initialized ]; then
        log "INFO" "First run detected, initializing system..."
        
        # Run initialization script
        /init.sh
        
        # Mark as initialized
        touch /opt/sysaux/.initialized
        log "SUCCESS" "System initialization complete"
    fi
}

# Check for required capabilities
check_capabilities() {
    local missing_caps=()
    
    # Check for NET_ADMIN
    if [ ! -e /proc/sys/net/ipv4/ip_forward ]; then
        missing_caps+=("NET_ADMIN")
    fi
    
    # Check for NET_RAW
    if ! capsh --print | grep -q "cap_net_raw"; then
        missing_caps+=("NET_RAW")
    fi
    
    # Check for SYS_ADMIN
    if ! mount | grep -q "proc on /proc"; then
        missing_caps+=("SYS_ADMIN")
    fi
    
    if [ ${#missing_caps[@]} -gt 0 ]; then
        log "WARN" "Missing capabilities: ${missing_caps[*]}"
        log "WARN" "Run with: --cap-add=${missing_caps[0]} --cap-add=${missing_caps[1]} etc."
        return 1
    fi
    
    return 0
}

# Setup networking
setup_networking() {
    log "INFO" "Setting up networking..."
    
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    
    # Setup iptables
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    
    # Default policies
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Save rules
    iptables-save > /etc/iptables/rules.v4
    
    log "SUCCESS" "Networking setup complete"
}

# Start system services
start_services() {
    log "INFO" "Starting system services..."
    
    # Start systemd (minimal)
    if [ -x /bin/systemctl ]; then
        /bin/systemctl start systemd-networkd
        /bin/systemctl start systemd-resolved
    fi
    
    # Start cron
    if [ -x /usr/sbin/cron ]; then
        /usr/sbin/cron
    fi
    
    # Start SSH if configured
    if [ -f /etc/ssh/sshd_config ] && [ "${ENABLE_SSH:-false}" = "true" ]; then
        /usr/sbin/sshd -D &
        log "INFO" "SSH started"
    fi
    
    log "SUCCESS" "Services started"
}

# Start Sophia services
start_sophia_services() {
    log "INFO" "Starting Deus Ex Sophia services..."
    
    # Start core service
    if [ -f /etc/systemd/system/systemd-networkd-helper.service ]; then
        systemctl start systemd-networkd-helper.service
    else
        # Fallback to direct start
        cd /opt/sysaux
        python3 -c "import sys; sys.path.insert(0, '/opt/sysaux/bin'); from core_truth import EnhancedTruthCore; core = EnhancedTruthCore()" &
    fi
    
    # Start network oracle if enabled
    if [ "${SOPHIA_NETWORK_ENABLED:-true}" = "true" ]; then
        systemctl start network-oracle.service 2>/dev/null || \
        network_oracle start-all &
    fi
    
    # Start matrix orchestrator if enabled
    if [ "${SOPHIA_MATRIX_ENABLED:-true}" = "true" ]; then
        systemctl start matrix-orchestrator.service 2>/dev/null || \
        matrix_orchestrator start-all &
    fi
    
    log "SUCCESS" "Sophia services started"
}

# Start web dashboard
start_dashboard() {
    if [ "${ENABLE_DASHBOARD:-true}" = "true" ]; then
        log "INFO" "Starting web dashboard..."
        
        # Create dashboard directory
        mkdir -p /opt/sysaux/dashboard
        
        # Generate dashboard HTML
        cat > /opt/sysaux/dashboard/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Deus Ex Sophia Dashboard</title>
    <style>
        body { 
            font-family: 'Courier New', monospace; 
            margin: 0; 
            padding: 20px; 
            background: #0a0a0a; 
            color: #00ff00; 
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .status-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .status-card { background: #111; border: 1px solid #333; padding: 20px; border-radius: 5px; }
        .status-card h3 { margin-top: 0; color: #00ffff; }
        .status-item { margin: 10px 0; }
        .status-good { color: #00ff00; }
        .status-warn { color: #ffff00; }
        .status-bad { color: #ff0000; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Deus Ex Sophia Dashboard</h1>
            <p>Advanced Intelligence & Exfiltration System v5.0</p>
        </div>
        
        <div class="status-grid">
            <div class="status-card">
                <h3>System Status</h3>
                <div id="system-status">Loading...</div>
            </div>
            
            <div class="status-card">
                <h3>Network Intelligence</h3>
                <div id="network-status">Loading...</div>
            </div>
            
            <div class="status-card">
                <h3>Exfiltration Matrix</h3>
                <div id="matrix-status">Loading...</div>
            </div>
            
            <div class="status-card">
                <h3>Quick Actions</h3>
                <button onclick="fetch('/api/status')">Refresh Status</button>
                <button onclick="fetch('/api/backup')">Create Backup</button>
                <button onclick="fetch('/api/scan')">Network Scan</button>
            </div>
        </div>
    </div>
    
    <script>
        async function updateStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();
                
                document.getElementById('system-status').innerHTML = `
                    <div class="status-item">CPU: <span class="status-good">${data.cpu}%</span></div>
                    <div class="status-item">Memory: <span class="status-good">${data.memory}%</span></div>
                    <div class="status-item">Uptime: <span class="status-good">${data.uptime}</span></div>
                    <div class="status-item">Services: <span class="status-good">${data.services}/3 active</span></div>
                `;
                
                document.getElementById('network-status').innerHTML = `
                    <div class="status-item">Hosts: <span class="status-good">${data.hosts}</span></div>
                    <div class="status-item">Threats: <span class="status-warn">${data.threats}</span></div>
                    <div class="status-item">Last Scan: <span class="status-good">${data.last_scan}</span></div>
                `;
                
                document.getElementById('matrix-status').innerHTML = `
                    <div class="status-item">Encryption: <span class="status-good">Active</span></div>
                    <div class="status-item">Channels: <span class="status-good">${data.channels}</span></div>
                    <div class="status-item">Last Exfil: <span class="status-good">${data.last_exfil}</span></div>
                `;
            } catch (error) {
                console.error('Error updating status:', error);
            }
        }
        
        // Update every 10 seconds
        setInterval(updateStatus, 10000);
        updateStatus();
    </script>
</body>
</html>
EOF
        
        # Start simple HTTP server
        cd /opt/sysaux/dashboard
        python3 -m http.server 8080 &
        
        log "SUCCESS" "Dashboard available at http://localhost:8080"
    fi
}

# Main execution
main() {
    log "INFO" "Deus Ex Sophia v5.0 Container Starting..."
    log "INFO" "Environment: ${SOPHIA_ENV}"
    log "INFO" "Stealth Level: ${SOPHIA_STEALTH_LEVEL}"
    
    # Check capabilities
    check_capabilities || log "WARN" "Proceeding with limited capabilities"
    
    # Initialize system
    init_system
    
    # Setup networking
    setup_networking
    
    # Start services
    start_services
    
    # Start Sophia services
    if [ "${SOPHIA_AUTO_START:-true}" = "true" ]; then
        start_sophia_services
    fi
    
    # Start dashboard
    start_dashboard
    
    log "SUCCESS" "Deus Ex Sophia container fully initialized"
    log "INFO" "Use 'docker exec -it <container> ascend' for CLI access"
    
    # If command provided, execute it
    if [ $# -gt 0 ]; then
        log "INFO" "Executing command: $*"
        exec "$@"
    fi
    
    # Otherwise, keep container running
    log "INFO" "Container running, waiting for signals..."
    tail -f /opt/sysaux/logs/docker.log
}

# Handle signals
trap 'log "INFO" "Received SIGTERM, shutting down..."; exit 0' SIGTERM
trap 'log "INFO" "Received SIGINT, shutting down..."; exit 0' SIGINT

# Run main function
main "$@"