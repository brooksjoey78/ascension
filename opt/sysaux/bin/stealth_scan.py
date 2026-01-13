# Create stealth nmap wrapper
cat > /opt/sysaux/bin/stealth_scan.py << 'STEALTH_SCAN'
#!/usr/bin/env python3
# Stealth nmap wrapper with randomized fingerprints
import os
import sys
import time
import random
import subprocess
import tempfile
from datetime import datetime

def randomize_scan():
    """Generate randomized nmap arguments"""
    scan_types = ['-sS', '-sT', '-sA', '-sW', '-sM']
    timing_templates = ['-T0', '-T1', '-T2', '-T3', '-T4', '-T5']
    decoys = []
    
    # Generate random decoy IPs
    for _ in range(random.randint(1, 3)):
        decoys.append(str(random.randint(1, 254)))
    
    # Randomize source port
    src_port = random.randint(1024, 65535)
    
    # Fragment packets
    fragment = '-f' if random.choice([True, False]) else ''
    
    # Randomize scan delay
    scan_delay = f'--scan-delay {random.randint(100, 5000)}ms'
    
    # Randomize MTU
    mtu = f'--mtu {random.choice([16, 24, 32])}'
    
    # Build command
    cmd = [
        'nmap',
        random.choice(scan_types),
        random.choice(timing_templates),
        fragment,
        mtu,
        f'--source-port {src_port}',
        scan_delay,
        '--data-length', str(random.randint(1, 100)),
        '--ttl', str(random.randint(32, 255)),
        '--spoof-mac', random.choice(['0', 'Cisco', 'Apple', 'Dell']),
        '--badsum' if random.random() > 0.7 else '',
        '-n',  # No DNS resolution
        '-v0',  # Minimal verbosity
        '--max-retries', str(random.randint(1, 3)),
        '--max-rate', str(random.randint(10, 100)),
        '--min-rate', str(random.randint(1, 10)),
    ]
    
    # Filter out empty strings
    cmd = [c for c in cmd if c]
    
    return cmd

def stealth_scan(target, ports="1-1000"):
    """Perform stealth scan with random fingerprint"""
    base_cmd = randomize_scan()
    base_cmd.extend(['-p', ports, target])
    
    # Execute with random delay
    time.sleep(random.uniform(0.1, 5.0))
    
    try:
        result = subprocess.run(
            base_cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        # Parse output
        return parse_nmap_output(result.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout"}
    except Exception as e:
        return {"error": str(e)}

def parse_nmap_output(output):
    """Parse nmap output without XML dependencies"""
    result = {
        "scan_start": datetime.now().isoformat(),
        "ports": [],
        "hostnames": []
    }
    
    lines = output.split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        
        # Extract hostnames
        if 'Nmap scan report for' in line:
            hostname = line.replace('Nmap scan report for', '').strip()
            if hostname and not hostname.startswith('('):
                result["hostnames"].append(hostname)
        
        # Extract ports
        if '/tcp' in line or '/udp' in line:
            parts = line.split()
            if len(parts) >= 3:
                port_proto = parts[0]
                state = parts[1]
                service = parts[2]
                
                port, proto = port_proto.split('/')
                result["ports"].append({
                    "port": int(port),
                    "protocol": proto,
                    "state": state,
                    "service": service
                })
    
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: stealth_scan.py <target> [ports]")
        sys.exit(1)
    
    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "1-1000"
    
    result = stealth_scan(target, ports)
    import json
    print(json.dumps(result, indent=2))
STEALTH_SCAN