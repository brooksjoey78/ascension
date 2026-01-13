#!/usr/bin/env python3
# Active Reconnaissance Module - Deus Ex Sophia v2.0 - Stealth Focus
import os
import sys
import json
import time
import socket
import random
import subprocess
import ipaddress
import threading
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed

class ActiveReconPurified:
    def __init__(self):
        self.base_path = "/opt/sysaux/.network/active"
        self.results_db = f"{self.base_path}/.scan_results.db"
        self.vuln_db = f"{self.base_path}/.vulnerabilities.db"
        self.config = self.load_config()
        self.init_storage()
    
    def load_config(self):
        """Load stealth configuration"""
        config = {
            'max_workers': 3,  # Reduced for stealth
            'scan_delay_min': 2,  # Minimum delay between scans (seconds)
            'scan_delay_max': 10,  # Maximum delay
            'timeout': 30,  # Scan timeout
            'ports': '21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',  # Common ports only
            'user_agents': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
                'curl/7.68.0',
                'Wget/1.20.3'
            ],
            'stealth_level': 8  # 1-10, higher = more stealth
        }
        
        # Load custom config if exists
        config_file = f"{self.base_path}/.config.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    custom_config = json.load(f)
                    config.update(custom_config)
            except:
                pass
        
        return config
    
    def init_storage(self):
        """Initialize stealth storage"""
        for db_file in [self.results_db, self.vuln_db]:
            if not os.path.exists(db_file):
                with open(db_file, 'w') as f:
                    json.dump({}, f)
        
        # Set restrictive permissions
        os.chmod(self.results_db, 0o600)
        os.chmod(self.vuln_db, 0o600)
    
    def generate_targets(self):
        """Generate target list for scanning"""
        targets = []
        
        # Method 1: Local network discovery
        try:
            # Get local IP and network
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 53))
            local_ip = s.getsockname()[0]
            s.close()
            
            network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
            net = ipaddress.ip_network(network, strict=False)
            
            # Add random hosts from local network
            for _ in range(min(20, len(list(net.hosts())))):  # Limit to 20 hosts
                host = random.choice(list(net.hosts()))
                if str(host) != local_ip:
                    targets.append(str(host))
        except:
            pass
        
        # Method 2: ARP cache
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '(' in line and ')' in line:
                    ip = line.split('(')[1].split(')')[0]
                    if ip not in targets:
                        targets.append(ip)
        except:
            pass
        
        # Method 3: Previous scan results
        if os.path.exists(self.results_db):
            try:
                with open(self.results_db, 'r') as f:
                    previous_results = json.load(f)
                    targets.extend(list(previous_results.keys())[:10])  # Add 10 previous targets
            except:
                pass
        
        # Remove duplicates and limit
        targets = list(set(targets))
        random.shuffle(targets)
        
        return targets[:50]  # Limit to 50 targets max
    
    def stealth_port_scan(self, target, ports=None):
        """Stealth port scan using custom techniques"""
        if ports is None:
            ports = self.config['ports']
        
        # Random delay before scan
        delay = random.uniform(self.config['scan_delay_min'], self.config['scan_delay_max'])
        time.sleep(delay)
        
        # Build stealth nmap command
        scan_id = random.randint(1000, 9999)
        output_file = f"/tmp/.scan_{scan_id}_{int(time.time())}.xml"
        
        # Randomize scan type based on stealth level
        scan_types = ['-sS', '-sT']
        if self.config['stealth_level'] > 8:
            scan_type = '-sN'  # NULL scan
        elif self.config['stealth_level'] > 6:
            scan_type = '-sF'  # FIN scan
        else:
            scan_type = random.choice(scan_types)
        
        # Randomize timing
        timing_options = ['-T0', '-T1', '-T2']
        timing = random.choice(timing_options)
        
        # Build command
        cmd = [
            'nmap',
            scan_type,
            timing,
            '-n',  # No DNS resolution
            '-Pn',  # No host discovery
            '--max-retries', '1',
            '--max-rate', str(random.randint(5, 20)),
            '--scan-delay', f'{random.randint(100, 1000)}ms',
            '--data-length', str(random.randint(1, 50)),
            '--ttl', str(random.randint(32, 128)),
            '-p', ports,
            '-oX', output_file,
            target
        ]
        
        try:
            # Execute scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.config['timeout'])
            
            # Parse XML output
            if os.path.exists(output_file):
                scan_results = self.parse_nmap_xml(output_file)
                os.unlink(output_file)  # Clean up
                
                # Enrich results
                if scan_results.get('ports'):
                    scan_results = self.enrich_results(target, scan_results)
                
                # Save results
                self.save_results(target, scan_results)
                
                return scan_results
                
        except subprocess.TimeoutExpired:
            return {'error': 'Scan timeout', 'target': target}
        except Exception as e:
            return {'error': str(e), 'target': target}
        
        return {'error': 'Scan failed', 'target': target}
    
    def parse_nmap_xml(self, xml_file):
        """Parse nmap XML output without external dependencies"""
        try:
            with open(xml_file, 'r') as f:
                content = f.read()
            
            result = {
                'scan_start': datetime.now().isoformat(),
                'ports': [],
                'hostnames': []
            }
            
            # Simple XML parsing for our needs
            lines = content.split('\n')
            
            # Extract hostnames
            for line in lines:
                if '<hostname name=' in line:
                    start = line.find('name="') + 6
                    end = line.find('"', start)
                    if start > 5 and end > start:
                        hostname = line[start:end]
                        result['hostnames'].append(hostname)
            
            # Extract ports
            in_port = False
            current_port = {}
            
            for line in lines:
                line = line.strip()
                
                if '<port protocol="' in line:
                    in_port = True
                    # Extract port number
                    port_start = line.find('portid="') + 8
                    port_end = line.find('"', port_start)
                    if port_start > 7 and port_end > port_start:
                        current_port = {'port': int(line[port_start:port_end])}
                
                elif in_port and '<state state="' in line:
                    state_start = line.find('state="') + 7
                    state_end = line.find('"', state_start)
                    if state_start > 6 and state_end > state_start:
                        current_port['state'] = line[state_start:state_end]
                
                elif in_port and '<service name="' in line:
                    service_start = line.find('name="') + 6
                    service_end = line.find('"', service_start)
                    if service_start > 5 and service_end > service_start:
                        current_port['service'] = line[service_start:service_end]
                
                elif in_port and '</port>' in line:
                    if current_port and current_port.get('state') == 'open':
                        result['ports'].append(current_port)
                    in_port = False
                    current_port = {}
            
            return result
            
        except Exception as e:
            return {'error': f'XML parse error: {str(e)}'}
    
    def enrich_results(self, target, scan_results):
        """Enrich scan results with service information"""
        for port_info in scan_results['ports']:
            port = port_info['port']
            service = port_info.get('service', 'unknown')
            
            # Basic service enrichment
            if service == 'http' or port in [80, 443, 8080, 8443]:
                port_info['enrichment'] = self.enrich_web_service(target, port)
            elif service == 'ssh' or port == 22:
                port_info['enrichment'] = self.enrich_ssh_service(target, port)
            elif service in ['microsoft-ds', 'netbios-ssn'] or port in [139, 445]:
                port_info['enrichment'] = self.enrich_smb_service(target, port)
        
        # Vulnerability assessment
        vulnerabilities = self.assess_vulnerabilities(target, scan_results)
        if vulnerabilities:
            scan_results['vulnerabilities'] = vulnerabilities
            self.save_vulnerabilities(target, vulnerabilities)
        
        return scan_results
    
    def enrich_web_service(self, target, port):
        """Enrich web service information"""
        enrichment = {'type': 'web'}
        
        # Determine protocol
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{target}:{port}"
        
        try:
            # Use curl for HTTP requests
            user_agent = random.choice(self.config['user_agents'])
            cmd = [
                'curl', '-s', '-L',
                '-A', user_agent,
                '-m', '5',
                '--max-redirs', '3',
                url
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Extract headers from verbose output
                headers_cmd = ['curl', '-s', '-I', '-A', user_agent, '-m', '5', url]
                headers_result = subprocess.run(headers_cmd, capture_output=True, text=True)
                
                # Parse headers
                for line in headers_result.stdout.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip().lower()
                        if key == 'server':
                            enrichment['server'] = value.strip()
                        elif key == 'x-powered-by':
                            enrichment['powered_by'] = value.strip()
                
                # Check for common applications
                content = result.stdout.lower()
                if 'wordpress' in content:
                    enrichment['application'] = 'WordPress'
                elif 'drupal' in content:
                    enrichment['application'] = 'Drupal'
                elif 'joomla' in content:
                    enrichment['application'] = 'Joomla'
                
        except:
            pass
        
        return enrichment
    
    def enrich_ssh_service(self, target, port):
        """Enrich SSH service information"""
        enrichment = {'type': 'ssh'}
        
        try:
            # SSH banner grab with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                enrichment['banner'] = banner
                if 'SSH' in banner:
                    parts = banner.split('-')
                    if len(parts) > 1:
                        enrichment['version'] = parts[1].split()[0]
        
        except:
            pass
        
        return enrichment
    
    def enrich_smb_service(self, target, port):
        """Enrich SMB service information"""
        enrichment = {'type': 'smb'}
        
        # Use nmap scripts for SMB
        try:
            output_file = f"/tmp/.smb_{int(time.time())}.xml"
            cmd = [
                'nmap', '-sS',
                '-p', str(port),
                '--script', 'smb-os-discovery,smb-security-mode',
                '-oX', output_file,
                target
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    content = f.read()
                
                # Extract SMB info
                if 'smb-os-discovery' in content:
                    enrichment['os_discovery'] = 'success'
                
                os.unlink(output_file)
        
        except:
            pass
        
        return enrichment
    
    def assess_vulnerabilities(self, target, scan_results):
        """Assess basic vulnerabilities"""
        vulnerabilities = []
        
        for port_info in scan_results.get('ports', []):
            port = port_info['port']
            service = port_info.get('service', '')
            state = port_info.get('state', '')
            
            if state != 'open':
                continue
            
            # Check for common vulnerable services
            # SSH
            if port == 22:
                enrichment = port_info.get('enrichment', {})
                banner = enrichment.get('banner', '')
                if 'SSH-2.0-OpenSSH_7.2' in banner or 'SSH-2.0-OpenSSH_7.3' in banner:
                    vulnerabilities.append({
                        'port': port,
                        'service': service,
                        'vulnerability': 'OpenSSH Legacy Version',
                        'severity': 'medium',
                        'description': 'Older OpenSSH versions may have vulnerabilities'
                    })
            
            # FTP
            elif port == 21:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': 'FTP Service Exposed',
                    'severity': 'low',
                    'description': 'FTP is insecure and may allow credential sniffing'
                })
            
            # Telnet
            elif port == 23:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': 'Telnet Service Exposed',
                    'severity': 'high',
                    'description': 'Telnet transmits credentials in plaintext'
                })
            
            # SMB
            elif port in [139, 445]:
                vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': 'SMB Service Exposed',
                    'severity': 'medium',
                    'description': 'SMB may be vulnerable to EternalBlue or other exploits'
                })
        
        return vulnerabilities
    
    def save_results(self, target, results):
        """Save scan results"""
        try:
            with open(self.results_db, 'r') as f:
                all_results = json.load(f)
            
            all_results[target] = results
            
            with open(self.results_db, 'w') as f:
                json.dump(all_results, f, indent=2)
        
        except Exception as e:
            pass
    
    def save_vulnerabilities(self, target, vulnerabilities):
        """Save vulnerabilities"""
        try:
            with open(self.vuln_db, 'r') as f:
                all_vulns = json.load(f)
            
            all_vulns[target] = {
                'timestamp': datetime.now().isoformat(),
                'vulnerabilities': vulnerabilities
            }
            
            with open(self.vuln_db, 'w') as f:
                json.dump(all_vulns, f, indent=2)
        
        except Exception as e:
            pass
    
    def start_scan(self):
        """Start comprehensive stealth scan"""
        print("[*] Generating target list...")
        targets = self.generate_targets()
        
        if not targets:
            print("[-] No targets found for scanning")
            return
        
        print(f"[*] Found {len(targets)} targets for scanning")
        print("[*] Starting stealth scan (this will take some time)...")
        
        results = {}
        
        # Use ThreadPoolExecutor with limited workers
        with ThreadPoolExecutor(max_workers=self.config['max_workers']) as executor:
            future_to_target = {
                executor.submit(self.stealth_port_scan, target): target 
                for target in targets[:20]  # Limit to 20 targets per scan
            }
            
            completed = 0
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                completed += 1
                
                try:
                    result = future.result(timeout=self.config['timeout'] + 10)
                    results[target] = result
                    
                    # Print progress
                    if 'error' in result:
                        print(f"  [-] {target}: {result['error']}")
                    else:
                        open_ports = len(result.get('ports', []))
                        print(f"  [+] {target}: {open_ports} open ports")
                        
                        # Print vulnerabilities if found
                        if 'vulnerabilities' in result:
                            vuln_count = len(result['vulnerabilities'])
                            print(f"      Found {vuln_count} potential vulnerabilities")
                
                except Exception as e:
                    print(f"  [-] {target}: Scan failed - {str(e)}")
                    results[target] = {'error': str(e)}
        
        print(f"[*] Scan completed: {completed}/{len(targets)} targets scanned")
        
        # Generate report
        report = self.generate_report(results)
        return report
    
    def generate_report(self, scan_results):
        """Generate scan report"""
        report = {
            'generated': datetime.now().isoformat(),
            'total_targets': len(scan_results),
            'successful_scans': sum(1 for r in scan_results.values() if 'error' not in r),
            'total_open_ports': 0,
            'vulnerabilities_found': 0,
            'targets': {}
        }
        
        for target, results in scan_results.items():
            if 'error' in results:
                report['targets'][target] = {'error': results['error']}
                continue
            
            open_ports = len(results.get('ports', []))
            report['total_open_ports'] += open_ports
            
            vulns = results.get('vulnerabilities', [])
            report['vulnerabilities_found'] += len(vulns)
            
            report['targets'][target] = {
                'open_ports': open_ports,
                'hostnames': results.get('hostnames', []),
                'vulnerabilities': vulns,
                'ports': results.get('ports', [])
            }
        
        # Save report
        report_file = f"{self.base_path}/../visual/.scan_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"[+] Report saved to {report_file}")
        
        return report

if __name__ == "__main__":
    recon = ActiveReconPurified()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--scan':
            report = recon.start_scan()
            print(json.dumps(report, indent=2))
        
        elif sys.argv[1] == '--target' and len(sys.argv) > 2:
            target = sys.argv[2]
            ports = sys.argv[3] if len(sys.argv) > 3 else None
            result = recon.stealth_port_scan(target, ports)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == '--config':
            print(json.dumps(recon.config, indent=2))
    
    else:
        print("Active Reconnaissance Module v2.0 - Deus Ex Sophia")
        print("Commands:")
        print("  --scan                 Start comprehensive stealth scan")
        print("  --target <IP> [ports]  Scan specific target")
        print("  --config               Show configuration")
ACTIVE_EOF