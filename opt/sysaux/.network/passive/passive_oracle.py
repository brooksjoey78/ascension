#!/usr/bin/env python3
# Passive Network Oracle - Deus Ex Sophia v2.0 - No external dependencies
import os
import sys
import json
import time
import socket
import struct
import threading
import subprocess
import binascii
from datetime import datetime, timedelta
from collections import defaultdict

class PassiveOraclePurified:
    def __init__(self):
        self.base_path = "/opt/sysaux/.network/passive"
        self.host_db = f"{self.base_path}/.hosts.db"
        self.arp_db = f"{self.base_path}/.arp.cache"
        self.dns_db = f"{self.base_path}/.dns.queries"
        self.monitor_interfaces = self.detect_interfaces()
        self.running = False
        self.init_storage()
        
    def detect_interfaces(self):
        """Detect all network interfaces automatically"""
        interfaces = []
        try:
            # Use ip command for reliable detection
            result = subprocess.run(['ip', '-o', 'link', 'show'], 
                                 capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'state UP' in line or 'state UNKNOWN' in line:
                    parts = line.split(':')
                    if len(parts) > 1:
                        iface = parts[1].strip()
                        if iface and iface != 'lo':
                            interfaces.append(iface)
        except:
            # Fallback to /sys/class/net
            if os.path.exists('/sys/class/net'):
                for iface in os.listdir('/sys/class/net'):
                    if iface != 'lo':
                        interfaces.append(iface)
        
        return interfaces if interfaces else ['eth0']
    
    def init_storage(self):
        """Initialize stealth storage"""
        for db_file in [self.host_db, self.arp_db, self.dns_db]:
            if not os.path.exists(db_file):
                with open(db_file, 'w') as f:
                    json.dump({}, f)
        
        # Set restrictive permissions
        os.chmod(self.host_db, 0o600)
        os.chmod(self.arp_db, 0o600)
        os.chmod(self.dns_db, 0o600)
    
    def raw_sniff(self, interface):
        """Raw packet sniffing without scapy"""
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((interface, 0))
            sock.settimeout(1)
            
            while self.running:
                try:
                    data, addr = sock.recvfrom(65535)
                    if len(data) >= 14:
                        self.process_packet(data, interface)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # Only log if we're supposed to be running
                        pass
                    
            sock.close()
        except Exception as e:
            pass
    
    def process_packet(self, data, interface):
        """Process raw packet"""
        # Ethernet header
        dest_mac = binascii.hexlify(data[0:6]).decode('utf-8')
        src_mac = binascii.hexlify(data[6:12]).decode('utf-8')
        eth_type = struct.unpack('!H', data[12:14])[0]
        
        # Format MAC addresses
        src_mac_fmt = ':'.join([src_mac[i:i+2] for i in range(0,12,2)])
        dest_mac_fmt = ':'.join([dest_mac[i:i+2] for i in range(0,12,2)])
        
        # ARP (0x0806)
        if eth_type == 0x0806 and len(data) >= 42:
            self.process_arp(data[14:], src_mac_fmt, interface)
        
        # IPv4 (0x0800)
        elif eth_type == 0x0800 and len(data) >= 34:
            self.process_ip(data[14:], src_mac_fmt, interface)
    
    def process_arp(self, arp_data, src_mac, interface):
        """Process ARP packet"""
        try:
            if len(arp_data) < 28:
                return
            
            operation = struct.unpack('!H', arp_data[6:8])[0]
            src_ip = socket.inet_ntoa(arp_data[8:12])
            dest_ip = socket.inet_ntoa(arp_data[18:22])
            
            timestamp = datetime.now().isoformat()
            
            # Load ARP cache
            with open(self.arp_db, 'r') as f:
                arp_cache = json.load(f)
            
            # Update ARP cache
            arp_key = f"{src_ip}_{src_mac}"
            arp_cache[arp_key] = {
                'ip': src_ip,
                'mac': src_mac,
                'interface': interface,
                'last_seen': timestamp,
                'operation': 'request' if operation == 1 else 'reply'
            }
            
            # Save ARP cache
            with open(self.arp_db, 'w') as f:
                json.dump(arp_cache, f)
            
            # Update host database
            self.update_host(src_ip, src_mac, 'arp', interface)
            
        except Exception as e:
            pass
    
    def process_ip(self, ip_data, src_mac, interface):
        """Process IP packet"""
        try:
            if len(ip_data) < 20:
                return
            
            # IP header length
            ihl = (ip_data[0] & 0x0F) * 4
            
            # Protocol
            protocol = ip_data[9]
            
            # Source and destination IPs
            src_ip = socket.inet_ntoa(ip_data[12:16])
            dst_ip = socket.inet_ntoa(ip_data[16:20])
            
            # UDP (protocol 17)
            if protocol == 17 and len(ip_data) >= ihl + 8:
                src_port = struct.unpack('!H', ip_data[ihl:ihl+2])[0]
                dst_port = struct.unpack('!H', ip_data[ihl+2:ihl+4])[0]
                
                # DNS (port 53)
                if dst_port == 53 and len(ip_data) >= ihl + 12:
                    self.process_dns(ip_data[ihl+8:], src_ip, src_mac)
            
            # Update host database
            self.update_host(src_ip, src_mac, 'ip', interface)
            
        except Exception as e:
            pass
    
    def process_dns(self, dns_data, src_ip, src_mac):
        """Process DNS query"""
        try:
            if len(dns_data) < 12:
                return
            
            # Check if it's a query (QR=0)
            flags = struct.unpack('!H', dns_data[2:4])[0]
            if flags & 0x8000:  # QR bit set = response
                return
            
            # Extract query count
            qdcount = struct.unpack('!H', dns_data[4:6])[0]
            
            offset = 12
            for _ in range(qdcount):
                # Extract domain name
                domain_parts = []
                while offset < len(dns_data) and dns_data[offset] != 0:
                    length = dns_data[offset]
                    offset += 1
                    if offset + length <= len(dns_data):
                        domain_parts.append(dns_data[offset:offset+length].decode('utf-8', errors='ignore'))
                    offset += length
                offset += 1  # Skip null terminator
                
                if offset + 4 > len(dns_data):
                    break
                
                # Skip QTYPE and QCLASS
                offset += 4
                
                if domain_parts:
                    domain = '.'.join(domain_parts)
                    
                    # Load DNS database
                    with open(self.dns_db, 'r') as f:
                        dns_queries = json.load(f)
                    
                    # Update DNS queries
                    query_key = f"{src_ip}_{domain}"
                    dns_queries[query_key] = {
                        'ip': src_ip,
                        'mac': src_mac,
                        'domain': domain,
                        'timestamp': datetime.now().isoformat(),
                        'count': dns_queries.get(query_key, {}).get('count', 0) + 1
                    }
                    
                    # Save DNS database
                    with open(self.dns_db, 'w') as f:
                        json.dump(dns_queries, f)
                    
                    # Update host with DNS info
                    self.update_host_dns(src_ip, domain)
                    
                break  # Only process first query for performance
            
        except Exception as e:
            pass
    
    def update_host(self, ip, mac, source, interface):
        """Update host database"""
        try:
            # Load host database
            with open(self.host_db, 'r') as f:
                hosts = json.load(f)
            
            timestamp = datetime.now().isoformat()
            
            if ip not in hosts:
                hosts[ip] = {
                    'mac': mac,
                    'first_seen': timestamp,
                    'last_seen': timestamp,
                    'sources': [source],
                    'interfaces': [interface],
                    'hostnames': [],
                    'dns_queries': [],
                    'activity_count': 1
                }
            else:
                hosts[ip]['last_seen'] = timestamp
                hosts[ip]['activity_count'] = hosts[ip].get('activity_count', 0) + 1
                
                if source not in hosts[ip]['sources']:
                    hosts[ip]['sources'].append(source)
                
                if interface not in hosts[ip].get('interfaces', []):
                    hosts[ip].setdefault('interfaces', []).append(interface)
            
            # Save host database
            with open(self.host_db, 'w') as f:
                json.dump(hosts, f, indent=2)
                
        except Exception as e:
            pass
    
    def update_host_dns(self, ip, domain):
        """Update host with DNS information"""
        try:
            with open(self.host_db, 'r') as f:
                hosts = json.load(f)
            
            if ip in hosts:
                if 'hostnames' not in hosts[ip]:
                    hosts[ip]['hostnames'] = []
                
                if domain not in hosts[ip]['hostnames']:
                    hosts[ip]['hostnames'].append(domain)
                
                if 'dns_queries' not in hosts[ip]:
                    hosts[ip]['dns_queries'] = []
                
                if domain not in hosts[ip]['dns_queries']:
                    hosts[ip]['dns_queries'].append(domain)
                
                with open(self.host_db, 'w') as f:
                    json.dump(hosts, f, indent=2)
                    
        except Exception as e:
            pass
    
    def start_monitoring(self):
        """Start passive monitoring on all interfaces"""
        self.running = True
        
        threads = []
        for interface in self.monitor_interfaces:
            thread = threading.Thread(target=self.raw_sniff, args=(interface,), daemon=True)
            thread.start()
            threads.append(thread)
        
        # Start periodic cleanup thread
        cleanup_thread = threading.Thread(target=self.periodic_cleanup, daemon=True)
        cleanup_thread.start()
        
        return threads
    
    def periodic_cleanup(self):
        """Periodic cleanup of old entries"""
        while self.running:
            time.sleep(3600)  # Cleanup every hour
            
            try:
                # Load databases
                with open(self.host_db, 'r') as f:
                    hosts = json.load(f)
                
                with open(self.arp_db, 'r') as f:
                    arp_cache = json.load(f)
                
                with open(self.dns_db, 'r') as f:
                    dns_queries = json.load(f)
                
                cutoff = (datetime.now() - timedelta(days=7)).isoformat()
                
                # Clean old hosts (older than 7 days)
                hosts = {ip: data for ip, data in hosts.items() 
                        if data['last_seen'] > cutoff}
                
                # Clean old ARP entries
                arp_cache = {key: data for key, data in arp_cache.items() 
                           if data['last_seen'] > cutoff}
                
                # Clean old DNS queries
                dns_queries = {key: data for key, data in dns_queries.items() 
                             if data['timestamp'] > cutoff}
                
                # Save cleaned databases
                with open(self.host_db, 'w') as f:
                    json.dump(hosts, f, indent=2)
                
                with open(self.arp_db, 'w') as f:
                    json.dump(arp_cache, f)
                
                with open(self.dns_db, 'w') as f:
                    json.dump(dns_queries, f)
                    
            except Exception as e:
                pass
    
    def stop_monitoring(self):
        """Stop passive monitoring"""
        self.running = False
        time.sleep(2)  # Allow threads to exit
    
    def get_stats(self):
        """Get monitoring statistics"""
        try:
            with open(self.host_db, 'r') as f:
                hosts = json.load(f)
            
            with open(self.dns_db, 'r') as f:
                dns_queries = json.load(f)
            
            # Count active hosts (seen in last 15 minutes)
            active_cutoff = (datetime.now() - timedelta(minutes=15)).isoformat()
            active_hosts = sum(1 for data in hosts.values() 
                             if data['last_seen'] > active_cutoff)
            
            return {
                'total_hosts': len(hosts),
                'active_hosts': active_hosts,
                'total_dns_queries': len(dns_queries),
                'monitoring_interfaces': self.monitor_interfaces,
                'timestamp': datetime.now().isoformat()
            }
        except:
            return {'error': 'Unable to load statistics'}
    
    def export_data(self, format='json'):
        """Export collected data"""
        try:
            with open(self.host_db, 'r') as f:
                hosts = json.load(f)
            
            with open(self.arp_db, 'r') as f:
                arp_cache = json.load(f)
            
            with open(self.dns_db, 'r') as f:
                dns_queries = json.load(f)
            
            data = {
                'hosts': hosts,
                'arp_cache': arp_cache,
                'dns_queries': dns_queries,
                'export_time': datetime.now().isoformat()
            }
            
            if format == 'json':
                return json.dumps(data, indent=2)
            elif format == 'csv':
                # Simple CSV conversion
                csv_lines = ['IP,MAC,First Seen,Last Seen,Hostnames']
                for ip, info in hosts.items():
                    hostnames = ';'.join(info.get('hostnames', []))
                    csv_lines.append(f'{ip},{info.get("mac","")},{info.get("first_seen","")},{info.get("last_seen","")},{hostnames}')
                return '\n'.join(csv_lines)
            else:
                return str(data)
                
        except Exception as e:
            return f'Error exporting data: {str(e)}'

if __name__ == "__main__":
    oracle = PassiveOraclePurified()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--start':
            print("[*] Starting passive monitoring...")
            threads = oracle.start_monitoring()
            try:
                while True:
                    time.sleep(60)
                    stats = oracle.get_stats()
                    print(f"[*] Stats: {stats['total_hosts']} hosts, {stats['active_hosts']} active")
            except KeyboardInterrupt:
                print("\n[*] Stopping monitoring...")
                oracle.stop_monitoring()
        
        elif sys.argv[1] == '--stats':
            stats = oracle.get_stats()
            print(json.dumps(stats, indent=2))
        
        elif sys.argv[1] == '--export':
            fmt = sys.argv[2] if len(sys.argv) > 2 else 'json'
            print(oracle.export_data(fmt))
        
        elif sys.argv[1] == '--interfaces':
            print("Detected interfaces:", oracle.monitor_interfaces)
    
    else:
        print("Passive Network Oracle v2.0 - Deus Ex Sophia")
        print("Commands:")
        print("  --start        Start passive monitoring")
        print("  --stats        Show statistics")
        print("  --export [fmt] Export data (json/csv)")
        print("  --interfaces   Show monitoring interfaces")
PASSIVE_EOF