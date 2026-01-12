#!/usr/bin/env python3
# Threat Intelligence Module - Deus Ex Sophia v2.0 - Self-contained
import os
import sys
import json
import time
import sqlite3
import hashlib
import ipaddress
import threading
from datetime import datetime, timedelta
from collections import defaultdict

class ThreatIntelligencePurified:
    def __init__(self):
        self.base_path = "/opt/sysaux/.network/threat"
        self.intel_db = f"{self.base_path}/.threat_intel.db"
        self.events_db = f"{self.base_path}/.events.db"
        self.local_iocs = f"{self.base_path}/.local_iocs.json"
        self.init_databases()
        self.load_local_intelligence()
    
    def init_databases(self):
        """Initialize SQLite databases"""
        conn = sqlite3.connect(self.intel_db)
        cursor = conn.cursor()
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                threat_type TEXT,
                severity INTEGER DEFAULT 5,
                source TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                description TEXT,
                confidence INTEGER DEFAULT 50,
                tags TEXT,
                UNIQUE(ip, threat_type)
            )
        ''')
        
        # Events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT,
                dest_ip TEXT,
                protocol TEXT,
                port INTEGER,
                event_type TEXT,
                severity INTEGER DEFAULT 1,
                details TEXT,
                processed INTEGER DEFAULT 0
            )
        ''')
        
        # Indicators table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT NOT NULL,
                ioc_type TEXT,
                threat_type TEXT,
                source TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                description TEXT,
                tags TEXT,
                UNIQUE(indicator, ioc_type)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_ip ON threats(ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threats_last_seen ON threats(last_seen)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicators_indicator ON indicators(indicator)')
        
        conn.commit()
        conn.close()
    
    def load_local_intelligence(self):
        """Load local threat intelligence"""
        if not os.path.exists(self.local_iocs):
            # Default local IOCs
            default_iocs = {
                "malicious_ips": [
                    "10.0.0.1",  # Example internal malicious IP
                ],
                "suspicious_domains": [
                    "malicious.example.com",
                ],
                "attack_patterns": [
                    {"pattern": "SELECT.*FROM", "type": "sql_injection"},
                    {"pattern": "<script>", "type": "xss"},
                    {"pattern": "../", "type": "path_traversal"}
                ],
                "threat_feeds": [
                    {
                        "name": "Internal Blacklist",
                        "url": "file:///opt/sysaux/.network/threat/.blacklist.txt",
                        "update_interval": 86400
                    }
                ]
            }
            
            with open(self.local_iocs, 'w') as f:
                json.dump(default_iocs, f, indent=2)
        
        with open(self.local_iocs, 'r') as f:
            self.local_intel = json.load(f)
    
    def update_from_local_sources(self):
        """Update threat intelligence from local sources"""
        print("[*] Updating from local sources...")
        
        # Check for local blacklist file
        blacklist_file = "/opt/sysaux/.network/threat/.blacklist.txt"
        if os.path.exists(blacklist_file):
            try:
                with open(blacklist_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            # Check if it's an IP
                            try:
                                ipaddress.ip_address(line)
                                self.add_threat(line, "malicious_ip", "local_blacklist", 
                                              severity=8, description="Local blacklist entry")
                            except ValueError:
                                # Might be a domain or other indicator
                                self.add_indicator(line, "domain", "suspicious", 
                                                 "local_blacklist", "Local blacklist entry")
            except Exception as e:
                print(f"[-] Error reading blacklist: {e}")
        
        # Check for recent events that might indicate threats
        self.analyze_recent_events()
        
        print("[+] Local intelligence updated")
    
    def add_threat(self, ip, threat_type, source, severity=5, description=""):
        """Add or update threat in database"""
        conn = sqlite3.connect(self.intel_db)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO threats 
                (ip, threat_type, severity, source, last_seen, description)
                VALUES (?, ?, ?, ?, datetime('now'), ?)
            ''', (ip, threat_type, severity, source, description))
            
            conn.commit()
            
        except Exception as e:
            print(f"[-] Error adding threat: {e}")
        
        finally:
            conn.close()
    
    def add_indicator(self, indicator, ioc_type, threat_type, source, description=""):
        """Add or update indicator"""
        conn = sqlite3.connect(self.intel_db)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO indicators 
                (indicator, ioc_type, threat_type, source, last_seen, description)
                VALUES (?, ?, ?, ?, datetime('now'), ?)
            ''', (indicator, ioc_type, threat_type, source, description))
            
            conn.commit()
            
        except Exception as e:
            print(f"[-] Error adding indicator: {e}")
        
        finally:
            conn.close()
    
    def log_event(self, source_ip, dest_ip, protocol, port, event_type, details):
        """Log network event"""
        conn = sqlite3.connect(self.events_db)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO events 
                (source_ip, dest_ip, protocol, port, event_type, details)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (source_ip, dest_ip, protocol, port, event_type, json.dumps(details)))
            
            conn.commit()
            
            # Check if this event indicates a threat
            self.evaluate_event(source_ip, dest_ip, protocol, port, event_type, details)
            
        except Exception as e:
            print(f"[-] Error logging event: {e}")
        
        finally:
            conn.close()
    
    def evaluate_event(self, source_ip, dest_ip, protocol, port, event_type, details):
        """Evaluate event for threat indicators"""
        threat_score = 0
        reasons = []
        
        # Check if source is known malicious
        if self.check_ip_threat(source_ip):
            threat_score += 30
            reasons.append("Source IP is known malicious")
        
        # Check for port scanning patterns
        if event_type == "port_scan":
            threat_score += 25
            reasons.append("Port scanning detected")
        
        # Check for failed authentication attempts
        if event_type == "auth_failed" and details.get('count', 0) > 5:
            threat_score += 20
            reasons.append("Multiple failed authentication attempts")
        
        # Check for suspicious ports
        suspicious_ports = [23, 1433, 3389, 5900]
        if port in suspicious_ports:
            threat_score += 15
            reasons.append(f"Connection to suspicious port {port}")
        
        # If threat score is high, add as threat
        if threat_score >= 40:
            self.add_threat(source_ip, "suspicious_activity", "event_analysis", 
                          severity=min(10, threat_score//10),
                          description=f"Threat score: {threat_score}. Reasons: {', '.join(reasons)}")
    
    def check_ip_threat(self, ip):
        """Check if IP is known threat"""
        conn = sqlite3.connect(self.intel_db)
        cursor = conn.cursor()
        
        try:
            # Check threats table
            cursor.execute('''
                SELECT severity, threat_type, description 
                FROM threats 
                WHERE ip = ? AND last_seen > datetime('now', '-30 days')
                ORDER BY last_seen DESC 
                LIMIT 1
            ''', (ip,))
            
            result = cursor.fetchone()
            if result:
                severity, threat_type, description = result
                return {
                    'malicious': True,
                    'severity': severity,
                    'threat_type': threat_type,
                    'description': description
                }
            
            # Check local IOCs
            if ip in self.local_intel.get('malicious_ips', []):
                return {
                    'malicious': True,
                    'severity': 7,
                    'threat_type': 'local_blacklist',
                    'description': 'IP in local blacklist'
                }
            
        except Exception as e:
            print(f"[-] Error checking IP threat: {e}")
        
        finally:
            conn.close()
        
        return {'malicious': False, 'severity': 0}
    
    def analyze_recent_events(self):
        """Analyze recent events for threat patterns"""
        conn = sqlite3.connect(self.events_db)
        cursor = conn.cursor()
        
        try:
            # Get events from last hour
            cursor.execute('''
                SELECT source_ip, COUNT(*) as event_count,
                       GROUP_CONCAT(DISTINCT event_type) as event_types,
                       GROUP_CONCAT(DISTINCT port) as ports
                FROM events 
                WHERE timestamp > datetime('now', '-1 hour')
                GROUP BY source_ip
                HAVING event_count > 10
            ''')
            
            suspicious_hosts = cursor.fetchall()
            
            for source_ip, count, event_types, ports in suspicious_hosts:
                # Analyze event types
                event_list = event_types.split(',')
                port_list = ports.split(',') if ports else []
                
                threat_level = "low"
                if count > 50:
                    threat_level = "high"
                elif count > 20:
                    threat_level = "medium"
                
                # Check for scanning patterns
                if len(port_list) > 5 and 'port_scan' in event_list:
                    self.add_threat(source_ip, "port_scanner", "pattern_analysis",
                                  severity=8 if threat_level == "high" else 6,
                                  description=f"Port scanning detected: {count} events, ports: {ports}")
                
                # Check for brute force patterns
                if event_list.count('auth_failed') > 3:
                    self.add_threat(source_ip, "brute_force", "pattern_analysis",
                                  severity=7,
                                  description=f"Multiple failed authentication attempts: {count} events")
        
        except Exception as e:
            print(f"[-] Error analyzing events: {e}")
        
        finally:
            conn.close()
    
    def generate_threat_report(self, hours=24):
        """Generate threat intelligence report"""
        conn = sqlite3.connect(self.intel_db)
        cursor = conn.cursor()
        
        report = {
            'generated': datetime.now().isoformat(),
            'period_hours': hours,
            'threats': [],
            'statistics': {
                'total_threats': 0,
                'high_severity': 0,
                'new_threats': 0
            },
            'recommendations': []
        }
        
        try:
            # Get recent threats
            cursor.execute('''
                SELECT ip, threat_type, severity, source, last_seen, description
                FROM threats 
                WHERE last_seen > datetime('now', ?)
                ORDER BY severity DESC, last_seen DESC
            ''', (f'-{hours} hours',))
            
            threats = cursor.fetchall()
            report['statistics']['total_threats'] = len(threats)
            
            for ip, threat_type, severity, source, last_seen, description in threats:
                report['threats'].append({
                    'ip': ip,
                    'threat_type': threat_type,
                    'severity': severity,
                    'source': source,
                    'last_seen': last_seen,
                    'description': description
                })
                
                if severity >= 8:
                    report['statistics']['high_severity'] += 1
            
            # Get new threats (first seen in last 24 hours)
            cursor.execute('''
                SELECT COUNT(*) 
                FROM threats 
                WHERE first_seen > datetime('now', '-24 hours')
            ''')
            
            new_threats = cursor.fetchone()[0]
            report['statistics']['new_threats'] = new_threats
            
            # Generate recommendations
            if report['statistics']['high_severity'] > 0:
                report['recommendations'].append(
                    f"Block {report['statistics']['high_severity']} high severity IPs"
                )
            
            if new_threats > 5:
                report['recommendations'].append(
                    "Review network security controls - high number of new threats"
                )
        
        except Exception as e:
            report['error'] = str(e)
        
        finally:
            conn.close()
        
        # Save report
        report_file = f"{self.base_path}/../visual/.threat_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def monitor_events(self):
        """Monitor for new events and update intelligence"""
        print("[*] Starting threat intelligence monitoring...")
        
        # Load existing events database
        if not os.path.exists(self.events_db):
            # Create from system logs
            self.harvest_system_logs()
        
        # Start monitoring thread
        self.monitoring = True
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        
        return monitor_thread
    
    def harvest_system_logs(self):
        """Harvest threat intelligence from system logs"""
        print("[*] Harvesting system logs for threat intelligence...")
        
        # Check auth.log for failed logins
        auth_log = "/var/log/auth.log"
        if os.path.exists(auth_log):
            try:
                with open(auth_log, 'r') as f:
                    for line in f:
                        if 'Failed password' in line or 'authentication failure' in line:
                            # Extract IP address
                            import re
                            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                            if ip_match:
                                ip = ip_match.group(0)
                                self.log_event(ip, "localhost", "ssh", 22, 
                                             "auth_failed", {"log_line": line.strip()})
            except:
                pass
        
        # Check syslog for other security events
        syslog = "/var/log/syslog"
        if os.path.exists(syslog):
            try:
                with open(syslog, 'r') as f:
                    for line in f:
                        if 'DROP' in line or 'REJECT' in line:
                            # Extract IP from iptables logs
                            import re
                            src_match = re.search(r'SRC=(\d+\.\d+\.\d+\.\d+)', line)
                            if src_match:
                                ip = src_match.group(1)
                                self.log_event(ip, "localhost", "firewall", 0,
                                             "firewall_block", {"log_line": line.strip()})
            except:
                pass
    
    def monitoring_loop(self):
        """Continuous monitoring loop"""
        while self.monitoring:
            try:
                # Update from local sources
                self.update_from_local_sources()
                
                # Analyze recent events
                self.analyze_recent_events()
                
                # Generate report every 6 hours
                current_hour = datetime.now().hour
                if current_hour % 6 == 0:
                    self.generate_threat_report(24)
                
                # Sleep for 5 minutes
                time.sleep(300)
                
            except Exception as e:
                print(f"[-] Monitoring error: {e}")
                time.sleep(60)
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False

if __name__ == "__main__":
    ti = ThreatIntelligencePurified()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--monitor':
            print("[*] Starting threat intelligence monitoring...")
            monitor = ti.monitor_events()
            try:
                monitor.join()
            except KeyboardInterrupt:
                print("\n[*] Stopping monitoring...")
                ti.stop_monitoring()
        
        elif sys.argv[1] == '--report':
            hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
            report = ti.generate_threat_report(hours)
            print(json.dumps(report, indent=2))
        
        elif sys.argv[1] == '--check' and len(sys.argv) > 2:
            ip = sys.argv[2]
            result = ti.check_ip_threat(ip)
            print(json.dumps(result, indent=2))
        
        elif sys.argv[1] == '--update':
            ti.update_from_local_sources()
            print("[+] Local intelligence updated")
        
        elif sys.argv[1] == '--analyze':
            ti.analyze_recent_events()
            print("[+] Recent events analyzed")
    
    else:
        print("Threat Intelligence Module v2.0 - Deus Ex Sophia")
        print("Commands:")
        print("  --monitor           Start continuous monitoring")
        print("  --report [hours]    Generate threat report")
        print("  --check <IP>        Check IP threat status")
        print("  --update            Update from local sources")
        print("  --analyze           Analyze recent events")
THREAT_EOF