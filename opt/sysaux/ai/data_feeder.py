#!/usr/bin/env python3

# AUTOMATED DATA FEEDER FOR DEUS EX SOPHIA
# Feeds live operational data to the LLM in real-time without manual intervention.

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import zmq
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class OperationalDataStream:
    """Streams live operational data to the LLM."""
    
    def __init__(self, llm_bridge):
        self.llm = llm_bridge
        self.data_sources = {
            'system_metrics': self._collect_system_metrics,
            'network_events': self._collect_network_events,
            'threat_intel': self._collect_threat_intel,
            'persistence_status': self._collect_persistence_status,
            'exfiltration_status': self._collect_exfiltration_status,
            'ai_context': self._collect_ai_context
        }
        
        # ZeroMQ for real-time data ingestion
        self.context = zmq.Context()
        self.subscriber = self.context.socket(zmq.SUB)
        self.subscriber.connect("tcp://localhost:5555")
        self.subscriber.setsockopt_string(zmq.SUBSCRIBE, "")
        
        # File watcher for log files
        self.observer = Observer()
        self.log_watcher = LogFileWatcher(self)
        
        # Buffer for recent data
        self.data_buffer = []
        self.buffer_max_size = 100
        
        print("[Data Feeder] Initialized with real-time streaming")
    
    async def start(self):
        """Start all data collection streams."""
        # Start ZeroMQ listener
        asyncio.create_task(self._zmq_listener())
        
        # Start file watcher
        self.observer.schedule(self.log_watcher, '/opt/sysaux/logs', recursive=True)
        self.observer.start()
        
        # Start periodic data collection
        asyncio.create_task(self._periodic_collection())
        
        print("[Data Feeder] All streams started")
    
    async def _zmq_listener(self):
        """Listen for real-time events via ZeroMQ."""
        while True:
            try:
                message = self.subscriber.recv_string(zmq.NOBLOCK)
                data = json.loads(message)
                
                # Add to buffer
                self._add_to_buffer({
                    'type': 'realtime_event',
                    'timestamp': time.time(),
                    'data': data
                })
                
                # If event is high priority, feed immediately to LLM
                if data.get('priority') in ['high', 'critical']:
                    await self._feed_to_llm({
                        'event': 'high_priority_alert',
                        'data': data,
                        'timestamp': datetime.utcnow().isoformat()
                    })
            
            except zmq.Again:
                await asyncio.sleep(0.1)
            except Exception as e:
                print(f"[Data Feeder] ZMQ error: {e}")
                await asyncio.sleep(1)
    
    async def _periodic_collection(self):
        """Periodically collect data from all sources."""
        collection_interval = 30  # seconds
        
        while True:
            try:
                # Collect data from all sources
                collected_data = {}
                for source_name, collector in self.data_sources.items():
                    try:
                        collected_data[source_name] = collector()
                    except Exception as e:
                        collected_data[source_name] = {'error': str(e)}
                
                # Add to buffer
                self._add_to_buffer({
                    'type': 'periodic_collection',
                    'timestamp': time.time(),
                    'data': collected_data
                })
                
                # Feed summarized data to LLM every 5 minutes
                if int(time.time()) % 300 < 30:  # Every 5 minutes
                    summary = self._summarize_data(collected_data)
                    await self._feed_to_llm({
                        'type': 'periodic_summary',
                        'timestamp': datetime.utcnow().isoformat(),
                        'summary': summary
                    })
                
                await asyncio.sleep(collection_interval)
            
            except Exception as e:
                print(f"[Data Feeder] Collection error: {e}")
                await asyncio.sleep(collection_interval)
    
    def _add_to_buffer(self, item: Dict):
        """Add data to circular buffer."""
        self.data_buffer.append(item)
        if len(self.data_buffer) > self.buffer_max_size:
            self.data_buffer = self.data_buffer[-self.buffer_max_size:]
    
    def _summarize_data(self, data: Dict) -> Dict:
        """Create a concise summary of collected data."""
        summary = {
            'timestamp': datetime.utcnow().isoformat(),
            'system': {
                'cpu_percent': data.get('system_metrics', {}).get('cpu_percent', 0),
                'memory_percent': data.get('system_metrics', {}).get('memory_percent', 0),
                'process_count': len(data.get('system_metrics', {}).get('processes', []))
            },
            'threats': {
                'active_count': len(data.get('threat_intel', {}).get('active_threats', [])),
                'high_severity': sum(1 for t in data.get('threat_intel', {}).get('active_threats', []) 
                                   if t.get('severity', 0) >= 7)
            },
            'persistence': {
                'active_vectors': sum(1 for v in data.get('persistence_status', {}).values() 
                                    if v.get('status') == 'active'),
                'total_vectors': len(data.get('persistence_status', {}))
            }
        }
        return summary
    
    async def _feed_to_llm(self, data: Dict):
        """Feed data to the LLM as context."""
        # Convert to text
        data_text = json.dumps(data, indent=2)
        
        # Create a context update prompt
        prompt = f"""
UPDATE AI CONTEXT WITH LIVE OPERATIONAL DATA:

{data_text}

This data should be incorporated into your understanding of the current system state.
Acknowledge receipt by summarizing the most important piece of information.
"""
        
        # Send to LLM
        try:
            response = self.llm.generate(prompt, system_context={'data_source': 'auto_feeder'})
            if response.get('success'):
                print(f"[Data Feeder] LLM acknowledged: {response['response'][:100]}...")
            else:
                print(f"[Data Feeder] LLM feed failed: {response.get('error')}")
        
        except Exception as e:
            print(f"[Data Feeder] Feed error: {e}")
    
    # Data collection methods
    def _collect_system_metrics(self) -> Dict:
        """Collect current system metrics."""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': {d.mountpoint: psutil.disk_usage(d.mountpoint).percent 
                          for d in psutil.disk_partitions()},
            'processes': [p.info for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent'])],
            'boot_time': psutil.boot_time(),
            'timestamp': time.time()
        }
    
    def _collect_network_events(self) -> Dict:
        """Collect recent network events."""
        # Implementation using /proc/net/tcp or netstat
        return {
            'connections': self._get_network_connections(),
            'interface_stats': self._get_interface_stats(),
            'timestamp': time.time()
        }
    
    def _collect_threat_intel(self) -> Dict:
        """Collect threat intelligence from database."""
        # Query the threat intelligence database
        import sqlite3
        conn = sqlite3.connect('/opt/sysaux/ai/threats.db')
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT ip, threat_type, severity, last_seen 
            FROM threats 
            WHERE last_seen > datetime('now', '-1 hour')
            ORDER BY severity DESC
            LIMIT 20
        """)
        
        threats = []
        for row in cursor.fetchall():
            threats.append({
                'ip': row[0],
                'threat_type': row[1],
                'severity': row[2],
                'last_seen': row[3]
            })
        
        conn.close()
        
        return {
            'active_threats': threats,
            'total_threats': len(threats),
            'timestamp': time.time()
        }
    
    def _get_network_connections(self) -> List:
        """Get active network connections."""
        connections = []
        for conn in psutil.net_connections():
            connections.append({
                'fd': conn.fd,
                'family': str(conn.family),
                'type': str(conn.type),
                'laddr': conn.laddr,
                'raddr': conn.raddr,
                'status': conn.status,
                'pid': conn.pid
            })
        return connections
    
    def _get_interface_stats(self) -> Dict:
        """Get network interface statistics."""
        stats = {}
        for iface, addrs in psutil.net_if_addrs().items():
            stats[iface] = {
                'addresses': [str(addr.address) for addr in addrs],
                'is_up': iface in psutil.net_if_stats() and psutil.net_if_stats()[iface].isup
            }
        return stats

class LogFileWatcher(FileSystemEventHandler):
    """Watches log files for changes and feeds them to the LLM."""
    
    def __init__(self, data_stream):
        self.data_stream = data_stream
    
    def on_modified(self, event):
        """When a log file is modified, read new lines."""
        if not event.is_directory and event.src_path.endswith('.log'):
            self._process_log_file(event.src_path)
    
    def _process_log_file(self, file_path: str):
        """Process new entries in a log file."""
        try:
            # Get last few lines
            with open(file_path, 'r') as f:
                lines = f.readlines()[-10:]  # Last 10 lines
            
            if lines:
                log_data = {
                    'file': file_path,
                    'new_entries': lines,
                    'timestamp': time.time()
                }
                
                # Add to buffer
                self.data_stream._add_to_buffer({
                    'type': 'log_update',
                    'timestamp': time.time(),
                    'data': log_data
                })
        
        except Exception as e:
            print(f"[Log Watcher] Error processing {file_path}: {e}")

# Integration with main Sophia system
async def integrate_data_feeder(sophia_system):
    """Integrate the data feeder with the main Sophia system."""
    from llm_bridge import LLMBridge, LLM_CONFIG
    
    # Create LLM bridge
    llm_bridge = LLMBridge(LLM_CONFIG)
    
    # Create data feeder
    data_feeder = OperationalDataStream(llm_bridge)
    
    # Start data feeder
    await data_feeder.start()
    
    # Update Sophia system with the feeder
    sophia_system.data_feeder = data_feeder
    sophia_system.llm_bridge = llm_bridge
    
    # Replace the existing LLM in SophiaAI with our bridge
    sophia_system.ai_core.llm = llm_bridge
    
    print("[Integration] Data feeder integrated with Sophia system")
    return sophia_system