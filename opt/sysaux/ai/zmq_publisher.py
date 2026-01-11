#!/usr/bin/env python3
"""
ZMQ PUBLISHER FOR REAL-TIME OPERATIONAL DATA
Publishes system events to the data feeder.
"""

import zmq
import json
import time
import psutil
from datetime import datetime

context = zmq.Context()
publisher = context.socket(zmq.PUB)
publisher.bind("tcp://*:5555")

print("[ZMQ Publisher] Broadcasting on tcp://*:5555")

while True:
    # Collect and publish system metrics
    metrics = {
        'type': 'system_metrics',
        'timestamp': datetime.utcnow().isoformat(),
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory_percent': psutil.virtual_memory().percent,
        'disk_usage': {d.mountpoint: psutil.disk_usage(d.mountpoint).percent 
                      for d in psutil.disk_partitions()},
        'process_count': len(list(psutil.process_iter()))
    }
    
    publisher.send_string(json.dumps(metrics))
    
    # Publish network connections every 30 seconds
    if int(time.time()) % 30 == 0:
        connections = []
        for conn in psutil.net_connections():
            connections.append({
                'fd': conn.fd,
                'status': conn.status,
                'laddr': str(conn.laddr),
                'raddr': str(conn.raddr) if conn.raddr else None,
                'pid': conn.pid
            })
        
        network_data = {
            'type': 'network_connections',
            'timestamp': datetime.utcnow().isoformat(),
            'connections': connections[:50]  # First 50
        }
        
        publisher.send_string(json.dumps(network_data))
    
    time.sleep(5)  # Publish every 5 seconds