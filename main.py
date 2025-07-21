"""
Smart Home Security Dashboard
A cybersecurity tool for monitoring IoT devices on your home network
"""

import nmap
import sqlite3
import json
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
import requests
import subprocess
import re
import socket
from scapy.all import *
import psutil

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

class SmartHomeSecurityDashboard:
    def __init__(self):
        self.devices = {}
        self.alerts = []
        self.monitoring = False
        self.init_database()
        self.nm = nmap.PortScanner()
        
    def init_database(self):
        """Initialize SQLite database for storing device info and alerts"""
        conn = sqlite3.connect('security_dashboard.db')
        cursor = conn.cursor()
        
        # Create devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                vendor TEXT,
                first_seen TEXT,
                last_seen TEXT,
                device_type TEXT,
                security_score INTEGER,
                is_trusted BOOLEAN DEFAULT 0
            )
        ''')
        
        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                device_mac TEXT,
                message TEXT,
                severity TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def get_network_range(self):
        """Get the local network range"""
        try:
            # Get default gateway
            result = subprocess.run(['ip', 'route', 'show', 'default'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                gateway = result.stdout.split()[2]
                # Assume /24 subnet
                network_parts = gateway.split('.')
                network_range = f"{'.'.join(network_parts[:3])}.0/24"
                return network_range
        except:
            pass
        return "192.168.1.0/24"  # Default fallback
    
    def discover_devices(self):
        """Discover devices on the network"""
        network_range = self.get_network_range()
        print(f"Scanning network range: {network_range}")
        
        try:
            # Perform network scan
            self.nm.scan(hosts=network_range, arguments='-sn')
            
            for host in self.nm.all_hosts():
                if self.nm[host].state() == 'up':
                    mac_address = self.get_mac_address(host)
                    if mac_address:
                        device_info = {
                            'ip_address': host,
                            'mac_address': mac_address,
                            'hostname': self.get_hostname(host),
                            'vendor': self.get_vendor(mac_address),
                            'last_seen': datetime.now().isoformat(),
                            'device_type': self.guess_device_type(mac_address, host),
                            'security_score': self.calculate_security_score(host)
                        }
                        
                        self.devices[mac_address] = device_info
                        self.store_device(device_info)
                        
                        # Check for security issues
                        self.check_device_security(device_info)
                        
        except Exception as e:
            print(f"Error during device discovery: {e}")
    
    def get_mac_address(self, ip):
        """Get MAC address for an IP"""
        try:
            result = subprocess.run(['arp', '-n', ip], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except:
            pass
        return None
    
    def get_hostname(self, ip):
        """Get hostname for an IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def get_vendor(self, mac):
        """Get vendor information from MAC address"""
        # This is a simplified version - in production, you'd use an OUI database
        vendors = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '00:0c:29': 'VMware',
            '00:1b:21': 'Apple',
            '00:26:bb': 'Apple',
            '28:cd:c4': 'Apple',
            'b8:27:eb': 'Raspberry Pi',
            'dc:a6:32': 'Raspberry Pi',
            '00:16:3e': 'Xensource',
            '52:54:00': 'QEMU'
        }
        
        mac_prefix = mac[:8].lower()
        return vendors.get(mac_prefix, "Unknown")
    
    def guess_device_type(self, mac, ip):
        """Guess device type based on MAC and other characteristics"""
        vendor = self.get_vendor(mac)
        
        if 'raspberry' in vendor.lower():
            return 'IoT Device'
        elif 'apple' in vendor.lower():
            return 'Mobile/Computer'
        elif 'vmware' in vendor.lower() or 'virtualbox' in vendor.lower():
            return 'Virtual Machine'
        else:
            # Try to determine based on open ports
            try:
                nm_result = self.nm.scan(ip, '22,23,80,443,8080')
                if ip in nm_result['scan']:
                    ports = nm_result['scan'][ip].get('tcp', {})
                    if 80 in ports or 443 in ports:
                        return 'IoT Device'
                    elif 22 in ports:
                        return 'Server/Computer'
            except:
                pass
            
            return 'Unknown'
    
    def calculate_security_score(self, ip):
        """Calculate a basic security score for a device"""
        score = 100
        
        try:
            # Check for common vulnerable ports
            vulnerable_ports = [23, 21, 135, 139, 445, 1433, 3389]
            nm_result = self.nm.scan(ip, ','.join(map(str, vulnerable_ports)))
            
            if ip in nm_result['scan']:
                open_ports = nm_result['scan'][ip].get('tcp', {})
                for port in vulnerable_ports:
                    if port in open_ports and open_ports[port]['state'] == 'open':
                        score -= 20
                        
                # Check for too many open ports
                if len(open_ports) > 10:
                    score -= 10
                    
        except Exception as e:
            print(f"Error calculating security score: {e}")
        
        return max(0, score)
    
    def check_device_security(self, device):
        """Check for security issues with a device"""
        alerts = []
        
        # Check security score
        if device['security_score'] < 50:
            alerts.append({
                'type': 'LOW_SECURITY_SCORE',
                'message': f"Device {device['hostname']} has low security score: {device['security_score']}",
                'severity': 'HIGH'
            })
        
        # Check for unknown devices
        if device['vendor'] == 'Unknown':
            alerts.append({
                'type': 'UNKNOWN_DEVICE',
                'message': f"Unknown device detected: {device['ip_address']}",
                'severity': 'MEDIUM'
            })
        
        # Store alerts
        for alert in alerts:
            self.create_alert(alert['type'], device['mac_address'], alert['message'], alert['severity'])
    
    def create_alert(self, alert_type, device_mac, message, severity):
        """Create and store a security alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'alert_type': alert_type,
            'device_mac': device_mac,
            'message': message,
            'severity': severity
        }
        
        self.alerts.insert(0, alert)  # Add to beginning for latest first
        
        # Store in database
        conn = sqlite3.connect('security_dashboard.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, device_mac, message, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert['timestamp'], alert['alert_type'], alert['device_mac'], 
              alert['message'], alert['severity']))
        conn.commit()
        conn.close()
        
        # Emit to web interface
        socketio.emit('new_alert', alert)
    
    def store_device(self, device):
        """Store device information in database"""
        conn = sqlite3.connect('security_dashboard.db')
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO devices 
            (mac_address, ip_address, hostname, vendor, first_seen, last_seen, device_type, security_score)
            VALUES (?, ?, ?, ?, 
                    COALESCE((SELECT first_seen FROM devices WHERE mac_address = ?), ?),
                    ?, ?, ?)
        ''', (device['mac_address'], device['ip_address'], device['hostname'], 
              device['vendor'], device['mac_address'], device['last_seen'], 
              device['last_seen'], device['device_type'], device['security_score']))
        
        conn.commit()
        conn.close()
    
    def start_monitoring(self):
        """Start continuous monitoring"""
        self.monitoring = True
        
        def monitor_loop():
            while self.monitoring:
                print("Scanning for devices...")
                self.discover_devices()
                
                # Emit updated device list to web interface
                socketio.emit('devices_updated', list(self.devices.values()))
                
                time.sleep(30)  # Scan every 30 seconds
        
        monitor_thread = threading.Thread(target=monitor_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
    
    def get_devices(self):
        """Get all discovered devices"""
        return list(self.devices.values())
    
    def get_alerts(self, limit=50):
        """Get recent alerts"""
        return self.alerts[:limit]

# Initialize the dashboard
dashboard = SmartHomeSecurityDashboard()

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/devices')
def get_devices():
    return jsonify(dashboard.get_devices())

@app.route('/api/alerts')
def get_alerts():
    return jsonify(dashboard.get_alerts())

@app.route('/api/start_monitoring')
def start_monitoring():
    dashboard.start_monitoring()
    return jsonify({'status': 'started'})

@app.route('/api/stop_monitoring')
def stop_monitoring():
    dashboard.stop_monitoring()
    return jsonify({'status': 'stopped'})

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit('devices_updated', dashboard.get_devices())
    emit('alerts_updated', dashboard.get_alerts())

if __name__ == '__main__':
    # Start monitoring on startup
    dashboard.start_monitoring()
    
    # Run the Flask app
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)