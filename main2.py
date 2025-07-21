#!/usr/bin/env python3
"""
Advanced Smart Home Security Dashboard
A comprehensive cybersecurity platform for IoT device monitoring and threat detection
"""

import nmap
import sqlite3
import json
import threading
import time
import hashlib
import requests
import smtplib
import logging
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import subprocess
import re
import socket
from scapy.all import *
import psutil
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
from collections import defaultdict, deque
import base64
import ssl
import paramiko
import ftplib
import telnetlib
from urllib.parse import urlparse
import dns.resolver
import whois
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

class AdvancedSecurityDashboard:
    def __init__(self):
        self.devices = {}
        self.alerts = []
        self.network_traffic = deque(maxlen=1000)
        self.threat_intelligence = {}
        self.anomaly_detector = None
        self.monitoring = False
        self.packet_capture = False
        self.vulnerability_db = self.load_vulnerability_database()
        self.threat_feeds = self.load_threat_feeds()
        self.ml_models = self.initialize_ml_models()
        self.init_database()
        self.nm = nmap.PortScanner()
        
        # Default credentials database
        self.default_credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
            ('root', 'root'), ('root', 'password'), ('root', ''),
            ('user', 'user'), ('guest', 'guest'), ('test', 'test'),
            ('admin', '12345'), ('admin', 'admin123'), ('pi', 'raspberry')
        ]
        
        # Common vulnerable ports
        self.vulnerable_ports = {
            21: 'FTP', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL'
        }
        
        # IoT specific ports
        self.iot_ports = {
            1883: 'MQTT', 5683: 'CoAP', 8080: 'HTTP-Alt',
            8883: 'MQTT-SSL', 9443: 'HTTPS-Alt'
        }
        
        # Start background services
        self.start_background_services()
    
    def init_database(self):
        """Initialize enhanced SQLite database"""
        conn = sqlite3.connect('advanced_security.db')
        cursor = conn.cursor()
        
        # Enhanced devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                hostname TEXT,
                vendor TEXT,
                os_fingerprint TEXT,
                device_type TEXT,
                open_ports TEXT,
                services TEXT,
                firmware_version TEXT,
                last_vulnerability_scan TEXT,
                security_score INTEGER,
                risk_level TEXT,
                first_seen TEXT,
                last_seen TEXT,
                is_trusted BOOLEAN DEFAULT 0,
                notes TEXT
            )
        ''')
        
        # Enhanced alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                device_mac TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                port INTEGER,
                message TEXT,
                severity TEXT,
                status TEXT DEFAULT 'open',
                response_action TEXT,
                false_positive BOOLEAN DEFAULT 0
            )
        ''')
        
        # Network traffic table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                port INTEGER,
                packet_size INTEGER,
                flags TEXT,
                payload_hash TEXT
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT,
                cve_id TEXT,
                severity TEXT,
                description TEXT,
                discovered_date TEXT,
                patched BOOLEAN DEFAULT 0,
                patch_available BOOLEAN DEFAULT 0
            )
        ''')
        
        # Threat intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator TEXT,
                indicator_type TEXT,
                threat_type TEXT,
                confidence INTEGER,
                source TEXT,
                last_updated TEXT
            )
        ''')
        
        # Compliance table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_mac TEXT,
                framework TEXT,
                requirement TEXT,
                status TEXT,
                last_check TEXT,
                details TEXT
            )
        ''')
        
        # Incident response table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE,
                title TEXT,
                description TEXT,
                severity TEXT,
                status TEXT,
                created_date TEXT,
                resolved_date TEXT,
                assigned_to TEXT,
                affected_devices TEXT,
                response_actions TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def load_vulnerability_database(self):
        """Load CVE vulnerability database"""
        # In production, this would connect to NVD or similar
        return {
            'CVE-2023-1234': {
                'severity': 'HIGH',
                'description': 'Default credentials vulnerability',
                'affected_products': ['IoT Camera', 'Smart Thermostat']
            },
            'CVE-2023-5678': {
                'severity': 'CRITICAL',
                'description': 'Remote code execution in web interface',
                'affected_products': ['Generic IoT Device']
            }
        }
    
    def load_threat_feeds(self):
        """Load threat intelligence feeds"""
        # This would integrate with real threat feeds
        return {
            'malicious_ips': ['192.168.1.100', '10.0.0.50'],
            'malicious_domains': ['malware.example.com', 'c2.badguy.net'],
            'known_malware_hashes': ['abc123', 'def456']
        }
    
    def initialize_ml_models(self):
        """Initialize machine learning models for anomaly detection"""
        return {
            'traffic_anomaly': IsolationForest(contamination=0.1, random_state=42),
            'behavior_anomaly': IsolationForest(contamination=0.05, random_state=42),
            'scaler': StandardScaler()
        }
    
    def start_background_services(self):
        """Start background monitoring services"""
        threading.Thread(target=self.threat_intelligence_updater, daemon=True).start()
        threading.Thread(target=self.continuous_monitoring, daemon=True).start()
    
    def get_network_range(self):
        """Enhanced network range detection"""
        try:
            # Get all network interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127'):
                        ip = addr.address
                        netmask = addr.netmask
                        # Calculate network range
                        network = self.calculate_network_range(ip, netmask)
                        return network
        except:
            pass
        return "192.168.1.0/24"
    
    def calculate_network_range(self, ip, netmask):
        """Calculate network range from IP and netmask"""
        import ipaddress
        try:
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except:
            return "192.168.1.0/24"
    
    def advanced_device_discovery(self):
        """Enhanced device discovery with fingerprinting"""
        network_range = self.get_network_range()
        logger.info(f"Starting advanced scan on {network_range}")
        
        try:
            # Multi-stage scanning
            # 1. Host discovery
            self.nm.scan(hosts=network_range, arguments='-sn -T4')
            active_hosts = [host for host in self.nm.all_hosts() if self.nm[host].state() == 'up']
            
            # 2. Service detection for each host
            for host in active_hosts:
                device_info = self.comprehensive_device_scan(host)
                if device_info:
                    self.devices[device_info['mac_address']] = device_info
                    self.store_device(device_info)
                    
                    # Run security tests
                    self.run_security_assessment(device_info)
                    
                    # Check threat intelligence
                    self.check_threat_intelligence(device_info)
                    
                    # Update ML models
                    self.update_anomaly_models(device_info)
                    
        except Exception as e:
            logger.error(f"Error in device discovery: {e}")
    
    def comprehensive_device_scan(self, ip):
        """Comprehensive device scanning and fingerprinting"""
        try:
            # Basic info
            mac_address = self.get_mac_address(ip)
            if not mac_address:
                return None
            
            # OS fingerprinting
            os_info = self.os_fingerprinting(ip)
            
            # Service detection
            services = self.service_detection(ip)
            
            # Banner grabbing
            banners = self.banner_grabbing(ip, services)
            
            # Device classification
            device_type = self.classify_device(mac_address, services, banners)
            
            device_info = {
                'ip_address': ip,
                'mac_address': mac_address,
                'hostname': self.get_hostname(ip),
                'vendor': self.get_vendor(mac_address),
                'os_fingerprint': os_info,
                'device_type': device_type,
                'open_ports': json.dumps(list(services.keys())),
                'services': json.dumps(services),
                'banners': banners,
                'last_seen': datetime.now().isoformat(),
                'security_score': 0,  # Will be calculated
                'risk_level': 'LOW'
            }
            
            return device_info
            
        except Exception as e:
            logger.error(f"Error scanning device {ip}: {e}")
            return None
    
    def os_fingerprinting(self, ip):
        """OS fingerprinting using nmap"""
        try:
            self.nm.scan(ip, arguments='-O -T4')
            if ip in self.nm.all_hosts():
                if 'osmatch' in self.nm[ip]:
                    matches = self.nm[ip]['osmatch']
                    if matches:
                        return matches[0]['name']
        except:
            pass
        return "Unknown"
    
    def service_detection(self, ip):
        """Detect services running on open ports"""
        services = {}
        try:
            # Scan common ports
            port_range = "21-23,25,53,80,110,135,139,443,445,993,995,1433,1883,3306,3389,5432,5683,8080,8883,9443"
            self.nm.scan(ip, port_range, arguments='-sV -T4')
            
            if ip in self.nm.all_hosts():
                for protocol in self.nm[ip].all_protocols():
                    ports = self.nm[ip][protocol].keys()
                    for port in ports:
                        port_info = self.nm[ip][protocol][port]
                        if port_info['state'] == 'open':
                            services[port] = {
                                'protocol': protocol,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
        except Exception as e:
            logger.error(f"Error in service detection for {ip}: {e}")
        
        return services
    
    def banner_grabbing(self, ip, services):
        """Grab banners from services"""
        banners = {}
        
        for port, service_info in services.items():
            try:
                if service_info['service'] in ['http', 'https']:
                    banners[port] = self.grab_http_banner(ip, port, service_info['service'])
                elif service_info['service'] == 'ssh':
                    banners[port] = self.grab_ssh_banner(ip, port)
                elif service_info['service'] == 'ftp':
                    banners[port] = self.grab_ftp_banner(ip, port)
                elif service_info['service'] == 'telnet':
                    banners[port] = self.grab_telnet_banner(ip, port)
            except Exception as e:
                logger.error(f"Error grabbing banner from {ip}:{port}: {e}")
        
        return banners
    
    def grab_http_banner(self, ip, port, protocol):
        """Grab HTTP/HTTPS banner"""
        try:
            url = f"{protocol}://{ip}:{port}"
            response = requests.get(url, timeout=5, verify=False)
            return {
                'server': response.headers.get('Server', ''),
                'powered_by': response.headers.get('X-Powered-By', ''),
                'status_code': response.status_code,
                'title': self.extract_title(response.text)
            }
        except:
            return {}
    
    def grab_ssh_banner(self, ip, port):
        """Grab SSH banner"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username='invalid', password='invalid', timeout=5)
        except paramiko.AuthenticationException:
            return {'banner': 'SSH service detected'}
        except Exception as e:
            return {'banner': str(e)}
    
    def grab_ftp_banner(self, ip, port):
        """Grab FTP banner"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=5)
            banner = ftp.getwelcome()
            ftp.quit()
            return {'banner': banner}
        except Exception as e:
            return {'banner': str(e)}
    
    def grab_telnet_banner(self, ip, port):
        """Grab Telnet banner"""
        try:
            tn = telnetlib.Telnet(ip, port, timeout=5)
            banner = tn.read_until(b"login:", timeout=5).decode('utf-8', errors='ignore')
            tn.close()
            return {'banner': banner}
        except Exception as e:
            return {'banner': str(e)}
    
    def extract_title(self, html):
        """Extract title from HTML"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def classify_device(self, mac, services, banners):
        """Enhanced device classification"""
        vendor = self.get_vendor(mac)
        
        # Check for IoT-specific services
        if any(port in [1883, 5683, 8883] for port in services.keys()):
            return 'IoT Device'
        
        # Check banners for device types
        for port, banner in banners.items():
            if isinstance(banner, dict):
                title = banner.get('title', '').lower()
                server = banner.get('server', '').lower()
                
                if any(keyword in title for keyword in ['camera', 'webcam', 'surveillance']):
                    return 'IP Camera'
                elif any(keyword in title for keyword in ['router', 'gateway', 'access point']):
                    return 'Network Device'
                elif any(keyword in title for keyword in ['thermostat', 'hvac', 'climate']):
                    return 'Smart Thermostat'
                elif any(keyword in server for keyword in ['apache', 'nginx', 'iis']):
                    return 'Web Server'
        
        # Vendor-based classification
        if 'raspberry' in vendor.lower():
            return 'Single Board Computer'
        elif 'apple' in vendor.lower():
            return 'Apple Device'
        elif 'samsung' in vendor.lower():
            return 'Samsung Device'
        
        return 'Unknown Device'
    
    def run_security_assessment(self, device):
        """Comprehensive security assessment"""
        try:
            # Test for default credentials
            self.test_default_credentials(device)
            
            # Check for known vulnerabilities
            self.check_vulnerabilities(device)
            
            # Analyze SSL/TLS configuration
            self.analyze_ssl_config(device)
            
            # Check for unencrypted protocols
            self.check_unencrypted_protocols(device)
            
            # Calculate security score
            device['security_score'] = self.calculate_enhanced_security_score(device)
            device['risk_level'] = self.determine_risk_level(device['security_score'])
            
            # Generate alerts for findings
            self.generate_security_alerts(device)
            
        except Exception as e:
            logger.error(f"Error in security assessment: {e}")
    
    def test_default_credentials(self, device):
        """Test for default credentials"""
        ip = device['ip_address']
        services = json.loads(device.get('services', '{}'))
        
        for port, service_info in services.items():
            service_name = service_info.get('service', '')
            
            if service_name == 'http':
                self.test_http_credentials(ip, port, device)
            elif service_name == 'ssh':
                self.test_ssh_credentials(ip, port, device)
            elif service_name == 'ftp':
                self.test_ftp_credentials(ip, port, device)
            elif service_name == 'telnet':
                self.test_telnet_credentials(ip, port, device)
    
    def test_http_credentials(self, ip, port, device):
        """Test HTTP authentication"""
        try:
            for username, password in self.default_credentials:
                url = f"http://{ip}:{port}/login"
                data = {'username': username, 'password': password}
                
                response = requests.post(url, data=data, timeout=5)
                if response.status_code == 200 and 'dashboard' in response.text.lower():
                    self.create_alert(
                        'DEFAULT_CREDENTIALS',
                        device['mac_address'],
                        f"Default credentials found: {username}:{password}",
                        'HIGH'
                    )
                    break
        except:
            pass
    
    def test_ssh_credentials(self, ip, port, device):
        """Test SSH authentication"""
        try:
            for username, password in self.default_credentials:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(ip, port=port, username=username, password=password, timeout=5)
                    self.create_alert(
                        'DEFAULT_CREDENTIALS',
                        device['mac_address'],
                        f"SSH default credentials found: {username}:{password}",
                        'CRITICAL'
                    )
                    ssh.close()
                    break
                except paramiko.AuthenticationException:
                    continue
                except:
                    break
        except:
            pass
    
    def test_ftp_credentials(self, ip, port, device):
        """Test FTP authentication"""
        try:
            for username, password in self.default_credentials:
                ftp = ftplib.FTP()
                try:
                    ftp.connect(ip, port, timeout=5)
                    ftp.login(username, password)
                    self.create_alert(
                        'DEFAULT_CREDENTIALS',
                        device['mac_address'],
                        f"FTP default credentials found: {username}:{password}",
                        'HIGH'
                    )
                    ftp.quit()
                    break
                except ftplib.error_perm:
                    continue
                except:
                    break
        except:
            pass
    
    def test_telnet_credentials(self, ip, port, device):
        """Test Telnet authentication"""
        try:
            for username, password in self.default_credentials:
                tn = telnetlib.Telnet(ip, port, timeout=5)
                try:
                    tn.read_until(b"login:", timeout=5)
                    tn.write(username.encode('ascii') + b"\n")
                    tn.read_until(b"Password:", timeout=5)
                    tn.write(password.encode('ascii') + b"\n")
                    
                    result = tn.read_until(b"#", timeout=5)
                    if b"#" in result:
                        self.create_alert(
                            'DEFAULT_CREDENTIALS',
                            device['mac_address'],
                            f"Telnet default credentials found: {username}:{password}",
                            'CRITICAL'
                        )
                        tn.close()
                        break
                    tn.close()
                except:
                    continue
        except:
            pass
    
    def check_vulnerabilities(self, device):
        """Check for known vulnerabilities"""
        device_type = device.get('device_type', '')
        services = json.loads(device.get('services', '{}'))
        
        # Check CVE database
        for cve_id, vuln_info in self.vulnerability_db.items():
            if device_type in vuln_info['affected_products']:
                self.create_vulnerability_alert(device, cve_id, vuln_info)
        
        # Check for specific service vulnerabilities
        for port, service_info in services.items():
            service_name = service_info.get('service', '')
            version = service_info.get('version', '')
            
            if service_name == 'http' and not version:
                self.create_alert(
                    'VERSION_DISCLOSURE',
                    device['mac_address'],
                    f"Web server version not disclosed on port {port}",
                    'LOW'
                )
    
    def analyze_ssl_config(self, device):
        """Analyze SSL/TLS configuration"""
        services = json.loads(device.get('services', '{}'))
        
        for port, service_info in services.items():
            if service_info.get('service') == 'https':
                self.check_ssl_certificate(device, port)
    
    def check_ssl_certificate(self, device, port):
        """Check SSL certificate configuration"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((device['ip_address'], port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=device['ip_address']) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        self.create_alert(
                            'SSL_EXPIRY',
                            device['mac_address'],
                            f"SSL certificate expires in {days_until_expiry} days",
                            'MEDIUM'
                        )
        except Exception as e:
            self.create_alert(
                'SSL_ERROR',
                device['mac_address'],
                f"SSL certificate error on port {port}: {str(e)}",
                'LOW'
            )
    
    def check_unencrypted_protocols(self, device):
        """Check for unencrypted protocols"""
        services = json.loads(device.get('services', '{}'))
        
        unencrypted_services = ['http', 'ftp', 'telnet', 'smtp']
        
        for port, service_info in services.items():
            service_name = service_info.get('service', '')
            
            if service_name in unencrypted_services:
                self.create_alert(
                    'UNENCRYPTED_PROTOCOL',
                    device['mac_address'],
                    f"Unencrypted {service_name} service on port {port}",
                    'MEDIUM'
                )
    
    def calculate_enhanced_security_score(self, device):
        """Calculate enhanced security score"""
        score = 100
        services = json.loads(device.get('services', '{}'))
        
        # Deduct points for vulnerable services
        for port, service_info in services.items():
            service_name = service_info.get('service', '')
            
            if service_name in ['telnet', 'ftp']:
                score -= 20
            elif service_name == 'http':
                score -= 10
            elif int(port) in self.vulnerable_ports:
                score -= 5
        
        # Check for default credentials
        if any(alert['alert_type'] == 'DEFAULT_CREDENTIALS' for alert in self.alerts 
               if alert['device_mac'] == device['mac_address']):
            score -= 30
        
        # Check for SSL issues
        if any(alert['alert_type'] in ['SSL_EXPIRY', 'SSL_ERROR'] for alert in self.alerts
               if alert['device_mac'] == device['mac_address']):
            score -= 10
        
        return max(0, score)
    
    def determine_risk_level(self, score):
        """Determine risk level based on score"""
        if score >= 80:
            return 'LOW'
        elif score >= 60:
            return 'MEDIUM'
        elif score >= 40:
            return 'HIGH'
        else:
            return 'CRITICAL'
    
    def generate_security_alerts(self, device):
        """Generate security alerts based on findings"""
        if device['security_score'] < 50:
            self.create_alert(
                'LOW_SECURITY_SCORE',
                device['mac_address'],
                f"Device has low security score: {device['security_score']}/100",
                'HIGH'
            )
        
        if device['device_type'] == 'Unknown Device':
            self.create_alert(
                'UNKNOWN_DEVICE',
                device['mac_address'],
                f"Unknown device type detected: {device['ip_address']}",
                'MEDIUM'
            )
    
    def create_vulnerability_alert(self, device, cve_id, vuln_info):
        """Create vulnerability alert"""
        self.create_alert(
            'VULNERABILITY',
            device['mac_address'],
            f"Vulnerability {cve_id}: {vuln_info['description']}",
            vuln_info['severity']
        )
        
        # Store in vulnerabilities table
        conn = sqlite3.connect('advanced_security.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO vulnerabilities 
            (device_mac, cve_id, severity, description, discovered_date)
            VALUES (?, ?, ?, ?, ?)
        ''', (device['mac_address'], cve_id, vuln_info['severity'], 
              vuln_info['description'], datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    def check_threat_intelligence(self, device):
        """Check device against threat intelligence"""
        ip = device['ip_address']
        
        # Check against malicious IPs
        if ip in self.threat_feeds['malicious_ips']:
            self.create_alert(
                'THREAT_INTELLIGENCE',
                device['mac_address'],
                f"Device IP {ip} found in threat intelligence feeds",
                'CRITICAL'
            )
        
        # Check DNS queries for malicious domains
        self.check_dns_queries(device)
    
    def check_dns_queries(self, device):
        """Check DNS queries for malicious domains"""
        # This would monitor DNS queries in real implementation
        pass
    
    def start_packet_capture(self):
        """Start packet capture for traffic analysis"""
        if not self.packet_capture:
            self.packet_capture = True
            threading.Thread(target=self.packet_capture_loop, daemon=True).start()
    
    def packet_capture_loop(self):
        """Main packet capture loop"""
        def packet_handler(packet):
            try:
                if packet.haslayer(IP):
                    self.analyze_packet(packet)
            except Exception as e:
                logger.error(f"Error analyzing packet: {e}")
        
        try:
            sniff(prn=packet_handler, store=0, stop_filter=lambda x: not self.packet_capture)
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
    
    def analyze_packet(self, packet):
        """Analyze captured packet"""
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        
        # Store traffic data
        traffic_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': ip_layer.src,
            'destination_ip': ip_layer.dst,
            'protocol': ip_layer.proto,
            'packet_size': len(packet)
        }
        
        if packet.haslayer(TCP):
            traffic_data['port'] = packet[TCP].dport
            traffic_data['flags'] = packet[TCP].flags
        elif packet.haslayer(UDP):
            traffic_data['port'] = packet[UDP].dport
            traffic_data['flags'] = 'UDP'
        
        self.network_traffic.append(traffic_data)
        
        # Check for suspicious patterns
        self.check_suspicious_traffic(traffic_data, packet)
        
        # Update anomaly detection
        self.update_traffic_anomaly_detection(traffic_data)
    
    def check_suspicious_traffic(self, traffic_data, packet):
        """Check for suspicious traffic patterns"""
        src_ip = traffic_data['source_ip']
        dst_ip = traffic_data['destination_ip']