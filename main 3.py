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
import base64
import ssl
import socket
import requests
import subprocess
import re
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from urllib.parse import urlparse
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from scapy.all import *
import psutil
import paramiko
import ftplib
import telnetlib
import threading
from collections import defaultdict, deque
import ipaddress
import dns.resolver
import whois
import yara
import hashlib
import os
import logging
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import xml.etree.ElementTree as ET

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app, cors_allowed_origins="*")

class ThreatIntelligence:
    def __init__(self):
        self.malicious_ips = set()
        self.threat_feeds = {
            'malware_domains': 'https://malware-domains.com/files/domains.txt',
            'emerging_threats': 'https://rules.emergingthreats.net/open/suricata/rules/'
        }
        self.load_threat_feeds()
    
    def load_threat_feeds(self):
        """Load threat intelligence feeds"""
        try:
            # Load malicious IPs from various sources
            self.malicious_ips.update([
                '192.168.1.100',  # Example suspicious IP
                '10.0.0.50',      # Example internal threat
            ])
            logger.info(f"Loaded {len(self.malicious_ips)} malicious IPs")
        except Exception as e:
            logger.error(f"Error loading threat feeds: {e}")
    
    def check_ip_reputation(self, ip):
        """Check if IP is in threat intelligence feeds"""
        return ip in self.malicious_ips
    
    def get_threat_score(self, ip):
        """Calculate threat score for an IP"""
        score = 0
        if self.check_ip_reputation(ip):
            score += 50
        # Add more threat intelligence checks here
        return min(score, 100)

class VulnerabilityScanner:
    def __init__(self):
        self.common_credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', ''),
            ('root', 'root'), ('root', 'password'), ('root', ''),
            ('user', 'user'), ('guest', 'guest'), ('test', 'test'),
            ('admin', '123456'), ('admin', 'default')
        ]
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 8080: 'HTTP-Alt'
        }
        self.vulnerability_db = self.load_vulnerability_db()
    
    def load_vulnerability_db(self):
        """Load CVE vulnerability database"""
        return {
            'http': ['CVE-2021-44228', 'CVE-2021-45046'],  # Log4j
            'ssh': ['CVE-2020-15778', 'CVE-2021-28041'],
            'telnet': ['CVE-2020-10188', 'CVE-2019-19356'],
            'ftp': ['CVE-2020-15778', 'CVE-2021-3560']
        }
    
    def scan_vulnerabilities(self, ip, ports):
        """Comprehensive vulnerability scan"""
        vulnerabilities = []
        
        for port in ports:
            service = self.common_ports.get(port, 'unknown')
            
            # Check for default credentials
            if port in [21, 22, 23]:
                vulns = self.test_default_credentials(ip, port, service)
                vulnerabilities.extend(vulns)
            
            # Check for known CVEs
            if service.lower() in self.vulnerability_db:
                cves = self.vulnerability_db[service.lower()]
                vulnerabilities.extend([{
                    'type': 'CVE',
                    'port': port,
                    'service': service,
                    'cve': cve,
                    'severity': 'HIGH'
                } for cve in cves])
            
            # Check SSL/TLS vulnerabilities
            if port in [443, 993, 995]:
                ssl_vulns = self.check_ssl_vulnerabilities(ip, port)
                vulnerabilities.extend(ssl_vulns)
        
        return vulnerabilities
    
    def test_default_credentials(self, ip, port, service):
        """Test for default credentials"""
        vulnerabilities = []
        
        for username, password in self.common_credentials:
            try:
                if service.lower() == 'ssh' and port == 22:
                    if self.test_ssh_credentials(ip, port, username, password):
                        vulnerabilities.append({
                            'type': 'DEFAULT_CREDENTIALS',
                            'port': port,
                            'service': service,
                            'credentials': f"{username}:{password}",
                            'severity': 'CRITICAL'
                        })
                        break
                elif service.lower() == 'ftp' and port == 21:
                    if self.test_ftp_credentials(ip, port, username, password):
                        vulnerabilities.append({
                            'type': 'DEFAULT_CREDENTIALS',
                            'port': port,
                            'service': service,
                            'credentials': f"{username}:{password}",
                            'severity': 'CRITICAL'
                        })
                        break
                elif service.lower() == 'telnet' and port == 23:
                    if self.test_telnet_credentials(ip, port, username, password):
                        vulnerabilities.append({
                            'type': 'DEFAULT_CREDENTIALS',
                            'port': port,
                            'service': service,
                            'credentials': f"{username}:{password}",
                            'severity': 'CRITICAL'
                        })
                        break
            except Exception as e:
                logger.debug(f"Error testing credentials on {ip}:{port} - {e}")
        
        return vulnerabilities
    
    def test_ssh_credentials(self, ip, port, username, password):
        """Test SSH credentials"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port=port, username=username, password=password, timeout=5)
            ssh.close()
            return True
        except:
            return False
    
    def test_ftp_credentials(self, ip, port, username, password):
        """Test FTP credentials"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=5)
            ftp.login(username, password)
            ftp.quit()
            return True
        except:
            return False
    
    def test_telnet_credentials(self, ip, port, username, password):
        """Test Telnet credentials"""
        try:
            tn = telnetlib.Telnet(ip, port, timeout=5)
            tn.read_until(b"login: ")
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(password.encode('ascii') + b"\n")
            response = tn.read_until(b"$", timeout=5)
            tn.close()
            return b"$" in response or b"#" in response
        except:
            return False
    
    def check_ssl_vulnerabilities(self, ip, port):
        """Check SSL/TLS vulnerabilities"""
        vulnerabilities = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((ip, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    
                    # Check certificate expiry
                    if x509_cert.not_valid_after < datetime.utcnow():
                        vulnerabilities.append({
                            'type': 'EXPIRED_CERTIFICATE',
                            'port': port,
                            'service': 'SSL/TLS',
                            'severity': 'HIGH'
                        })
                    
                    # Check for weak ciphers
                    cipher = ssock.cipher()
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        vulnerabilities.append({
                            'type': 'WEAK_CIPHER',
                            'port': port,
                            'service': 'SSL/TLS',
                            'cipher': cipher[0],
                            'severity': 'MEDIUM'
                        })
        except Exception as e:
            logger.debug(f"SSL check failed for {ip}:{port} - {e}")
        
        return vulnerabilities

class TrafficAnalyzer:
    def __init__(self):
        self.packet_buffer = deque(maxlen=10000)
        self.connection_tracker = defaultdict(list)
        self.protocol_stats = defaultdict(int)
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        self.suspicious_patterns = []
        self.baseline_established = False
    
    def analyze_packet(self, packet):
        """Analyze individual packets for threats"""
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'size': len(packet),
            'flags': [],
            'suspicious': False,
            'threats': []
        }
        
        if packet.haslayer(IP):
            analysis['src_ip'] = packet[IP].src
            analysis['dst_ip'] = packet[IP].dst
            analysis['protocol'] = packet[IP].proto
            
            # Check for suspicious IPs
            if self.is_suspicious_ip(analysis['src_ip']) or self.is_suspicious_ip(analysis['dst_ip']):
                analysis['suspicious'] = True
                analysis['threats'].append('SUSPICIOUS_IP')
            
            # Analyze TCP packets
            if packet.haslayer(TCP):
                analysis['src_port'] = packet[TCP].sport
                analysis['dst_port'] = packet[TCP].dport
                
                # Check for port scanning
                if self.detect_port_scan(analysis['src_ip'], analysis['dst_port']):
                    analysis['threats'].append('PORT_SCAN')
                
                # Check for unusual ports
                if analysis['dst_port'] in [4444, 31337, 12345, 1234]:
                    analysis['threats'].append('BACKDOOR_PORT')
            
            # Analyze HTTP traffic
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if 'HTTP' in payload:
                    http_threats = self.analyze_http_traffic(payload)
                    analysis['threats'].extend(http_threats)
        
        self.packet_buffer.append(analysis)
        return analysis
    
    def is_suspicious_ip(self, ip):
        """Check if IP is suspicious based on various criteria"""
        try:
            # Check if IP is in private range but behaving suspiciously
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return False
            
            # Check against threat intelligence
            # This would integrate with real threat feeds
            suspicious_ranges = [
                '192.168.100.0/24',  # Example suspicious range
                '10.10.10.0/24'
            ]
            
            for range_str in suspicious_ranges:
                if ip_obj in ipaddress.ip_network(range_str):
                    return True
            
            return False
        except:
            return False
    
    def detect_port_scan(self, src_ip, dst_port):
        """Detect port scanning behavior"""
        current_time = time.time()
        
        # Track connections per IP
        if src_ip not in self.connection_tracker:
            self.connection_tracker[src_ip] = []
        
        # Add current connection
        self.connection_tracker[src_ip].append({
            'port': dst_port,
            'timestamp': current_time
        })
        
        # Clean old connections (older than 60 seconds)
        self.connection_tracker[src_ip] = [
            conn for conn in self.connection_tracker[src_ip]
            if current_time - conn['timestamp'] < 60
        ]
        
        # Check for port scan (more than 10 different ports in 60 seconds)
        recent_ports = set(conn['port'] for conn in self.connection_tracker[src_ip])
        return len(recent_ports) > 10
    
    def analyze_http_traffic(self, payload):
        """Analyze HTTP traffic for threats"""
        threats = []
        
        # Check for SQL injection attempts
        sql_patterns = [
            r"union\s+select", r"drop\s+table", r"insert\s+into",
            r"delete\s+from", r"update\s+set", r"or\s+1=1",
            r"and\s+1=1", r"having\s+1=1"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threats.append('SQL_INJECTION')
                break
        
        # Check for XSS attempts
        xss_patterns = [
            r"<script", r"javascript:", r"onerror=", r"onload=",
            r"alert\(", r"document\.cookie"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threats.append('XSS_ATTEMPT')
                break
        
        # Check for directory traversal
        if '../' in payload or '..\\' in payload:
            threats.append('DIRECTORY_TRAVERSAL')
        
        # Check for credential theft
        if re.search(r'password=|pwd=|pass=', payload, re.IGNORECASE):
            threats.append('CREDENTIAL_TRANSMISSION')
        
        return threats
    
    def train_anomaly_detector(self):
        """Train anomaly detection model on normal traffic"""
        if len(self.packet_buffer) < 100:
            return False
        
        # Extract features from packets
        features = []
        for packet in self.packet_buffer:
            if packet['src_ip'] and packet['dst_ip']:
                feature_vector = [
                    packet['size'],
                    packet['protocol'] or 0,
                    len(packet['threats']),
                    1 if packet['suspicious'] else 0
                ]
                features.append(feature_vector)
        
        if len(features) > 50:
            features_array = np.array(features)
            self.anomaly_detector.fit(features_array)
            self.is_trained = True
            logger.info("Anomaly detection model trained")
            return True
        
        return False
    
    def detect_anomalies(self, packet_analysis):
        """Detect anomalies in traffic patterns"""
        if not self.is_trained:
            return False
        
        try:
            feature_vector = [[
                packet_analysis['size'],
                packet_analysis['protocol'] or 0,
                len(packet_analysis['threats']),
                1 if packet_analysis['suspicious'] else 0
            ]]
            
            anomaly_score = self.anomaly_detector.decision_function(feature_vector)[0]
            is_anomaly = self.anomaly_detector.predict(feature_vector)[0] == -1
            
            return is_anomaly, anomaly_score
        except:
            return False, 0

class IncidentResponse:
    def __init__(self):
        self.incident_queue = []
        self.response_actions = {
            'CRITICAL': self.handle_critical_incident,
            'HIGH': self.handle_high_incident,
            'MEDIUM': self.handle_medium_incident,
            'LOW': self.handle_low_incident
        }
        self.notification_config = {
            'email_enabled': False,
            'sms_enabled': False,
            'slack_enabled': False
        }
    
    def create_incident(self, incident_type, device_ip, details, severity='MEDIUM'):
        """Create a new security incident"""
        incident = {
            'id': f"INC-{int(time.time())}",
            'timestamp': datetime.now().isoformat(),
            'type': incident_type,
            'device_ip': device_ip,
            'details': details,
            'severity': severity,
            'status': 'OPEN',
            'actions_taken': [],
            'resolved': False
        }
        
        self.incident_queue.append(incident)
        
        # Trigger automated response
        self.respond_to_incident(incident)
        
        return incident
    
    def respond_to_incident(self, incident):
        """Automated incident response"""
        severity = incident['severity']
        
        if severity in self.response_actions:
            self.response_actions[severity](incident)
        
        # Log incident
        logger.warning(f"Security incident: {incident['id']} - {incident['type']} - {incident['severity']}")
        
        # Send notifications
        self.send_notifications(incident)
    
    def handle_critical_incident(self, incident):
        """Handle critical security incidents"""
        actions = [
            "Immediate isolation of affected device",
            "Forensic data collection initiated",
            "Security team notified",
            "Incident response team activated"
        ]
        
        # Attempt to isolate device (placeholder)
        self.isolate_device(incident['device_ip'])
        
        incident['actions_taken'].extend(actions)
    
    def handle_high_incident(self, incident):
        """Handle high severity incidents"""
        actions = [
            "Enhanced monitoring activated",
            "Security scan initiated",
            "Administrator notified"
        ]
        
        incident['actions_taken'].extend(actions)
    
    def handle_medium_incident(self, incident):
        """Handle medium severity incidents"""
        actions = [
            "Logged for review",
            "Monitoring increased"
        ]
        
        incident['actions_taken'].extend(actions)
    
    def handle_low_incident(self, incident):
        """Handle low severity incidents"""
        actions = [
            "Logged for periodic review"
        ]
        
        incident['actions_taken'].extend(actions)
    
    def isolate_device(self, device_ip):
        """Isolate a compromised device (placeholder)"""
        # In a real implementation, this would:
        # - Add firewall rules to block device
        # - Remove from network access
        # - Quarantine traffic
        logger.info(f"Device isolation initiated for {device_ip}")
        return True
    
    def send_notifications(self, incident):
        """Send incident notifications"""
        if self.notification_config['email_enabled']:
            self.send_email_notification(incident)
        
        # Emit to web interface
        socketio.emit('incident_created', incident)
    
    def send_email_notification(self, incident):
        """Send email notification for incident"""
        # Placeholder for email notification
        logger.info(f"Email notification sent for incident {incident['id']}")

class ComplianceChecker:
    def __init__(self):
        self.compliance_frameworks = {
            'NIST': self.check_nist_compliance,
            'ISO27001': self.check_iso27001_compliance,
            'GDPR': self.check_gdpr_compliance,
            'HIPAA': self.check_hipaa_compliance
        }
    
    def check_nist_compliance(self, device_data):
        """Check NIST Cybersecurity Framework compliance"""
        compliance_score = 100
        issues = []
        
        # Identify function
        if not device_data.get('device_type'):
            compliance_score -= 10
            issues.append("Device type not identified")
        
        # Protect function
        if device_data.get('security_score', 0) < 70:
            compliance_score -= 20
            issues.append("Insufficient security controls")
        
        # Detect function
        if not device_data.get('monitoring_enabled'):
            compliance_score -= 15
            issues.append("Monitoring not enabled")
        
        return {
            'framework': 'NIST',
            'score': max(0, compliance_score),
            'issues': issues,
            'compliant': compliance_score >= 80
        }
    
    def check_iso27001_compliance(self, device_data):
        """Check ISO 27001 compliance"""
        compliance_score = 100
        issues = []
        
        # Access control
        if device_data.get('default_credentials'):
            compliance_score -= 25
            issues.append("Default credentials detected")
        
        # Cryptography
        if not device_data.get('encryption_enabled'):
            compliance_score -= 20
            issues.append("Encryption not enabled")
        
        return {
            'framework': 'ISO27001',
            'score': max(0, compliance_score),
            'issues': issues,
            'compliant': compliance_score >= 80
        }
    
    def check_gdpr_compliance(self, device_data):
        """Check GDPR compliance"""
        compliance_score = 100
        issues = []
        
        # Data protection
        if device_data.get('data_collection_detected'):
            if not device_data.get('privacy_policy'):
                compliance_score -= 30
                issues.append("Data collection without privacy policy")
        
        # Security measures
        if device_data.get('security_score', 0) < 80:
            compliance_score -= 20
            issues.append("Inadequate security measures")
        
        return {
            'framework': 'GDPR',
            'score': max(0, compliance_score),
            'issues': issues,
            'compliant': compliance_score >= 90
        }
    
    def check_hipaa_compliance(self, device_data):
        """Check HIPAA compliance"""
        compliance_score = 100
        issues = []
        
        # Administrative safeguards
        if not device_data.get('access_controls'):
            compliance_score -= 25
            issues.append("Access controls not implemented")
        
        # Technical safeguards
        if not device_data.get('encryption_enabled'):
            compliance_score -= 30
            issues.append("Encryption not enabled")
        
        return {
            'framework': 'HIPAA',
            'score': max(0, compliance_score),
            'issues': issues,
            'compliant': compliance_score >= 85
        }

class AdvancedSmartHomeSecurityDashboard:
    def __init__(self):
        self.devices = {}
        self.alerts = []
        self.incidents = []
        self.monitoring = False
        self.init_database()
        self.nm = nmap.PortScanner()
        
        # Initialize advanced components
        self.threat_intel = ThreatIntelligence()
        self.vuln_scanner = VulnerabilityScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        self.incident_response = IncidentResponse()
        self.compliance_checker = ComplianceChecker()
        
        # ML and Analytics
        self.ml_models = {}
        self.analytics_data = []
        
        # Advanced monitoring
        self.packet_capture_active = False
        self.forensic_mode = False
    
    def init_database(self):
        """Initialize SQLite database with advanced tables"""
        conn = sqlite3.connect('security_dashboard.db')
        cursor = conn.cursor()
        
        # Enhanced devices table
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
                is_trusted BOOLEAN DEFAULT 0,
                firmware_version TEXT,
                os_fingerprint TEXT,
                vulnerabilities TEXT,
                compliance_score INTEGER,
                threat_score INTEGER,
                encryption_enabled BOOLEAN DEFAULT 0,
                monitoring_enabled BOOLEAN DEFAULT 1
            )
        ''')
        
        # Enhanced alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                device_mac TEXT,
                device_ip TEXT,
                message TEXT,
                severity TEXT,
                threat_indicators TEXT,
                response_actions TEXT,
                status TEXT DEFAULT 'OPEN'
            )
        ''')
        
        # Incidents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                incident_type TEXT,
                device_ip TEXT,
                details TEXT,
                severity TEXT,
                status TEXT,
                actions_taken TEXT,
                resolved BOOLEAN DEFAULT 0
            )
        ''')
        
        # Traffic analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                size INTEGER,
                threats TEXT,
                anomaly_score REAL
            )
        ''')
        
        # Vulnerability scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                device_ip TEXT,
                scan_type TEXT,
                vulnerabilities TEXT,
                severity TEXT,
                remediation TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def start_advanced_monitoring(self):
        """Start comprehensive monitoring with all advanced features"""
        self.monitoring = True
        
        # Start device discovery
        discovery_thread = threading.Thread(target=self.continuous_device_discovery)
        discovery_thread.daemon = True
        discovery_thread.start()
        
        # Start vulnerability scanning
        vuln_thread = threading.Thread(target=self.continuous_vulnerability_scanning)
        vuln_thread.daemon = True
        vuln_thread.start()
        
        # Start traffic analysis
        traffic_thread = threading.Thread(target=self.start_traffic_analysis)
        traffic_thread.daemon = True
        traffic_thread.start()
        
        # Start threat intelligence updates
        threat_thread = threading.Thread(target=self.update_threat_intelligence)
        threat_thread.daemon = True
        threat_thread.start()
        
        # Start ML model training
        ml_thread = threading.Thread(target=self.train_ml_models)
        ml_thread.daemon = True
        ml_thread.start()
        
        logger.info("Advanced monitoring started with all components")
    
    def continuous_device_discovery(self):
        """Enhanced device discovery with fingerprinting"""
        while self.monitoring:
            try:
                network_range = self.get_network_range()
                self.nm.scan(hosts=network_range, arguments='-sS -sV -O')
                
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        device_info = self.gather_comprehensive_device_info(host)
                        if device_info:
                            self.devices[device_info['mac_address']] = device_info
                            self.analyze_device_security(device_info)
                            self.check_compliance(device_info)
                            self.store_enhanced_device(device_info)
                
                # Emit updates
                socketio.emit('devices_updated', list(self.devices.values()))
                
                time.sleep(60)  # Scan every minute
            except Exception as e:
                logger.error(f"Error in device discovery: {e}")
                time.sleep(30)
    
    def gather_comprehensive_device_info(self, ip):
        """Gather detailed device information"""
        try:
            mac_address = self.get_mac_address(ip)
            if not mac_address:
                return None
            
            device_info = {
                'ip_address': ip,
                'mac_address': mac_address,
                'hostname': self.get_hostname(ip),
                'vendor': self.get_vendor(mac_address),
                'last_seen': datetime.now().isoformat(),
                'device_type': self.advanced_device_classification(ip, mac_address),
                'security_score': 0,
                'threat_score': 0,
                'compliance_score': 0,
                'open_ports': [],
                'services': {},
                'os_fingerprint': None,
                'firmware_version': None,
                'vulnerabilities': [],
                'encryption_enabled': False,
                'monitoring_enabled': True
            }
            
            # Get detailed port and service information
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                
                # Extract OS information
                if 'osmatch' in host_info and host_info['osmatch']:
                    device_info['os_fingerprint'] = host_info['osmatch'][0]['name']
                
                # Extract port and service information
                for protocol in host_info.all_protocols():
                    ports = host_info[protocol].keys()
                    for port in ports:
                        port_info = host_info[protocol][port]
                        if port_info['state'] == 'open':
                            device_info['open_ports'].append(port)
                            device_info['services'][port] = {
                                'name': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', '')
                            }
            
            # Calculate threat score
            device_info['threat_score'] = self.threat_intel.get_threat_score(ip)
            
            return device_info
            
        except Exception as e:
            logger.error(f"Error gathering device info for {ip}: {e}")
            return None
    
    def advanced_device_classification(self, ip, mac):
        """Advanced device type classification"""
        vendor = self.get_vendor(mac).lower()
        
        # IoT device patterns
        iot_vendors = ['philips', 'nest', 'ring', 'amazon', 'google', 'samsung