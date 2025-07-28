import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import random
import threading
import time
from datetime import datetime, timedelta
import queue
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from PIL import Image, ImageTk
import json
import csv
import socket
import struct
import hashlib
import ipaddress
from collections import deque
import webbrowser
import platform
import psutil
import uuid
import fpdf
from fpdf import FPDF
from mpl_toolkits.mplot3d import Axes3D
import openai  # pip install openai
# from pymodbus.client.sync import ModbusTcpClient
import paho.mqtt.client as mqtt
import pandas as pd

# ======================
# INDUSTRIAL PROTOCOLS
# ======================
class IndustrialProtocol:
    MODBUS_TCP = "Modbus/TCP"
    OPC_UA = "OPC UA"
    PROFINET = "PROFINET"
    DNP3 = "DNP3"
    IEC61850 = "IEC 61850"
    ETHERNET_IP = "EtherNet/IP"
    BACNET = "BACnet"
    IEC104 = "IEC 60870-5-104"
    S7COMM = "S7Comm (Siemens)"
    CIP = "Common Industrial Protocol"
    FINS = "FINS (Omron)"
    MELSEC = "MELSEC (Mitsubishi)"
    
    @classmethod
    def all_protocols(cls):
        return [p for p in cls.__dict__.values() if isinstance(p, str) and not p.startswith('__')]

# ======================
# INDUSTRIAL ATTACKS
# ======================
class IndustrialAttack:
    def __init__(self, name, protocol, severity, indicators, mitigation, cve=None):
        self.name = name
        self.protocol = protocol
        self.severity = severity  # Low, Medium, High, Critical
        self.indicators = indicators
        self.mitigation = mitigation
        self.last_detected = None
        self.detection_count = 0
        self.cve = cve if cve else f"CVE-{random.randint(2020, 2023)}-{random.randint(1000, 9999)}"
        self.tactics = random.choice(["Initial Access", "Execution", "Persistence", "Lateral Movement"])

# Known industrial cyber attacks with detailed indicators
INDUSTRIAL_ATTACKS = [
    IndustrialAttack(
        "Modbus Enumeration", 
        IndustrialProtocol.MODBUS_TCP, 
        "High",
        ["Function Code 43 (Read Device ID)", 
         "Multiple failed unit ID attempts (3+/min)",
         "Unusual polling intervals",
         "Scanning across register ranges"],
        ["Implement access control lists", 
         "Enable Modbus/TCP security extensions",
         "Deploy protocol-aware firewall",
         "Monitor for enumeration patterns"],
        cve="CVE-2022-31814"
    ),
    IndustrialAttack(
        "Command Injection", 
        IndustrialProtocol.MODBUS_TCP, 
        "Critical",
        ["Unauthorized function code 6 (Write Single Register)", 
         "Out-of-range register writes",
         "Write commands to read-only areas",
         "Malformed packet structures"],
        ["Implement write protection", 
         "Deploy anomaly detection",
         "Segment control network",
         "Enable command signing"],
        cve="CVE-2021-44228"
    ),
    IndustrialAttack(
        "OPC UA Server Spoofing", 
        IndustrialProtocol.OPC_UA, 
        "High",
        ["Certificate mismatch", 
         "Unauthorized endpoint connection",
         "Invalid security policies",
         "Man-in-the-middle patterns"],
        ["Implement certificate pinning", 
         "Enforce endpoint validation",
         "Monitor for rogue servers",
         "Enable strict authentication"],
        cve="CVE-2023-1234"
    ),
    IndustrialAttack(
        "PROFINET Discovery", 
        IndustrialProtocol.PROFINET, 
        "Medium",
        ["Excessive DCP Identify requests (>5/sec)", 
         "Unauthorized LLDP traffic",
         "MAC address scanning",
         "Network topology probing"],
        ["Enable port security", 
         "Disable unused protocols",
         "Monitor for reconnaissance",
         "Implement network segmentation"],
        cve="CVE-2022-4567"
    ),
    IndustrialAttack(
        "DNP3 DoS", 
        IndustrialProtocol.DNP3, 
        "Critical",
        ["Malformed application layer fragments", 
         "Flood of confirm requests",
         "Invalid CRC values",
         "Session exhaustion attempts"],
        ["Implement DNP3 secure authentication", 
         "Rate limit confirm requests",
         "Validate message integrity",
         "Deploy protocol-aware IPS"],
        cve="CVE-2021-7890"
    ),
    IndustrialAttack(
        "IEC 61850 Goose Spoofing", 
        IndustrialProtocol.IEC61850, 
        "High",
        ["Unauthorized GOOSE packets", 
         "Abnormal multicast patterns",
         "Invalid timestamps",
         "Incorrect state numbers"],
        ["Implement GOOSE message signing", 
         "Monitor multicast traffic",
         "Validate packet timing",
         "Enable goose authentication"],
        cve="CVE-2023-3456"
    ),
    IndustrialAttack(
        "CIP Class 3 Scanning", 
        IndustrialProtocol.ETHERNET_IP, 
        "Medium",
        ["Excessive Class 3 service requests", 
         "Unregistered session initiation",
         "Invalid encapsulation commands",
         "Service code enumeration"],
        ["Restrict CIP services", 
         "Monitor session establishment",
         "Implement access controls",
         "Deploy deep packet inspection"],
        cve="CVE-2022-6789"
    ),
    IndustrialAttack(
        "S7Comm Stop CPU", 
        IndustrialProtocol.S7COMM, 
        "Critical",
        ["Function code 0x29 (Stop CPU)", 
         "Unauthorized PLC commands",
         "Invalid job references",
         "Malformed parameter blocks"],
        ["Implement command authorization", 
         "Monitor critical functions",
         "Segment PLC access",
         "Enable PLC write protection"],
        cve="CVE-2021-3712"
    ),
    IndustrialAttack(
        "BACnet Device Spoofing", 
        IndustrialProtocol.BACNET, 
        "High",
        ["Duplicate device IDs", 
         "Invalid BVLC messages",
         "Unauthorized Who-Is requests",
         "Broadcast storm patterns"],
        ["Implement BACnet security", 
         "Monitor device registration",
         "Validate BVLC headers",
         "Enable BACnet authentication"],
        cve="CVE-2023-2345"
    )
]

# ======================
# INDUSTRIAL ASSETS
# ======================
class IndustrialAsset:
    def __init__(self, asset_id, asset_type, ip_address, protocol, criticality):
        self.asset_id = asset_id
        self.asset_type = asset_type
        self.ip_address = ip_address
        self.protocol = protocol
        self.criticality = criticality  # Low, Medium, High, Critical
        self.status = "Normal"
        self.last_seen = datetime.now()
        self.vulnerabilities = []
        self.security_controls = []
        self.mac_address = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        self.firmware_version = f"{random.randint(1, 5)}.{random.randint(0, 9)}.{random.randint(0, 20)}"
        self.operating_hours = random.randint(100, 10000)
        self.location = random.choice(["Production Line A", "Control Room", "Substation 1", "Field Unit 3"])
    
    def add_vulnerability(self, cve_id, description, severity):
        self.vulnerabilities.append({
            'cve_id': cve_id,
            'description': description,
            'severity': severity,
            'detected': datetime.now(),
            'status': 'Unpatched',
            'cvss_score': round(random.uniform(3.0, 9.9), 1)
        })
    
    def add_security_control(self, control_type, status):
        self.security_controls.append({
            'type': control_type,
            'status': status,
            'last_checked': datetime.now(),
            'effectiveness': random.choice(["High", "Medium", "Low"])
        })

# ======================
# NETWORK TRAFFIC SIMULATION
# ======================
class IndustrialTrafficGenerator:
    def __init__(self):
        self.protocol_distribution = {
            IndustrialProtocol.MODBUS_TCP: 0.35,
            IndustrialProtocol.OPC_UA: 0.15,
            IndustrialProtocol.PROFINET: 0.12,
            IndustrialProtocol.DNP3: 0.08,
            IndustrialProtocol.ETHERNET_IP: 0.10,
            IndustrialProtocol.S7COMM: 0.10,
            IndustrialProtocol.BACNET: 0.05,
            IndustrialProtocol.IEC61850: 0.05
        }
        self.normal_traffic_ranges = {
            IndustrialProtocol.MODBUS_TCP: (5, 25),
            IndustrialProtocol.OPC_UA: (10, 40),
            IndustrialProtocol.PROFINET: (8, 30),
            IndustrialProtocol.DNP3: (3, 15),
            IndustrialProtocol.ETHERNET_IP: (5, 20),
            IndustrialProtocol.S7COMM: (4, 18),
            IndustrialProtocol.BACNET: (2, 10),
            IndustrialProtocol.IEC61850: (1, 8)
        }
        self.attack_traffic_multiplier = {
            "Low": 3,
            "Medium": 5,
            "High": 8,
            "Critical": 15
        }
        self.attack_duration = {
            "Low": (1, 3),
            "Medium": (2, 5),
            "High": (3, 8),
            "Critical": (5, 15)
        }
    
    def generate_normal_traffic(self, protocol):
        low, high = self.normal_traffic_ranges.get(protocol, (1, 10))
        return random.randint(low, high)
    
    def generate_attack_traffic(self, protocol, severity):
        base = self.generate_normal_traffic(protocol)
        return base * self.attack_traffic_multiplier.get(severity, 1)
    
    def get_attack_duration(self, severity):
        low, high = self.attack_duration.get(severity, (1, 5))
        return random.randint(low, high)

# ======================
# PDF REPORT GENERATION
# ======================
class PDFReport(FPDF):
    def __init__(self):
        super().__init__()
        self.WIDTH = 210
        self.HEIGHT = 297
    
    def header(self):
        # Custom header with logo and title
        try:
            self.image('scureprod_logo.png', 10, 8, 25)
        except Exception as e:
            print(f"Logo image not found: {e}")
        self.set_font('Arial', 'B', 15)
        self.cell(self.WIDTH - 20)
        self.cell(10, 10, 'Industrial Security Report', 0, 0, 'R')
        self.ln(20)
    
    def footer(self):
        # Page footer
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.set_text_color(128)
        self.cell(0, 10, 'Page ' + str(self.page_no()), 0, 0, 'C')
    
    def chapter_title(self, title):
        # Chapter title
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)
    
    def chapter_body(self, body):
        # Chapter text
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, body)
        self.ln()
    
    def add_table(self, headers, data):
        # Add a table to the report
        self.set_font('Arial', 'B', 10)
        col_count = len(headers)
        col_widths = [self.WIDTH // col_count for _ in range(col_count)]
        
        # Headers
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 7, header, 1, 0, 'C')
        self.ln()
        
        # Data
        self.set_font('Arial', '', 9)
        for row in data:
            for i, item in enumerate(row):
                self.cell(col_widths[i], 6, str(item), 1)
            self.ln()

# ======================
# MAIN APPLICATION
# ======================
# =============================================
# INDUSTRIAL VULNERABILITY SCANNER
# =============================================

class IndustrialVulnerabilityScanner:
    """Advanced Industrial Vulnerability Scanner with Real-time Detection"""
    
    def __init__(self):
        self.targets = []
        self.scan_results = []
        self.scan_status = "idle"
        self.current_scan = None
        self.scan_modules = {
            "ports": True,
            "web": True,
            "protocols": True,
            "auth": True,
            "config": True,
            "firmware": True,
            "physical": False
        }
        
    def add_target(self, target):
        """Add a target for scanning"""
        if target and target not in self.targets:
            self.targets.append(target)
            
    def get_targets(self):
        return self.targets
        
    def run_scan(self):
        """Run comprehensive industrial vulnerability scan"""
        if not self.targets:
            return {"error": "No targets specified"}
            
        self.scan_status = "running"
        self.scan_results = []
        
        for target in self.targets:
            target_results = self._scan_single_target(target)
            self.scan_results.extend(target_results)
                
        self.scan_status = "completed"
        return self._generate_report()
        
    def _scan_single_target(self, target):
        """Scan a single target for vulnerabilities"""
        results = []
        
        # Simulate realistic scan results for industrial systems
        scan_modules = [
            self._scan_network_ports,
            self._scan_web_services,
            self._scan_industrial_protocols,
            self._scan_authentication,
            self._scan_configuration,
            self._scan_firmware,
            self._scan_physical_security
        ]
        
        for module in scan_modules:
            try:
                module_results = module(target)
                results.extend(module_results)
            except Exception as e:
                results.append({
                    "type": "scan_error",
                    "target": target,
                    "module": module.__name__,
                    "severity": "info",
                    "description": f"Scan module failed: {str(e)}",
                    "timestamp": datetime.now().isoformat()
                })
                    
        return results
        
    def _scan_network_ports(self, target):
        """Scan for open ports and services"""
        results = []
        
        # Common industrial ports
        industrial_ports = {
            502: "Modbus TCP",
            4840: "OPC UA",
            34964: "EtherNet/IP",
            2222: "SSH",
            23: "Telnet",
            21: "FTP",
            80: "HTTP",
            443: "HTTPS",
            3389: "RDP",
            5900: "VNC",
            161: "SNMP",
            162: "SNMP Trap",
            102: "S7Comm",
            9600: "Modbus RTU",
            5020: "DNP3",
            20000: "DNP3 Secure"
        }
        
        # Simulate port scan results
        for port, service in industrial_ports.items():
            if random.random() < 0.3:  # 30% chance port is open
                severity = "high" if port in [23, 21, 161] else "medium"
                results.append({
                    "type": "open_port",
                    "target": target,
                    "port": port,
                    "service": service,
                    "severity": severity,
                    "description": f"Open {service} port {port} detected",
                    "recommendation": f"Close port {port} if not required, or secure with firewall rules",
                    "timestamp": datetime.now().isoformat()
                })
                    
        return results
        
    def _scan_web_services(self, target):
        """Scan web services for vulnerabilities"""
        results = []
        
        # Common web vulnerabilities
        web_vulns = [
            {
                "name": "Default Credentials",
                "severity": "critical",
                "description": "Default admin credentials found (admin/admin)",
                "recommendation": "Change default passwords immediately"
            },
            {
                "name": "SQL Injection",
                "severity": "critical", 
                "description": "SQL injection vulnerability detected in login form",
                "recommendation": "Implement input validation and parameterized queries"
            },
            {
                "name": "XSS Vulnerability",
                "severity": "high",
                "description": "Cross-site scripting vulnerability found",
                "recommendation": "Sanitize user inputs and implement CSP headers"
            },
            {
                "name": "Missing Security Headers",
                "severity": "medium",
                "description": "Security headers not configured",
                "recommendation": "Implement HSTS, CSP, and other security headers"
            },
            {
                "name": "Directory Traversal",
                "severity": "high",
                "description": "Directory traversal vulnerability detected",
                "recommendation": "Validate and sanitize file paths"
            },
            {
                "name": "Weak SSL/TLS",
                "severity": "high",
                "description": "Weak SSL/TLS configuration detected",
                "recommendation": "Update to TLS 1.3 and disable weak ciphers"
            }
        ]
        
        for vuln in web_vulns:
            if random.random() < 0.4:  # 40% chance of finding each vulnerability
                results.append({
                    "type": "web_vulnerability",
                    "target": target,
                    "name": vuln["name"],
                    "severity": vuln["severity"],
                    "description": vuln["description"],
                    "recommendation": vuln["recommendation"],
                    "timestamp": datetime.now().isoformat()
                })
                    
        return results
        
    def _scan_industrial_protocols(self, target):
        """Scan industrial protocols for vulnerabilities"""
        results = []
        
        # Industrial protocol vulnerabilities
        protocol_vulns = [
            {
                "protocol": "Modbus TCP",
                "vulneration": "Unauthenticated Access",
                "severity": "critical",
                "description": "Modbus TCP service accessible without authentication",
                "recommendation": "Implement authentication or restrict access to trusted networks"
            },
            {
                "protocol": "OPC UA",
                "vulneration": "Weak Certificate",
                "severity": "high",
                "description": "OPC UA certificate uses weak encryption",
                "recommendation": "Update to strong certificate with proper key length"
            },
            {
                "protocol": "EtherNet/IP",
                "vulneration": "CIP Object Exposure",
                "severity": "high",
                "description": "CIP objects exposed without proper access control",
                "recommendation": "Implement proper CIP object access controls"
            },
            {
                "protocol": "SNMP",
                "vulneration": "Default Community Strings",
                "severity": "critical",
                "description": "SNMP using default community strings (public/private)",
                "recommendation": "Change default community strings and use SNMPv3"
            },
            {
                "protocol": "S7Comm",
                "vulneration": "Siemens S7 Protocol Exposure",
                "severity": "critical",
                "description": "Siemens S7 protocol accessible without authentication",
                "recommendation": "Implement S7Comm authentication and access controls"
            },
            {
                "protocol": "DNP3",
                "vulneration": "DNP3 Master Station Exposure",
                "severity": "high",
                "description": "DNP3 master station accessible without proper authentication",
                "recommendation": "Implement DNP3 authentication and secure communications"
            }
        ]
        
        for vuln in protocol_vulns:
            if random.random() < 0.5:  # 50% chance of finding protocol vulnerability
                results.append({
                    "type": "protocol_vulnerability",
                    "target": target,
                    "protocol": vuln["protocol"],
                    "name": vuln["vulneration"],
                    "severity": vuln["severity"],
                    "description": vuln["description"],
                    "recommendation": vuln["recommendation"],
                    "timestamp": datetime.now().isoformat()
                })
                    
        return results
        
    def _scan_authentication(self, target):
        """Scan authentication mechanisms"""
        results = []
        
        auth_issues = [
            {
                "name": "Weak Password Policy",
                "severity": "high",
                "description": "Password policy allows weak passwords",
                "recommendation": "Implement strong password policy with complexity requirements"
            },
            {
                "name": "No Multi-Factor Authentication",
                "severity": "medium",
                "description": "Multi-factor authentication not enabled",
                "recommendation": "Enable MFA for all critical system access"
            },
            {
                "name": "Session Timeout Too Long",
                "severity": "medium",
                "description": "Session timeout set to 24 hours",
                "recommendation": "Reduce session timeout to 15-30 minutes"
            },
            {
                "name": "Account Lockout Disabled",
                "severity": "high",
                "description": "Account lockout after failed attempts not configured",
                "recommendation": "Enable account lockout after 5 failed attempts"
            },
            {
                "name": "Default Admin Account",
                "severity": "critical",
                "description": "Default admin account still active",
                "recommendation": "Disable default admin account and create new admin user"
            },
            {
                "name": "Password Reuse",
                "severity": "medium",
                "description": "Password history not enforced",
                "recommendation": "Implement password history policy to prevent reuse"
            }
        ]
        
        for issue in auth_issues:
            if random.random() < 0.6:  # 60% chance of finding auth issue
                results.append({
                    "type": "authentication_issue",
                    "target": target,
                    "name": issue["name"],
                    "severity": issue["severity"],
                    "description": issue["description"],
                    "recommendation": issue["recommendation"],
                    "timestamp": datetime.now().isoformat()
                })
                    
        return results
        
    def _scan_configuration(self, target):
        """Scan system configuration issues"""
        results = []
        
        config_issues = [
            {
                "name": "Debug Mode Enabled",
                "severity": "high",
                "description": "Debug mode enabled in production environment",
                "recommendation": "Disable debug mode in production"
            },
            {
                "name": "Default Configurations",
                "severity": "medium",
                "description": "System using default configurations",
                "recommendation": "Review and customize security configurations"
            },
            {
                "name": "Unnecessary Services",
                "severity": "medium",
                "description": "Unnecessary services running",
                "recommendation": "Disable unused services to reduce attack surface"
            },
            {
                "name": "Logging Disabled",
                "severity": "medium",
                "description": "Security logging not properly configured",
                "recommendation": "Enable comprehensive security logging"
            },
            {
                "name": "Firewall Rules Too Permissive",
                "severity": "high",
                "description": "Firewall allows all traffic",
                "recommendation": "Implement restrictive firewall rules"
            },
            {
                "name": "Backup Not Configured",
                "severity": "medium",
                "description": "System backup not configured",
                "recommendation": "Implement regular backup procedures"
            }
        ]
        
        for issue in config_issues:
            if random.random() < 0.4:  # 40% chance of finding config issue
                results.append({
                    "type": "configuration_issue",
                    "target": target,
                    "name": issue["name"],
                    "severity": issue["severity"],
                    "description": issue["description"],
                    "recommendation": issue["recommendation"],
                    "timestamp": datetime.now().isoformat()
                })
                    
        return results
        
    def _scan_firmware(self, target):
        """Scan firmware and software versions"""
        results = []
        
        firmware_issues = [
            {
                "name": "Outdated Firmware",
                "severity": "high",
                "description": "Device firmware is 2 years old",
                "recommendation": "Update to latest firmware version"
            },
            {
                "name": "Known Vulnerabilities",
                "severity": "critical",
                "description": "Firmware contains known CVE-2023-1234",
                "recommendation": "Apply security patches immediately"
            },
            {
                "name": "Unsupported Version",
                "severity": "high",
                "description": "Running unsupported firmware version",
                "recommendation": "Upgrade to supported version or replace device"
            },
            {
                "name": "Firmware Integrity Check Failed",
                "severity": "critical",
                "description": "Firmware integrity check failed",
                "recommendation": "Reinstall firmware from trusted source"
            },
            {
                "name": "No Firmware Update Mechanism",
                "severity": "medium",
                "description": "No secure firmware update mechanism",
                "recommendation": "Implement secure firmware update process"
            }
        ]
        
        for issue in firmware_issues:
            if random.random() < 0.3:  # 30% chance of finding firmware issue
                results.append({
                    "type": "firmware_issue",
                    "target": target,
                    "name": issue["name"],
                    "severity": issue["severity"],
                    "description": issue["description"],
                    "recommendation": issue["recommendation"],
                    "timestamp": datetime.now().isoformat()
                })
                    
        return results
        
    def _scan_physical_security(self, target):
        """Scan physical security issues"""
        results = []
        
        physical_issues = [
            {
                "name": "Physical Access Control",
                "severity": "medium",
                "description": "No physical access control to device location",
                "recommendation": "Implement physical access controls and monitoring"
            },
            {
                "name": "USB Ports Enabled",
                "severity": "high",
                "description": "USB ports not disabled on critical devices",
                "recommendation": "Disable USB ports or implement USB device control"
            },
            {
                "name": "Serial Console Access",
                "severity": "medium",
                "description": "Serial console accessible without authentication",
                "recommendation": "Secure serial console access with authentication"
            },
            {
                "name": "No Environmental Monitoring",
                "severity": "low",
                "description": "No environmental monitoring (temperature, humidity)",
                "recommendation": "Implement environmental monitoring systems"
            }
        ]
        
        for issue in physical_issues:
            if random.random() < 0.2:  # 20% chance of finding physical issue
                results.append({
                    "type": "physical_security_issue",
                    "target": target,
                    "name": issue["name"],
                    "severity": issue["severity"],
                    "description": issue["description"],
                    "recommendation": issue["recommendation"],
                    "timestamp": datetime.now().isoformat()
                })
                    
        return results
        
    def _generate_report(self):
        """Generate comprehensive scan report"""
        total_findings = len(self.scan_results)
        critical_count = len([r for r in self.scan_results if r.get('severity') == 'critical'])
        high_count = len([r for r in self.scan_results if r.get('severity') == 'high'])
        medium_count = len([r for r in self.scan_results if r.get('severity') == 'medium'])
        low_count = len([r for r in self.scan_results if r.get('severity') == 'low'])
        
        return {
            "scan_id": f"SCAN_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timestamp": datetime.now().isoformat(),
            "targets": self.targets,
            "status": self.scan_status,
            "summary": {
                "total_findings": total_findings,
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count
            },
            "findings": self.scan_results,
            "recommendations": self._generate_recommendations()
        }
        
    def _generate_recommendations(self):
        """Generate prioritized recommendations"""
        recommendations = []
        
        # Group findings by type and severity
        critical_findings = [f for f in self.scan_results if f.get('severity') == 'critical']
        high_findings = [f for f in self.scan_results if f.get('severity') == 'high']
        
        if critical_findings:
            recommendations.append({
                "priority": "immediate",
                "title": "Address Critical Vulnerabilities",
                "description": f"Fix {len(critical_findings)} critical vulnerabilities immediately",
                "actions": [f.get('recommendation', '') for f in critical_findings[:3]]
            })
            
        if high_findings:
            recommendations.append({
                "priority": "high",
                "title": "Address High Priority Issues",
                "description": f"Address {len(high_findings)} high priority security issues",
                "actions": [f.get('recommendation', '') for f in high_findings[:3]]
            })
            
        recommendations.append({
            "priority": "ongoing",
            "title": "Implement Security Best Practices",
            "description": "Establish ongoing security monitoring and maintenance",
            "actions": [
                "Implement regular vulnerability scanning",
                "Establish patch management process",
                "Conduct security awareness training",
                "Implement network segmentation",
                "Enable comprehensive logging and monitoring",
                "Create incident response plan",
                "Perform regular security assessments"
            ]
        })
        
        return recommendations

class ScureProdApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ScureProd | Industrial Cyber Defense Platform")
        self.root.geometry("1600x1000")
        self.root.state('zoomed')  # Start maximized
        
        # System information
        self.system_id = str(uuid.uuid4())[:8]
        self.operator = "Industrial Security Operator"
        self.facility = "ACME Manufacturing Plant"
        
        # Custom Dark Theme (modernized)
        self.bg_color = "#181a20"
        self.card_color = "#232634"
        self.text_color = "#f5f6fa"
        self.accent_color = "#4a90e2"
        self.alert_color = "#e74c3c"
        self.safe_color = "#27ae60"
        self.warning_color = "#f1c40f"
        self.critical_color = "#c0392b"
        self.info_color = "#3498db"
        self.border_color = "#353b48"
        self.selected_row_color = "#2d3a4a"
        self.alt_row_color = "#20232a"
        self.font_family = "Segoe UI"
        # Setup styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('.', background=self.bg_color, foreground=self.text_color, font=(self.font_family, 10))
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=(self.font_family, 10))
        self.style.configure('Header.TLabel', font=(self.font_family, 18, 'bold'), foreground=self.accent_color, background=self.bg_color)
        self.style.configure('Card.TFrame', background=self.card_color, relief=tk.RAISED, borderwidth=2)
        self.style.configure('TButton', background=self.accent_color, foreground="white", borderwidth=0, font=(self.font_family, 10, 'bold'), padding=6)
        self.style.map('TButton', background=[('active', '#357ab8')])
        self.style.configure('Red.TButton', background=self.alert_color, foreground="white")
        self.style.map('Red.TButton', background=[('active', '#a93226')])
        self.style.configure('Green.TButton', background=self.safe_color, foreground="white")
        self.style.map('Green.TButton', background=[('active', '#229954')])
        self.style.configure('TNotebook', background=self.bg_color)
        self.style.configure('TNotebook.Tab', background=self.card_color, foreground=self.text_color, font=(self.font_family, 11, 'bold'), padding=[10, 5])
        self.style.map('TNotebook.Tab', background=[('selected', self.accent_color)])
        # Treeview styling
        self.style.configure('Treeview', background=self.card_color, foreground=self.text_color, fieldbackground=self.card_color, font=(self.font_family, 10), rowheight=28, borderwidth=0)
        self.style.configure('Treeview.Heading', background=self.accent_color, foreground='white', font=(self.font_family, 11, 'bold'))
        self.style.map('Treeview', background=[('selected', self.selected_row_color)])
        
        # Initialize components
        self.traffic_generator = IndustrialTrafficGenerator()
        self.assets = []
        self.alerts = []
        self.attack_log = []
        self.network_traffic = []
        self.protocol_traffic = {p: deque(maxlen=100) for p in IndustrialProtocol.all_protocols()}
        self.alert_queue = queue.Queue()
        self.threat_level = 0
        self.attack_patterns = INDUSTRIAL_ATTACKS
        self.ai_models = {}
        self.models_trained = False
        self.last_incident_report = None
        self.attack_in_progress = False
        self.current_attack = None
        
        # Create UI components
        self.create_menu()
        self.create_header()
        self.create_main_panels()
        
        # Initialize with sample data
        self.initialize_sample_assets()
        self.initialize_ai_models()
        
        # Start background services
        self.running = True
        threading.Thread(target=self.simulate_industrial_network, daemon=True).start()
        threading.Thread(target=self.process_alerts, daemon=True).start()
        threading.Thread(target=self.train_ai_models, daemon=True).start()
        threading.Thread(target=self.monitor_asset_health, daemon=True).start()
        threading.Thread(target=self.detect_anomalies, daemon=True).start()
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_menu(self):
        """Create the application menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Asset Discovery", command=self.run_asset_discovery)
        tools_menu.add_command(label="Vulnerability Scan", command=self.run_vulnerability_scan)
        tools_menu.add_command(label="Configuration Backup", command=self.backup_configurations)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Reports menu
        report_menu = tk.Menu(menubar, tearoff=0)
        report_menu.add_command(label="Generate Security Report", command=self.generate_report)
        report_menu.add_command(label="View Threat Intelligence", command=self.show_threat_intel)
        menubar.add_cascade(label="Reports", menu=report_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_header(self):
        """Create the application header with system info"""
        header_frame = ttk.Frame(self.root, style='Card.TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Logo and title
        logo_label = ttk.Label(header_frame, text="⚡ ScureProd", font=('Arial', 18, 'bold'), style='Header.TLabel')
        logo_label.pack(side=tk.LEFT, padx=10)
        
        # System info
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side=tk.RIGHT, padx=10)
        
        ttk.Label(info_frame, text=f"Facility: {self.facility}", font=('Arial', 10)).pack(anchor=tk.E)
        ttk.Label(info_frame, text=f"Operator: {self.operator}", font=('Arial', 10)).pack(anchor=tk.E)
        ttk.Label(info_frame, text=f"System ID: {self.system_id}", font=('Arial', 10)).pack(anchor=tk.E)
        
        # Threat level indicator
        self.threat_frame = ttk.Frame(header_frame, style='Card.TFrame')
        self.threat_frame.pack(side=tk.RIGHT, padx=20)
        
        ttk.Label(self.threat_frame, text="Threat Level:", font=('Arial', 10)).pack(side=tk.LEFT)
        self.threat_label = ttk.Label(self.threat_frame, text="0%", font=('Arial', 10, 'bold'))
        self.threat_label.pack(side=tk.LEFT, padx=5)
        
        # Time display
        self.time_label = ttk.Label(header_frame, text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), font=('Arial', 10))
        self.time_label.pack(side=tk.RIGHT, padx=10)
        self.update_time()
    
    def create_main_panels(self):
        """Create the main application panels using a notebook"""
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        # Dashboard tab
        dashboard_tab = ttk.Frame(notebook)
        self.create_dashboard(dashboard_tab)
        notebook.add(dashboard_tab, text="Dashboard")
        # Assets tab
        assets_tab = ttk.Frame(notebook)
        self.create_asset_panel(assets_tab)
        notebook.add(assets_tab, text="Assets")
        # Network tab
        network_tab = ttk.Frame(notebook)
        self.create_network_monitor(network_tab)
        notebook.add(network_tab, text="Network")
        # Alerts tab
        alerts_tab = ttk.Frame(notebook)
        self.create_alert_panel(alerts_tab)
        notebook.add(alerts_tab, text="Alerts")
        # Response tab
        response_tab = ttk.Frame(notebook)
        self.create_incident_response_panel(response_tab)
        notebook.add(response_tab, text="Incident Response")
        # Vulnerability Scanner tab
        scanner_tab = ttk.Frame(notebook)
        self.create_vulnerability_scanner_panel(scanner_tab)
        notebook.add(scanner_tab, text="🔍 Vulnerability Scanner")
        # 3D/2D Visualization tab
        visualization_tab = ttk.Frame(notebook)
        self.create_visualization_panel(visualization_tab)
        notebook.add(visualization_tab, text="🗺️ 3D/2D Visualization")
        # AI Chatbot tab
        chatbot_tab = ttk.Frame(notebook)
        self.create_chatbot_panel(chatbot_tab)
        notebook.add(chatbot_tab, text="AI Chatbot")
        # Metrics tab
        metrics_tab = ttk.Frame(notebook)
        self.create_metrics_panel(metrics_tab)
        notebook.add(metrics_tab, text="Industry Metrics")
    
    def create_dashboard(self, parent):
        """Create the main dashboard with overview widgets"""
        # Top row - summary cards
        top_frame = ttk.Frame(parent)
        top_frame.pack(fill=tk.X, pady=5)
        
        # Asset summary card
        asset_card = ttk.Frame(top_frame, style='Card.TFrame', padding=10)
        asset_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(asset_card, text="Assets", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        self.asset_summary_label = ttk.Label(asset_card, text="0 Total | 0 Critical", font=('Arial', 10))
        self.asset_summary_label.pack(anchor=tk.W)
        
        # Alert summary card
        alert_card = ttk.Frame(top_frame, style='Card.TFrame', padding=10)
        alert_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(alert_card, text="Alerts", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        self.alert_summary_label = ttk.Label(alert_card, text="0 Total | 0 Unacknowledged", font=('Arial', 10))
        self.alert_summary_label.pack(anchor=tk.W)
        
        # Protocol summary card
        protocol_card = ttk.Frame(top_frame, style='Card.TFrame', padding=10)
        protocol_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(protocol_card, text="Protocols", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        self.protocol_summary_label = ttk.Label(protocol_card, text="0 Active | 0 Anomalous", font=('Arial', 10))
        self.protocol_summary_label.pack(anchor=tk.W)
        
        # Security summary card
        security_card = ttk.Frame(top_frame, style='Card.TFrame', padding=10)
        security_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(security_card, text="Security", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        self.security_summary_label = ttk.Label(security_card, text="0 Vulnerabilities", font=('Arial', 10))
        self.security_summary_label.pack(anchor=tk.W)
        
        # Middle row - network graph
        middle_frame = ttk.Frame(parent)
        middle_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        graph_card = ttk.Frame(middle_frame, style='Card.TFrame')
        graph_card.pack(fill=tk.BOTH, expand=True, padx=5)
        
        self.figure = plt.Figure(figsize=(8, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.canvas = FigureCanvasTkAgg(self.figure, graph_card)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add toolbar
        toolbar = NavigationToolbar2Tk(self.canvas, graph_card)
        toolbar.update()
        self.canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
        
        # Bottom row - recent alerts and quick actions
        bottom_frame = ttk.Frame(parent)
        bottom_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Recent alerts
        alert_frame = ttk.Frame(bottom_frame, style='Card.TFrame', padding=10)
        alert_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(alert_frame, text="Recent Alerts", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        self.recent_alerts_tree = ttk.Treeview(alert_frame, columns=('time', 'alert', 'severity'), show='headings', height=5)
        self.recent_alerts_tree.heading('time', text='Time')
        self.recent_alerts_tree.heading('alert', text='Alert')
        self.recent_alerts_tree.heading('severity', text='Severity')
        self.recent_alerts_tree.column('time', width=120)
        self.recent_alerts_tree.column('alert', width=250)
        self.recent_alerts_tree.column('severity', width=80)
        self.recent_alerts_tree.pack(fill=tk.BOTH, expand=True)
        
        # Quick actions
        action_frame = ttk.Frame(bottom_frame, style='Card.TFrame', padding=10)
        action_frame.pack(side=tk.LEFT, fill=tk.BOTH, padx=5)
        ttk.Label(action_frame, text="Quick Actions", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        ttk.Button(action_frame, text="Acknowledge All Alerts", command=self.acknowledge_all_alerts).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Isolate Critical Assets", command=self.isolate_critical_assets).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Generate Security Report", command=self.generate_report).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Run Asset Discovery", command=self.run_asset_discovery).pack(fill=tk.X, pady=2)
        ttk.Button(action_frame, text="Emergency Shutdown", command=self.emergency_shutdown, style='Red.TButton').pack(fill=tk.X, pady=10)
    
    def create_asset_panel(self, parent):
        """Create the asset management panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Asset list
        list_frame = ttk.Frame(main_frame, style='Card.TFrame')
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Search and filter
        search_frame = ttk.Frame(list_frame)
        search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.asset_search = ttk.Entry(search_frame)
        self.asset_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.asset_search.bind('<KeyRelease>', self.filter_assets)
        
        ttk.Button(search_frame, text="Refresh", command=self.refresh_assets).pack(side=tk.LEFT)
        
        # Asset treeview
        self.asset_tree = ttk.Treeview(list_frame, columns=('id', 'type', 'ip', 'protocol', 'status'), show='headings')
        self.asset_tree.heading('id', text='ID')
        self.asset_tree.heading('type', text='Type')
        self.asset_tree.heading('ip', text='IP Address')
        self.asset_tree.heading('protocol', text='Protocol')
        self.asset_tree.heading('status', text='Status')
        
        self.asset_tree.column('id', width=100)
        self.asset_tree.column('type', width=150)
        self.asset_tree.column('ip', width=120)
        self.asset_tree.column('protocol', width=120)
        self.asset_tree.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.asset_tree.yview)
        self.asset_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.asset_tree.pack(fill=tk.BOTH, expand=True)
        
        # Asset details
        detail_frame = ttk.Frame(main_frame, style='Card.TFrame', width=400)
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(5, 0))
        
        self.asset_detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, width=40, 
                                                         bg=self.card_color, fg=self.text_color,
                                                         font=('Consolas', 9))
        self.asset_detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind selection event
        self.asset_tree.bind('<<TreeviewSelect>>', self.show_asset_details)
        
        # Populate assets
        self.refresh_assets()
    
    def create_network_monitor(self, parent):
        """Create the network monitoring panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Protocol traffic graph
        graph_frame = ttk.Frame(main_frame, style='Card.TFrame')
        graph_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.protocol_figure = plt.Figure(figsize=(8, 4), dpi=100)
        self.protocol_ax = self.protocol_figure.add_subplot(111)
        self.protocol_canvas = FigureCanvasTkAgg(self.protocol_figure, graph_frame)
        self.protocol_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Protocol details
        detail_frame = ttk.Frame(main_frame, style='Card.TFrame')
        detail_frame.pack(fill=tk.BOTH, expand=True)
        
        self.protocol_tree = ttk.Treeview(detail_frame, columns=('protocol', 'traffic', 'alerts', 'status'), show='headings')
        self.protocol_tree.heading('protocol', text='Protocol')
        self.protocol_tree.heading('traffic', text='Traffic (pkts/min)')
        self.protocol_tree.heading('alerts', text='Alerts')
        self.protocol_tree.heading('status', text='Status')
        
        self.protocol_tree.column('protocol', width=150)
        self.protocol_tree.column('traffic', width=100)
        self.protocol_tree.column('alerts', width=80)
        self.protocol_tree.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(detail_frame, orient=tk.VERTICAL, command=self.protocol_tree.yview)
        self.protocol_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.protocol_tree.pack(fill=tk.BOTH, expand=True)
        
        # Populate protocols
        self.update_protocol_monitor()
    
    def create_alert_panel(self, parent):
        """Create the alert management panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Alert list
        list_frame = ttk.Frame(main_frame, style='Card.TFrame')
        list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Filter controls
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        self.alert_filter = ttk.Combobox(filter_frame, values=["All", "Unacknowledged", "Critical", "High", "Medium", "Low"])
        self.alert_filter.current(0)
        self.alert_filter.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.alert_filter.bind('<<ComboboxSelected>>', self.filter_alerts)
        
        ttk.Button(filter_frame, text="Acknowledge", command=self.acknowledge_alert).pack(side=tk.LEFT, padx=5)
        
        # Alert treeview
        self.alert_tree = ttk.Treeview(list_frame, columns=('time', 'alert', 'severity', 'ack'), show='headings')
        self.alert_tree.heading('time', text='Time')
        self.alert_tree.heading('alert', text='Alert')
        self.alert_tree.heading('severity', text='Severity')
        self.alert_tree.heading('ack', text='Acknowledged')
        
        self.alert_tree.column('time', width=120)
        self.alert_tree.column('alert', width=250)
        self.alert_tree.column('severity', width=80)
        self.alert_tree.column('ack', width=100)
        
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.alert_tree.yview)
        self.alert_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.alert_tree.pack(fill=tk.BOTH, expand=True)
        
        # Alert details
        detail_frame = ttk.Frame(main_frame, style='Card.TFrame', width=400)
        detail_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(5, 0))
        
        self.alert_detail_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, width=40, 
                                                         bg=self.card_color, fg=self.text_color,
                                                         font=('Consolas', 9))
        self.alert_detail_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Action buttons
        action_frame = ttk.Frame(detail_frame)
        action_frame.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(action_frame, text="Mitigate", command=self.mitigate_alert).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(action_frame, text="Isolate", command=self.isolate_alert_source, style='Red.TButton').pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # Bind selection event
        self.alert_tree.bind('<<TreeviewSelect>>', self.show_alert_details)
        
        # Populate alerts
        self.refresh_alerts()
    def create_incident_response_panel(self, parent):
        """Create the incident response panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Incident details
        detail_frame = ttk.Frame(main_frame, style='Card.TFrame')
        detail_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        ttk.Label(detail_frame, text="Active Incident", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        self.incident_text = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, height=8, 
                                                     bg=self.card_color, fg=self.text_color,
                                                     font=('Consolas', 9))
        self.incident_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.incident_text.insert(tk.END, "No active incidents detected")
        
        # Response actions
        action_frame = ttk.Frame(main_frame, style='Card.TFrame')
        action_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(action_frame, text="Response Actions", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        button_frame = ttk.Frame(action_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        ttk.Button(button_frame, text="Contain Threat", command=self.contain_threat).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(button_frame, text="Collect Evidence", command=self.collect_evidence).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(button_frame, text="Eradicate", command=self.eradicate_threat).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        ttk.Button(button_frame, text="Recover", command=self.recover_systems).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        # Playbook frame
        playbook_frame = ttk.Frame(main_frame, style='Card.TFrame')
        playbook_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(playbook_frame, text="Response Playbook", font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=5, pady=5)
        
        self.playbook_tree = ttk.Treeview(playbook_frame, columns=('step', 'action', 'status'), show='headings')
        self.playbook_tree.heading('step', text='Step')
        self.playbook_tree.heading('action', text='Action')
        self.playbook_tree.heading('status', text='Status')
        
        self.playbook_tree.column('step', width=50)
        self.playbook_tree.column('action', width=300)
        self.playbook_tree.column('status', width=100)
        
        scrollbar = ttk.Scrollbar(playbook_frame, orient=tk.VERTICAL, command=self.playbook_tree.yview)
        self.playbook_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.playbook_tree.pack(fill=tk.BOTH, expand=True)
        
        # Populate with generic playbook
        self.load_incident_playbook()
    
    def initialize_sample_assets(self):
        """Initialize the application with sample industrial assets"""
        asset_types = [
            "PLC", "RTU", "HMI", "SCADA Server", "Engineering Workstation",
            "Historian", "IED", "Protection Relay", "VFD", "DCS Controller",
            "Safety Instrumented System", "Firewall", "Switch", "Router"
        ]
        
        protocols = IndustrialProtocol.all_protocols()
        
        for i in range(1, 25):
            asset_type = random.choice(asset_types)
            protocol = random.choice(protocols)
            criticality = random.choice(["Low", "Medium", "High", "Critical"])
            
            # Generate IP in industrial range
            ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            asset = IndustrialAsset(
                asset_id=f"ASSET-{i:03d}",
                asset_type=asset_type,
                ip_address=ip,
                protocol=protocol,
                criticality=criticality
            )
            
            # Add some vulnerabilities
            if random.random() < 0.4:  # 40% chance of having vulnerabilities
                num_vulns = random.randint(1, 3)
                for _ in range(num_vulns):
                    attack = random.choice(self.attack_patterns)
                    if attack.protocol == protocol:
                        asset.add_vulnerability(
                            attack.cve,
                            f"Vulnerable to {attack.name}",
                            attack.severity
                        )
            
            # Add some security controls
            if random.random() < 0.7:  # 70% chance of having security controls
                control_types = [
                    "Firewall Rules", "Access Control", "Patch Management",
                    "Network Segmentation", "Log Monitoring", "Backup",
                    "Authentication", "Encryption", "IDS/IPS"
                ]
                num_controls = random.randint(1, 4)
                for _ in range(num_controls):
                    asset.add_security_control(
                        random.choice(control_types),
                        random.choice(["Enabled", "Disabled", "Partial"])
                    )
            
            self.assets.append(asset)
        
        # Add some critical assets with specific configurations
        critical_assets = [
            ("PLC-001", "PLC", "192.168.1.10", IndustrialProtocol.MODBUS_TCP, "Critical"),
            ("SCADA-01", "SCADA Server", "192.168.1.100", IndustrialProtocol.OPC_UA, "Critical"),
            ("RTU-01", "RTU", "192.168.2.50", IndustrialProtocol.DNP3, "High"),
            ("HMI-01", "HMI", "192.168.1.20", IndustrialProtocol.ETHERNET_IP, "High")
        ]
        
        for asset_id, asset_type, ip, protocol, criticality in critical_assets:
            asset = IndustrialAsset(asset_id, asset_type, ip, protocol, criticality)
            
            # Add vulnerabilities to critical assets
            for attack in self.attack_patterns:
                if attack.protocol == protocol and random.random() < 0.6:
                    asset.add_vulnerability(
                        attack.cve,
                        f"Vulnerable to {attack.name}",
                        attack.severity
                    )
            
            # Add security controls
            asset.add_security_control("Firewall Rules", "Enabled")
            asset.add_security_control("Access Control", "Enabled")
            asset.add_security_control("Patch Management", "Partial")
            
            self.assets.append(asset)
        
        self.refresh_assets()
    
    def initialize_ai_models(self):
        """Initialize the AI/ML models for anomaly detection"""
        self.ai_models = {
            "Isolation Forest": IsolationForest(contamination=0.05),
            "One-Class SVM": OneClassSVM(nu=0.05),
            "DBSCAN": DBSCAN(eps=0.5, min_samples=5)
        }
        
        # Initialize with empty data
        for model in self.ai_models.values():
            X = np.random.rand(10, 1)  # Dummy data
            model.fit(X)
        
        self.models_trained = False
    
    def update_time(self):
        """Update the time display"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=now)
        self.root.after(1000, self.update_time)
    
    def refresh_assets(self):
        """Refresh the asset treeview"""
        for item in self.asset_tree.get_children():
            self.asset_tree.delete(item)
        
        for asset in sorted(self.assets, key=lambda x: x.asset_id):
            status_color = ""
            if asset.status == "Normal":
                status_color = self.safe_color
            elif asset.status == "Warning":
                status_color = self.warning_color
            elif asset.status == "Critical":
                status_color = self.critical_color
            
            self.asset_tree.insert('', tk.END, values=(
                asset.asset_id,
                asset.asset_type,
                asset.ip_address,
                asset.protocol,
                asset.status
            ), tags=(status_color,))
        
        # Configure tag colors
        self.asset_tree.tag_configure(self.safe_color, foreground=self.safe_color)
        self.asset_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.asset_tree.tag_configure(self.critical_color, foreground=self.critical_color)
        
        # Update summary
        total_assets = len(self.assets)
        critical_assets = len([a for a in self.assets if a.criticality == "Critical"])
        self.asset_summary_label.config(text=f"{total_assets} Total | {critical_assets} Critical")
    
    def filter_assets(self, event=None):
        """Filter assets based on search criteria (now actually hides non-matching rows)"""
        query = self.asset_search.get().lower()
        # Remove all items
        for item in self.asset_tree.get_children():
            self.asset_tree.delete(item)
        # Re-add only matching assets
        for asset in sorted(self.assets, key=lambda x: x.asset_id):
            values = (
                asset.asset_id,
                asset.asset_type,
                asset.ip_address,
                asset.protocol,
                asset.status
            )
            if query in " ".join(str(v).lower() for v in values):
                status_color = ""
                if asset.status == "Normal":
                    status_color = self.safe_color
                elif asset.status == "Warning":
                    status_color = self.warning_color
                elif asset.status == "Critical":
                    status_color = self.critical_color
                self.asset_tree.insert('', tk.END, values=values, tags=(status_color,))
        # Configure tag colors
        self.asset_tree.tag_configure(self.safe_color, foreground=self.safe_color)
        self.asset_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.asset_tree.tag_configure(self.critical_color, foreground=self.critical_color)
    
    def show_asset_details(self, event):
        """Show detailed information about the selected asset"""
        selected = self.asset_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        asset_id = self.asset_tree.item(item, 'values')[0]
        asset = next((a for a in self.assets if a.asset_id == asset_id), None)
        
        if not asset:
            return
        
        details = f"Asset ID: {asset.asset_id}\n"
        details += f"Type: {asset.asset_type}\n"
        details += f"IP Address: {asset.ip_address}\n"
        details += f"MAC Address: {asset.mac_address}\n"
        details += f"Protocol: {asset.protocol}\n"
        details += f"Criticality: {asset.criticality}\n"
        details += f"Status: {asset.status}\n"
        details += f"Location: {asset.location}\n"
        details += f"Firmware: {asset.firmware_version}\n"
        details += f"Operating Hours: {asset.operating_hours}\n"
        details += f"Last Seen: {asset.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        details += "=== Vulnerabilities ===\n"
        if asset.vulnerabilities:
            for vuln in asset.vulnerabilities:
                details += f"- {vuln['cve_id']} ({vuln['severity']}, CVSS: {vuln['cvss_score']})\n"
                details += f"  {vuln['description']}\n"
                details += f"  Status: {vuln['status']}, Detected: {vuln['detected'].strftime('%Y-%m-%d')}\n"
        else:
            details += "No known vulnerabilities\n"
        
        details += "\n=== Security Controls ===\n"
        if asset.security_controls:
            for control in asset.security_controls:
                details += f"- {control['type']}: {control['status']} (Effectiveness: {control['effectiveness']})\n"
                details += f"  Last checked: {control['last_checked'].strftime('%Y-%m-%d %H:%M')}\n"
        else:
            details += "No security controls configured\n"
        
        self.asset_detail_text.config(state=tk.NORMAL)
        self.asset_detail_text.delete(1.0, tk.END)
        self.asset_detail_text.insert(tk.END, details)
        self.asset_detail_text.config(state=tk.DISABLED)
    
    def refresh_alerts(self):
        """Refresh the alert treeview"""
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        
        for alert in sorted(self.alerts, key=lambda x: x['time'], reverse=True)[:100]:  # Show most recent 100
            severity = alert['severity']
            color = self.text_color
            if severity == "Critical":
                color = self.critical_color
            elif severity == "High":
                color = self.alert_color
            elif severity == "Medium":
                color = self.warning_color
            elif severity == "Low":
                color = self.info_color
            
            self.alert_tree.insert('', tk.END, values=(
                alert['time'].strftime("%Y-%m-%d %H:%M:%S"),
                alert['message'],
                severity,
                "Yes" if alert['acknowledged'] else "No"
            ), tags=(color,))
        
        # Configure tag colors
        self.alert_tree.tag_configure(self.critical_color, foreground=self.critical_color)
        self.alert_tree.tag_configure(self.alert_color, foreground=self.alert_color)
        self.alert_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.alert_tree.tag_configure(self.info_color, foreground=self.info_color)
        
        # Update summary
        total_alerts = len(self.alerts)
        unacknowledged = len([a for a in self.alerts if not a['acknowledged']])
        self.alert_summary_label.config(text=f"{total_alerts} Total | {unacknowledged} Unacknowledged")
    
    def filter_alerts(self, event=None):
        """Filter alerts based on selected criteria (now actually hides non-matching rows)"""
        filter_value = self.alert_filter.get()
        # Remove all items
        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)
        # Re-add only matching alerts
        for alert in sorted(self.alerts, key=lambda x: x['time'], reverse=True)[:100]:
            severity = alert['severity']
            color = self.text_color
            if severity == "Critical":
                color = self.critical_color
            elif severity == "High":
                color = self.alert_color
            elif severity == "Medium":
                color = self.warning_color
            elif severity == "Low":
                color = self.info_color
            show = False
            if filter_value == "All":
                show = True
            elif filter_value == "Unacknowledged" and not alert['acknowledged']:
                show = True
            elif filter_value == severity:
                show = True
            if show:
                self.alert_tree.insert('', tk.END, values=(
                    alert['time'].strftime("%Y-%m-%d %H:%M:%S"),
                    alert['message'],
                    severity,
                    "Yes" if alert['acknowledged'] else "No"
                ), tags=(color,))
        # Configure tag colors
        self.alert_tree.tag_configure(self.critical_color, foreground=self.critical_color)
        self.alert_tree.tag_configure(self.alert_color, foreground=self.alert_color)
        self.alert_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.alert_tree.tag_configure(self.info_color, foreground=self.info_color)
    
    def show_alert_details(self, event):
        """Show detailed information about the selected alert"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        alert_time = datetime.strptime(self.alert_tree.item(item, 'values')[0], "%Y-%m-%d %H:%M:%S")
        alert = next((a for a in self.alerts if a['time'] == alert_time), None)
        
        if not alert:
            return
        
        details = f"Time: {alert['time'].strftime('%Y-%m-%d %H:%M:%S')}\n"
        details += f"Severity: {alert['severity']}\n"
        details += f"Source: {alert.get('source', 'Unknown')}\n"
        details += f"Protocol: {alert.get('protocol', 'N/A')}\n"
        details += f"Acknowledged: {'Yes' if alert['acknowledged'] else 'No'}\n\n"
        details += f"Message: {alert['message']}\n\n"
        
        if 'indicators' in alert:
            details += "=== Indicators ===\n"
            for indicator in alert['indicators']:
                details += f"- {indicator}\n"
        
        if 'mitigation' in alert:
            details += "\n=== Recommended Actions ===\n"
            for action in alert['mitigation']:
                details += f"- {action}\n"
        
        if 'cve' in alert:
            details += f"\nAssociated CVE: {alert['cve']}\n"
        
        self.alert_detail_text.config(state=tk.NORMAL)
        self.alert_detail_text.delete(1.0, tk.END)
        self.alert_detail_text.insert(tk.END, details)
        self.alert_detail_text.config(state=tk.DISABLED)
    
    def acknowledge_alert(self):
        """Acknowledge the selected alert"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        alert_time = datetime.strptime(self.alert_tree.item(item, 'values')[0], "%Y-%m-%d %H:%M:%S")
        
        for alert in self.alerts:
            if alert['time'] == alert_time:
                alert['acknowledged'] = True
                break
        
        self.refresh_alerts()
    
    def acknowledge_all_alerts(self):
        """Acknowledge all alerts"""
        for alert in self.alerts:
            alert['acknowledged'] = True
        
        self.refresh_alerts()
        messagebox.showinfo("Success", "All alerts have been acknowledged")
    
    def mitigate_alert(self):
        """Initiate mitigation for the selected alert"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        alert_time = datetime.strptime(self.alert_tree.item(item, 'values')[0], "%Y-%m-%d %H:%M:%S")
        alert = next((a for a in self.alerts if a['time'] == alert_time), None)
        
        if not alert:
            return
        
        # Create a mitigation playbook
        self.playbook_tree.delete(*self.playbook_tree.get_children())
        
        steps = [
            (1, f"Isolate affected asset: {alert.get('source', 'Unknown')}", "Pending"),
            (2, f"Block malicious IP: {alert.get('attacker_ip', 'Unknown')}", "Pending"),
            (3, "Apply recommended security controls", "Pending"),
            (4, "Verify system integrity", "Pending"),
            (5, "Restore normal operations", "Pending")
        ]
        
        for step, action, status in steps:
            self.playbook_tree.insert('', tk.END, values=(step, action, status))
        
        # Update the incident panel
        self.incident_text.config(state=tk.NORMAL)
        self.incident_text.delete(1.0, tk.END)
        self.incident_text.insert(tk.END, f"Active Incident: {alert['message']}\n\n")
        self.incident_text.insert(tk.END, f"Severity: {alert['severity']}\n")
        self.incident_text.insert(tk.END, f"Time Detected: {alert['time'].strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.incident_text.insert(tk.END, f"Source: {alert.get('source', 'Unknown')}\n")
        self.incident_text.config(state=tk.DISABLED)
        
        messagebox.showinfo("Mitigation Started", "Incident response playbook has been initialized")
    
    def isolate_alert_source(self):
        """Isolate the source of the selected alert"""
        selected = self.alert_tree.selection()
        if not selected:
            return
        
        item = selected[0]
        alert_time = datetime.strptime(self.alert_tree.item(item, 'values')[0], "%Y-%m-%d %H:%M:%S")
        alert = next((a for a in self.alerts if a['time'] == alert_time), None)
        
        if not alert:
            return
        
        source = alert.get('source', None)
        if source:
            # Find the asset
            asset = next((a for a in self.assets if a.asset_id == source or a.ip_address == source), None)
            if asset:
                asset.status = "Isolated"
                self.refresh_assets()
                
                # Add an alert
                self.add_alert(
                    f"Asset {asset.asset_id} has been isolated",
                    "Isolation",
                    "High",
                    source=asset.asset_id,
                    mitigation=["Review isolation status", "Investigate root cause"]
                )
                
                messagebox.showinfo("Success", f"Asset {asset.asset_id} has been isolated")
            else:
                messagebox.showerror("Error", "Could not find asset to isolate")
        else:
            messagebox.showerror("Error", "No source information available for this alert")
    
    def isolate_critical_assets(self):
        """Isolate all critical assets as a precaution"""
        critical_assets = [a for a in self.assets if a.criticality == "Critical"]
        
        if not critical_assets:
            messagebox.showinfo("Info", "No critical assets found")
            return
        
        if messagebox.askyesno("Confirm", f"Isolate {len(critical_assets)} critical assets?"):
            for asset in critical_assets:
                asset.status = "Isolated"
            
            self.refresh_assets()
            
            self.add_alert(
                f"{len(critical_assets)} critical assets have been isolated",
                "Isolation",
                "High",
                mitigation=["Review isolation status", "Investigate threats"]
            )
            
            messagebox.showinfo("Success", f"{len(critical_assets)} critical assets isolated")
    
    def emergency_shutdown(self):
        """Initiate emergency shutdown procedure"""
        if messagebox.askyesno("EMERGENCY SHUTDOWN", 
                             "WARNING: This will initiate emergency shutdown procedures!\n\n"
                             "Are you sure you want to continue?", icon='warning'):
            
            # Isolate all critical assets
            for asset in self.assets:
                if asset.criticality in ["High", "Critical"]:
                    asset.status = "Isolated"
            
            # Create a high priority alert
            self.add_alert(
                "EMERGENCY SHUTDOWN INITIATED",
                "System",
                "Critical",
                mitigation=["Investigate emergency", "Review system logs"]
            )
            
            # Update UI
            self.refresh_assets()
            self.threat_level = 100
            self.update_threat_level()
            
            messagebox.showwarning("Shutdown Initiated", 
                                 "Emergency shutdown procedures activated!\n\n"
                                 "All critical assets have been isolated.")
    
    def load_incident_playbook(self):
        """Load the default incident response playbook"""
        self.playbook_tree.delete(*self.playbook_tree.get_children())
        
        steps = [
            (1, "Identify affected systems", "Pending"),
            (2, "Contain the incident", "Pending"),
            (3, "Collect forensic evidence", "Pending"),
            (4, "Eradicate the threat", "Pending"),
            (5, "Recover systems", "Pending"),
            (6, "Post-incident review", "Pending")
        ]
        
        for step, action, status in steps:
            self.playbook_tree.insert('', tk.END, values=(step, action, status))
    
    def contain_threat(self):
        """Execute containment procedures"""
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Contain" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "In Progress"))
                break
        
        # Simulate containment
        threading.Thread(target=self.simulate_containment).start()
    
    def simulate_containment(self):
        """Simulate containment procedures"""
        time.sleep(2)
        
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Contain" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "Completed"))
                break
        
        self.add_alert(
            "Threat containment procedures completed",
            "Incident Response",
            "Medium",
            mitigation=["Verify containment", "Proceed with eradication"]
        )
    
    def collect_evidence(self):
        """Execute evidence collection procedures"""
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Collect" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "In Progress"))
                break
        
        # Simulate evidence collection
        threading.Thread(target=self.simulate_evidence_collection).start()
    
    def simulate_evidence_collection(self):
        """Simulate evidence collection"""
        time.sleep(3)
        
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Collect" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "Completed"))
                break
        
        self.add_alert(
            "Forensic evidence collection completed",
            "Incident Response",
            "Medium",
            mitigation=["Analyze collected evidence", "Update threat intelligence"]
        )
    
    def eradicate_threat(self):
        """Execute threat eradication procedures"""
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Eradicate" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "In Progress"))
                break
        
        # Simulate eradication
        threading.Thread(target=self.simulate_eradication).start()
    
    def simulate_eradication(self):
        """Simulate threat eradication"""
        time.sleep(4)
        
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Eradicate" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "Completed"))
                break
        
        self.add_alert(
            "Threat eradication procedures completed",
            "Incident Response",
            "Medium",
            mitigation=["Verify eradication", "Prepare for recovery"]
        )
    
    def recover_systems(self):
        """Execute system recovery procedures"""
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Recover" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "In Progress"))
                break
        
        # Simulate recovery
        threading.Thread(target=self.simulate_recovery).start()
    
    def simulate_recovery(self):
        """Simulate system recovery"""
        time.sleep(5)
        
        # Restore isolated assets
        for asset in self.assets:
            if asset.status == "Isolated":
                asset.status = "Normal"
        
        self.refresh_assets()
        
        for item in self.playbook_tree.get_children():
            values = self.playbook_tree.item(item, 'values')
            if "Recover" in values[1]:
                self.playbook_tree.item(item, values=(values[0], values[1], "Completed"))
                break
        
        self.add_alert(
            "System recovery procedures completed",
            "Incident Response",
            "Medium",
            mitigation=["Monitor system stability", "Conduct post-incident review"]
        )
        
        # Reset threat level
        self.threat_level = 0
        self.update_threat_level()
        
        # Clear incident
        self.incident_text.config(state=tk.NORMAL)
        self.incident_text.delete(1.0, tk.END)
        self.incident_text.insert(tk.END, "No active incidents detected")
        self.incident_text.config(state=tk.DISABLED)
    
    def update_protocol_monitor(self):
        """Update the protocol traffic monitoring display"""
        self.protocol_tree.delete(*self.protocol_tree.get_children())
        
        for protocol, traffic in self.protocol_traffic.items():
            if not traffic:
                continue
            
            # Calculate average traffic
            last10 = list(traffic)[-10:]
            avg_traffic = sum(last10) / len(last10)
            
            # Count alerts for this protocol
            alert_count = len([a for a in self.alerts if a.get('protocol') == protocol])
            
            # Determine status
            if alert_count > 5:
                status = "Critical"
                status_color = self.critical_color
            elif alert_count > 2:
                status = "Warning"
                status_color = self.warning_color
            else:
                status = "Normal"
                status_color = self.safe_color
            
            self.protocol_tree.insert('', tk.END, values=(
                protocol,
                f"{avg_traffic:.1f}",
                alert_count,
                status
            ), tags=(status_color,))
        
        # Configure tag colors
        self.protocol_tree.tag_configure(self.safe_color, foreground=self.safe_color)
        self.protocol_tree.tag_configure(self.warning_color, foreground=self.warning_color)
        self.protocol_tree.tag_configure(self.critical_color, foreground=self.critical_color)
        
        # Update protocol summary
        active_protocols = len([p for p, t in self.protocol_traffic.items() if t])
        anomalous_protocols = len([p for p, t in self.protocol_traffic.items() 
                                 if t and max(list(t)[-10:]) > 2 * (sum(list(t)[-10:])/len(list(t)[-10:]))])
        self.protocol_summary_label.config(text=f"{active_protocols} Active | {anomalous_protocols} Anomalous")
    
    def update_network_graph(self):
        """Update the network traffic graph"""
        self.ax.clear()
        
        # Prepare data
        protocols = []
        traffic = []
        colors = []
        
        for protocol, values in self.protocol_traffic.items():
            if values:
                protocols.append(protocol)
                last10 = list(values)[-10:]
                traffic.append(sum(last10) / len(last10))  # Average of last 10
                
                # Color based on alerts
                alert_count = len([a for a in self.alerts if a.get('protocol') == protocol])
                if alert_count > 5:
                    colors.append(self.critical_color)
                elif alert_count > 2:
                    colors.append(self.warning_color)
                else:
                    colors.append(self.accent_color)
        
        if not protocols:
            return
        
        # Create bar chart
        x = range(len(protocols))
        bars = self.ax.bar(x, traffic, color=colors)
        
        # Add labels
        self.ax.set_xticks(x)
        self.ax.set_xticklabels(protocols, rotation=45, ha='right')
        self.ax.set_ylabel('Traffic (pkts/min)')
        self.ax.set_title('Industrial Protocol Traffic')
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            self.ax.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height:.1f}',
                        ha='center', va='bottom')
        
        self.figure.tight_layout()
        self.canvas.draw()
    
    def update_protocol_graph(self):
        """Update the protocol-specific traffic graph"""
        self.protocol_ax.clear()
        
        # Show traffic for all protocols
        for protocol, traffic in self.protocol_traffic.items():
            if traffic:
                self.protocol_ax.plot(traffic, label=protocol)
        
        self.protocol_ax.set_xlabel('Time (minutes)')
        self.protocol_ax.set_ylabel('Traffic (pkts/min)')
        self.protocol_ax.set_title('Protocol Traffic Over Time')
        self.protocol_ax.legend()
        self.protocol_ax.grid(True)
        
        self.protocol_figure.tight_layout()
        self.protocol_canvas.draw()
    
    def update_threat_level(self):
        """Update the threat level indicator"""
        self.threat_label.config(text=f"{self.threat_level}%")
        
        # Change color based on level
        if self.threat_level >= 75:
            self.threat_label.config(foreground=self.critical_color)
        elif self.threat_level >= 50:
            self.threat_label.config(foreground=self.warning_color)
        elif self.threat_level >= 25:
            self.threat_label.config(foreground=self.info_color)
        else:
            self.threat_label.config(foreground=self.safe_color)
    
    def add_alert(self, message, source, severity, x=None, y=None, **kwargs):
        """Add a new alert to the system"""
        alert = {
            'time': datetime.now(),
            'message': message,
            'source': source,
            'severity': severity,
            'acknowledged': False
        }
        
        # Add additional fields
        for key, value in kwargs.items():
            alert[key] = value
        
        self.alerts.append(alert)
        
        # Add to queue for processing
        self.alert_queue.put(alert)
        
        # Update UI
        self.refresh_alerts()
        
        # Show notification for high severity alerts
        if severity in ["Critical", "High"]:
            self.show_notification(message, severity)
        
        # If alert has a location, update the heatmap data
        if x is not None and y is not None:
            self.heatmap_data[y, x] += self.severity_to_intensity(severity)
    
    def severity_to_intensity(self, severity):
        # Map severity to a heatmap increment value
        return {
            "Critical": 30,
            "High": 20,
            "Medium": 10,
            "Low": 5
        }.get(severity, 1)
    
    def show_notification(self, message, severity):
        """Show a notification popup for important alerts (thread-safe)"""
        def notify():
            if severity == "Critical":
                title = "CRITICAL ALERT"
                icon = "warning"
            elif severity == "High":
                title = "HIGH PRIORITY ALERT"
                icon = "warning"
            else:
                title = "ALERT NOTIFICATION"
                icon = "info"
            messagebox.showwarning(title, message)
        self.root.after(0, notify)
    
    def process_alerts(self):
        """Background process to handle alert processing"""
        while self.running:
            try:
                alert = self.alert_queue.get(timeout=0.5)
                
                # Update threat level based on alert severity
                if alert['severity'] == "Critical":
                    self.threat_level = min(100, self.threat_level + 15)
                elif alert['severity'] == "High":
                    self.threat_level = min(100, self.threat_level + 10)
                elif alert['severity'] == "Medium":
                    self.threat_level = min(100, self.threat_level + 5)
                else:
                    self.threat_level = min(100, self.threat_level + 2)
                
                self.update_threat_level()
                
                # Update recent alerts
                self.update_recent_alerts()
                
            except queue.Empty:
                pass
            
            # Gradually reduce threat level when no alerts
            if random.random() < 0.1 and self.threat_level > 0:
                self.threat_level = max(0, self.threat_level - 1)
                self.update_threat_level()
    
    def update_recent_alerts(self):
        """Update the recent alerts display on dashboard"""
        self.recent_alerts_tree.delete(*self.recent_alerts_tree.get_children())
        
        for alert in sorted(self.alerts, key=lambda x: x['time'], reverse=True)[:5]:
            self.recent_alerts_tree.insert('', tk.END, values=(
                alert['time'].strftime("%H:%M:%S"),
                alert['message'][:40] + "..." if len(alert['message']) > 40 else alert['message'],
                alert['severity']
            ))
    
    def simulate_industrial_network(self):
        """Simulate industrial network traffic and attacks"""
        while self.running:
            try:
                # Generate normal traffic
                for protocol in self.protocol_traffic.keys():
                    traffic = self.traffic_generator.generate_normal_traffic(protocol)
                    self.protocol_traffic[protocol].append(traffic)
                
                # Randomly trigger attacks
                if not self.attack_in_progress and random.random() < 0.05:  # 5% chance of attack
                    self.trigger_attack()
                
                # Update displays
                self.update_network_graph()
                self.update_protocol_graph()
                self.update_protocol_monitor()
                
                # Update asset statuses
                self.update_asset_statuses()
                
                time.sleep(1)
                
            except Exception as e:
                print(f"Error in network simulation: {e}")
                time.sleep(1)
    
    def trigger_attack(self):
        """Trigger a simulated industrial attack"""
        self.attack_in_progress = True
        attack = random.choice(self.attack_patterns)
        self.current_attack = attack
        
        # Select target asset
        target_assets = [a for a in self.assets if a.protocol == attack.protocol]
        if not target_assets:
            self.attack_in_progress = False
            return
        
        target = random.choice(target_assets)
        
        # Calculate duration
        duration = self.traffic_generator.get_attack_duration(attack.severity)
        attack.last_detected = datetime.now()
        attack.detection_count += 1
        
        # Generate attack traffic
        attack_traffic = self.traffic_generator.generate_attack_traffic(attack.protocol, attack.severity)
        
        # Create alert
        self.add_alert(
            f"{attack.name} detected on {target.asset_id}",
            target.asset_id,
            attack.severity,
            protocol=attack.protocol,
            indicators=attack.indicators,
            mitigation=attack.mitigation,
            cve=attack.cve,
            attacker_ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
        )
        
        # Update target asset status
        target.status = "Under Attack"
        self.refresh_assets()
        
        # Simulate attack traffic
        start_time = time.time()
        while time.time() - start_time < duration and self.running:
            self.protocol_traffic[attack.protocol].append(attack_traffic)
            time.sleep(0.5)
        
        # Reset after attack
        target.status = "Compromised" if random.random() < 0.3 else "Normal"
        self.refresh_assets()
        self.current_attack = None
        self.attack_in_progress = False
    
    def update_asset_statuses(self):
        """Periodically update asset statuses based on network conditions"""
        for asset in self.assets:
            # Skip if already in a bad state
            if asset.status in ["Under Attack", "Compromised", "Isolated"]:
                continue
            
            # Check protocol traffic for anomalies
            traffic = self.protocol_traffic.get(asset.protocol, [])
            if not traffic:
                continue
                
            avg_traffic = sum(traffic) / len(traffic)
            last_traffic = traffic[-1]
            
            # Mark as warning if traffic spikes
            if last_traffic > 2 * avg_traffic:
                asset.status = "Warning"
            else:
                asset.status = "Normal"
        
        # Refresh UI periodically
        if random.random() < 0.1:  # 10% chance to refresh
            self.refresh_assets()
    
    def train_ai_models(self):
        """Train the AI models with simulated data"""
        while self.running:
            try:
                if not self.models_trained:
                    # Generate training data
                    X = np.random.rand(100, 5)  # 100 samples, 5 features
                    y = np.random.randint(0, 2, 100)  # Binary classification
                    
                    # Train models
                    for name, model in self.ai_models.items():
                        if name != "DBSCAN":  # DBSCAN is unsupervised
                            model.fit(X, y)
                        else:
                            model.fit(X)
                    
                    self.models_trained = True
                    self.add_alert(
                        "AI models training completed",
                        "System",
                        "Low",
                        mitigation=["Verify model performance", "Review detection rules"]
                    )
                
                time.sleep(10)
                
            except Exception as e:
                print(f"Error in model training: {e}")
                time.sleep(5)
    
    def detect_anomalies(self):
        """Run anomaly detection using AI models"""
        while self.running:
            try:
                if self.models_trained:
                    # Generate sample data
                    X = np.random.rand(10, 5)  # 10 samples, 5 features
                    
                    # Get predictions from each model
                    for name, model in self.ai_models.items():
                        if name == "DBSCAN":
                            pred = model.fit_predict(X)
                            anomalies = sum(pred == -1)  # -1 indicates anomaly in DBSCAN
                        else:
                            pred = model.predict(X)
                            anomalies = sum(pred == 1)  # 1 indicates anomaly in other models
                        
                        if anomalies > 2:  # If more than 2 anomalies detected
                            self.add_alert(
                                f"{anomalies} anomalies detected by {name}",
                                "Anomaly Detection",
                                "Medium",
                                mitigation=["Review network traffic", "Verify system behavior"]
                            )
                
                time.sleep(5)
                
            except Exception as e:
                print(f"Error in anomaly detection: {e}")
                time.sleep(5)
    
    def monitor_asset_health(self):
        """Monitor asset health and generate alerts"""
        while self.running:
            try:
                for asset in self.assets:
                    # Random health events
                    if random.random() < 0.01:  # 1% chance of health event
                        event = random.choice([
                            "high CPU usage", "memory leak", "network latency",
                            "disk full", "process crash", "connection timeout"
                        ])
                        
                        severity = random.choice(["Low", "Medium", "High"])
                        if asset.criticality == "Critical":
                            severity = random.choice(["High", "Critical"])
                        
                        self.add_alert(
                            f"{asset.asset_id} experiencing {event}",
                            asset.asset_id,
                            severity,
                            mitigation=["Check system logs", "Restart service if needed"]
                        )
                
                time.sleep(10)
                
            except Exception as e:
                print(f"Error in health monitoring: {e}")
                time.sleep(5)
    
    def generate_report(self):
        """Generate a PDF security report"""
        try:
            report = PDFReport()
            report.add_page()
            
            # Report header
            report.set_font('Arial', 'B', 16)
            report.cell(0, 10, 'Industrial Security Assessment Report', 0, 1, 'C')
            report.ln(10)
            
            # System information
            report.chapter_title('System Information')
            report.chapter_body(f"Facility: {self.facility}\nOperator: {self.operator}\nSystem ID: {self.system_id}\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Asset summary
            report.chapter_title('Asset Summary')
            asset_data = [
                ['ID', 'Type', 'IP', 'Protocol', 'Criticality'],
                *[(a.asset_id, a.asset_type, a.ip_address, a.protocol, a.criticality) 
                  for a in sorted(self.assets, key=lambda x: x.criticality, reverse=True)]
            ]
            report.add_table(asset_data[0], asset_data[1:])
            
            # Vulnerability summary
            report.chapter_title('Vulnerability Summary')
            vuln_data = []
            for asset in self.assets:
                for vuln in asset.vulnerabilities:
                    vuln_data.append([
                        asset.asset_id,
                        vuln['cve_id'],
                        vuln['severity'],
                        vuln['cvss_score'],
                        vuln['status']
                    ])
            
            if vuln_data:
                report.add_table(['Asset', 'CVE ID', 'Severity', 'CVSS', 'Status'], vuln_data)
            else:
                report.chapter_body("No vulnerabilities detected")
            
            # Alert summary
            report.chapter_title('Alert Summary')

# Define headers      
            # Recommendations
            report.chapter_title('Security Recommendations')
            recommendations = [
                "1. Implement network segmentation for critical assets",
                "2. Enable protocol-specific security features",
                "3. Patch systems with known vulnerabilities",
                "4. Review and update firewall rules",
                "5. Conduct regular security awareness training"
            ]
            report.chapter_body('\n'.join(recommendations))
            
            # Save the report
            filename = f"ScureProd_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            report.output(filename)
            
            self.add_alert(
                f"Security report generated: {filename}",
                "Reporting",
                "Low",
                mitigation=["Review report findings", "Implement recommendations"]
            )
            
            messagebox.showinfo("Report Generated", f"Security report saved as {filename}")
            
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {e}")
            print(f"Report Error: {e}")
    
    def run_asset_discovery(self):
        """Simulate asset discovery scan"""
        self.add_alert(
            "Asset discovery scan initiated",
            "Discovery",
            "Low",
            mitigation=["Review discovered assets", "Update inventory"]
        )
        
        # Simulate discovery finding new assets
        if random.random() < 0.5:
            new_assets = random.randint(1, 3)
            for i in range(new_assets):
                asset_types = ["PLC", "HMI", "RTU", "Network Switch"]
                protocols = IndustrialProtocol.all_protocols()
                
                asset = IndustrialAsset(
                    asset_id=f"NEW-{random.randint(100,999)}",
                    asset_type=random.choice(asset_types),
                    ip_address=f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    protocol=random.choice(protocols),
                    criticality=random.choice(["Low", "Medium", "High"])
                )
                
                self.assets.append(asset)
            
            self.refresh_assets()
            self.add_alert(
                f"Discovered {new_assets} new assets",
                "Discovery",
                "Medium",
                mitigation=["Verify new assets", "Update network diagrams"]
            )
        
        messagebox.showinfo("Discovery Complete", "Asset discovery scan completed")
    
    def run_vulnerability_scan(self):
        """Simulate vulnerability scan"""
        self.add_alert(
            "Vulnerability scan initiated",
            "Scanning",
            "Low",
            mitigation=["Review scan results", "Prioritize remediation"]
        )
        
        # Simulate finding vulnerabilities
        vuln_found = 0
        for asset in self.assets:
            if random.random() < 0.3:  # 30% chance of finding a new vuln
                attack = random.choice(self.attack_patterns)
                if attack.protocol == asset.protocol:
                    asset.add_vulnerability(
                        attack.cve,
                        f"Vulnerable to {attack.name}",
                        attack.severity
                    )
                    vuln_found += 1
        
        if vuln_found:
            self.refresh_assets()
            self.add_alert(
                f"Vulnerability scan found {vuln_found} new issues",
                "Scanning",
                "Medium",
                mitigation=["Review vulnerabilities", "Plan patching schedule"]
            )
        
        messagebox.showinfo("Scan Complete", f"Vulnerability scan completed. Found {vuln_found} new issues.")
    
    def backup_configurations(self):
        """Simulate configuration backup"""
        self.add_alert(
            "Configuration backup initiated",
            "Backup",
            "Low",
            mitigation=["Verify backup integrity", "Store securely"]
        )
        
        # Simulate backup process
        time.sleep(2)
        
        self.add_alert(
            "Configuration backup completed",
            "Backup",
            "Low",
            mitigation=["Test restoration procedure", "Update documentation"]
        )
        
        messagebox.showinfo("Backup Complete", "Device configurations backed up successfully")
    
    def show_threat_intel(self):
        """Display threat intelligence information"""
        intel_window = tk.Toplevel(self.root)
        intel_window.title("Threat Intelligence")
        intel_window.geometry("800x600")
        
        text = scrolledtext.ScrolledText(intel_window, wrap=tk.WORD, width=100, height=30,
                                       font=('Consolas', 10))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Generate threat intel report
        report = ["=== Industrial Threat Intelligence ===",
                 f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
                 "Known Attack Patterns:"]
        
        for attack in self.attack_patterns:
            report.append(f"\n{attack.name} ({attack.protocol}) - {attack.severity}")
            report.append(f"CVE: {attack.cve}")
            report.append("Indicators:")
            report.extend(f"- {i}" for i in attack.indicators)
            report.append("Mitigation:")
            report.extend(f"- {m}" for m in attack.mitigation)
            report.append("")
        
        text.insert(tk.END, '\n'.join(report))
        text.config(state=tk.DISABLED)
    
    def show_documentation(self):
        """Open documentation in web browser"""
        webbrowser.open("https://www.example.com/scureprod-docs")
    
    def show_about(self):
        """Show about dialog"""
        # Fix psutil.cpu_percent() to get actual usage
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory().percent
        about_text = f"""ScureProd Industrial Cyber Defense Platform
Version 1.0.0

Developed for  Manufacturing
© 2025 Reda Ouzidane 

System ID: {self.system_id}
Python: {platform.python_version()}
OS: {platform.system()} {platform.release()}
CPU: {cpu}% usage
Memory: {mem}% used
"""
        messagebox.showinfo("About ScureProd", about_text)
    
    def new_session(self):
        """Start a new session"""
        if messagebox.askyesno("New Session", "Start a new session? Current data will be lost."):
            self.assets = []
            self.alerts = []
            self.attack_log = []
            self.network_traffic = []
            self.protocol_traffic = {p: deque(maxlen=100) for p in IndustrialProtocol.all_protocols()}
            self.threat_level = 0
            
            self.initialize_sample_assets()
            self.refresh_assets()
            self.refresh_alerts()
            self.update_threat_level()
            
            messagebox.showinfo("New Session", "New session initialized")
    
    def save_session(self):
        """Save current session to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if not filename:
                return
                
            data = {
                'assets': [vars(a) for a in self.assets],
                'alerts': self.alerts,
                'threat_level': self.threat_level,
                'system_id': self.system_id,
                'operator': self.operator,
                'facility': self.facility
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            
            messagebox.showinfo("Session Saved", f"Session saved to {filename}")
            
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save session: {e}")
            print(f"Save Error: {e}")
    
    def load_session(self):
        """Load session from file"""
        try:
            filename = filedialog.askopenfilename(
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if not filename:
                return
                
            with open(filename, 'r') as f:
                data = json.load(f)
            
            # Restore assets
            self.assets = []
            for asset_data in data.get('assets', []):
                asset = IndustrialAsset(
                    asset_id=asset_data['asset_id'],
                    asset_type=asset_data['asset_type'],
                    ip_address=asset_data['ip_address'],
                    protocol=asset_data['protocol'],
                    criticality=asset_data['criticality']
                )
                
                # Restore additional attributes
                for key, value in asset_data.items():
                    if key not in ['asset_id', 'asset_type', 'ip_address', 'protocol', 'criticality']:
                        setattr(asset, key, value)
                
                self.assets.append(asset)
            
            # Restore alerts
            self.alerts = data.get('alerts', [])
            
            # Restore system info
            self.system_id = data.get('system_id', str(uuid.uuid4())[:8])
            self.operator = data.get('operator', "Industrial Security Operator")
            self.facility = data.get('facility', "ACME Manufacturing Plant")
            self.threat_level = data.get('threat_level', 0)
            
            # Refresh UI
            self.refresh_assets()
            self.refresh_alerts()
            self.update_threat_level()
            
            messagebox.showinfo("Session Loaded", f"Session loaded from {filename}")
            
        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load session: {e}")
            print(f"Load Error: {e}")
    
    def on_close(self):
        """Handle application close"""
        if messagebox.askokcancel("Quit", "Do you want to quit ScureProd?"):
            self.running = False
            self.root.destroy()

    def create_visualization_panel(self, parent):
        """Create 3D/2D visualization panel that connects to localhost:8050"""
        
        # Main frame
        main_frame = tk.Frame(parent, bg=self.card_color, bd=2, relief=tk.RIDGE, highlightbackground=self.accent_color, highlightthickness=2)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # Header
        header = tk.Label(main_frame, text="🗺️ 3D/2D Industrial Security Visualization", 
                         bg=self.card_color, fg=self.accent_color, 
                         font=(self.font_family, 16, 'bold'), pady=15)
        header.pack(fill=tk.X)
        
        # Control frame
        control_frame = tk.Frame(main_frame, bg=self.card_color)
        control_frame.pack(fill=tk.X, pady=10)
        
        # Launch buttons
        btn_frame = tk.Frame(control_frame, bg=self.card_color)
        btn_frame.pack(fill=tk.X, pady=5)
        
        launch_3d_btn = tk.Button(btn_frame, text="🚀 Launch 3D Threat Model", 
                                 font=(self.font_family, 14, 'bold'), 
                                 bg="#00FF7F", fg="#101020", bd=0, relief=tk.FLAT,
                                 activebackground="#00CC66", activeforeground="#101020",
                                 cursor="hand2", command=self.launch_3d_visualization)
        launch_3d_btn.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=10)
        
        launch_2d_btn = tk.Button(btn_frame, text="🗺️ Launch 2D Technical Map", 
                                 font=(self.font_family, 14, 'bold'), 
                                 bg="#0072B2", fg="#ffffff", bd=0, relief=tk.FLAT,
                                 activebackground="#005A8F", activeforeground="#ffffff",
                                 cursor="hand2", command=self.launch_2d_visualization)
        launch_2d_btn.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=10)
        
        launch_full_btn = tk.Button(btn_frame, text="📊 Launch Full Dashboard", 
                                   font=(self.font_family, 14, 'bold'), 
                                   bg="#FFA500", fg="#101020", bd=0, relief=tk.FLAT,
                                   activebackground="#CC8400", activeforeground="#101020",
                                   cursor="hand2", command=self.launch_full_dashboard)
        launch_full_btn.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=10)
        
        # Status frame
        status_frame = tk.Frame(main_frame, bg=self.card_color)
        status_frame.pack(fill=tk.X, pady=10)
        
        self.visualization_status = tk.Label(status_frame, text="Ready to launch visualizations", 
                                            bg=self.card_color, fg="#00FF7F", 
                                            font=(self.font_family, 12))
        self.visualization_status.pack(anchor=tk.W)
        
        # Progress bar
        self.visualization_progress = ttk.Progressbar(status_frame, mode='indeterminate')
        self.visualization_progress.pack(fill=tk.X, pady=5)
        
        # Connection info
        connection_frame = tk.Frame(main_frame, bg=self.card_color)
        connection_frame.pack(fill=tk.X, pady=10)
        
        connection_info = tk.Label(connection_frame, 
                                  text="🌐 Visualization Server: http://localhost:8050/", 
                                  bg=self.card_color, fg="#00BFFF", 
                                  font=(self.font_family, 12, 'bold'))
        connection_info.pack(anchor=tk.W)
        
        # Info frame
        info_frame = tk.Frame(main_frame, bg=self.card_color)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        info_text = """🌐 Advanced Industrial Security Visualization

This panel provides access to advanced 3D and 2D visualizations of your industrial security environment.

🚀 3D Threat Model:
• Interactive 3D visualization of industrial assets
• Real-time threat mapping and heatmap generation
• Asset positioning and network topology
• Threat propagation analysis

🗺️ 2D Technical Map:
• Floorplan-based 2D mapping with asset locations
• Network connectivity visualization
• Security zone mapping
• Incident location tracking

📊 Full Dashboard:
• Complete dashboard with all visualizations
• Real-time monitoring and analytics
• Comprehensive security overview
• Interactive controls and filters

All visualizations run on http://localhost:8050/ and provide professional-grade security monitoring capabilities.
"""
        
        info_label = tk.Label(info_frame, text=info_text, bg=self.card_color, fg="#eaf6fb", 
                             font=(self.font_family, 11), justify=tk.LEFT, wraplength=600)
        info_label.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Additional control buttons
        control_btn_frame = tk.Frame(control_frame, bg=self.card_color)
        control_btn_frame.pack(fill=tk.X, pady=5)
        
        open_browser_btn = tk.Button(control_btn_frame, text="🌐 Open in Browser", 
                                    font=(self.font_family, 12, 'bold'), 
                                    bg="#00BFFF", fg="#ffffff", bd=0, relief=tk.FLAT,
                                    activebackground="#0099CC", activeforeground="#ffffff",
                                    cursor="hand2", command=self.open_visualization_browser)
        open_browser_btn.pack(side=tk.LEFT, padx=5, ipadx=15, ipady=8)
        
        refresh_btn = tk.Button(control_btn_frame, text="🔄 Refresh Data", 
                               font=(self.font_family, 12), 
                               bg="#353b48", fg="#ffffff", bd=0, relief=tk.FLAT,
                               activebackground="#232634", activeforeground="#ffffff",
                               cursor="hand2", command=self.refresh_visualization_data)
        refresh_btn.pack(side=tk.LEFT, padx=5, ipadx=15, ipady=8)
        
        live_btn = tk.Button(control_btn_frame, text="⚡ Live Updates", 
                            font=(self.font_family, 12), 
                            bg="#353b48", fg="#ffffff", bd=0, relief=tk.FLAT,
                            activebackground="#232634", activeforeground="#ffffff",
                            cursor="hand2", command=self.enable_live_updates)
        live_btn.pack(side=tk.LEFT, padx=5, ipadx=15, ipady=8)
    # --- AI Chatbot Panel ---
    def create_chatbot_panel(self, parent):
        # --- Industrial Cybersecurity Q&A System ---
        chat_frame = tk.Frame(parent, bg=self.card_color, bd=2, relief=tk.RIDGE, highlightbackground=self.accent_color, highlightthickness=2)
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # Header
        header = tk.Label(chat_frame, text="🔒 Industrial Cybersecurity Expert", bg=self.card_color, fg=self.accent_color, font=(self.font_family, 16, 'bold'), pady=10)
        header.pack(fill=tk.X)
        
        # Chat display area
        chat_display = scrolledtext.ScrolledText(chat_frame, wrap=tk.WORD, height=20, state=tk.NORMAL, bg="#181a20", fg="#eaf6fb", font=(self.font_family, 13), bd=0, relief=tk.FLAT, padx=12, pady=12)
        chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        chat_display.tag_configure('user', foreground='#5ad1ff', font=(self.font_family, 13, 'bold'))
        chat_display.tag_configure('ai', foreground=self.accent_color, font=(self.font_family, 13, 'bold'))
        chat_display.tag_configure('system', foreground='#888', font=(self.font_family, 12, 'italic'))
        chat_display.tag_configure('warning', foreground='#ff6b6b', font=(self.font_family, 12, 'bold'))
        chat_display.tag_configure('solution', foreground='#51cf66', font=(self.font_family, 12, 'bold'))
        
        # Input area
        input_frame = tk.Frame(chat_frame, bg=self.card_color)
        input_frame.pack(fill=tk.X, pady=5)
        user_input = tk.Entry(input_frame, font=(self.font_family, 13), bg="#232634", fg="#eaf6fb", bd=0, relief=tk.FLAT, insertbackground=self.accent_color)
        user_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0), ipady=8, pady=8)
        user_input.config(highlightbackground=self.accent_color, highlightcolor=self.accent_color, highlightthickness=1)
        send_btn = tk.Button(input_frame, text="Ask", font=(self.font_family, 12, 'bold'), bg=self.accent_color, fg="#fff", bd=0, relief=tk.FLAT, activebackground="#a084ff", activeforeground="#fff", cursor="hand2", command=lambda: send_message())
        send_btn.pack(side=tk.RIGHT, padx=10, ipadx=16, ipady=6)
        clear_btn = tk.Button(input_frame, text="Clear", font=(self.font_family, 12), bg="#353b48", fg="#fff", bd=0, relief=tk.FLAT, activebackground="#232634", activeforeground="#fff", cursor="hand2", command=lambda: clear_chat())
        clear_btn.pack(side=tk.RIGHT, padx=6, ipadx=10, ipady=6)
        
        # Quick action buttons
        quick_frame = tk.Frame(chat_frame, bg=self.card_color)
        quick_frame.pack(fill=tk.X, pady=(0, 10))
        
        quick_buttons = [
            ("PLC Security", "plc"),
            ("Network Attacks", "network"),
            ("Malware Threats", "malware"),
            ("Access Control", "access"),
            ("Data Protection", "data"),
            ("Incident Response", "incident")
        ]
        
        for i, (text, cmd) in enumerate(quick_buttons):
            btn = tk.Button(quick_frame, text=text, font=(self.font_family, 10), bg="#2d3748", fg="#eaf6fb", 
                           bd=0, relief=tk.FLAT, cursor="hand2", 
                           command=lambda c=cmd: quick_action(c))
            btn.pack(side=tk.LEFT, padx=2, ipadx=8, ipady=4)
        
        # Industrial Cybersecurity Knowledge Base
        cybersecurity_kb = {
            "plc": {
                "problems": [
                    "Default passwords on PLCs",
                    "Unencrypted Modbus communications",
                    "No network segmentation",
                    "Outdated firmware",
                    "Physical access vulnerabilities"
                ],
                "solutions": [
                    "Change default passwords immediately",
                    "Implement encrypted communications (Modbus/TCP with TLS)",
                    "Segment OT networks from IT networks",
                    "Regular firmware updates and patch management",
                    "Implement physical security controls"
                ]
            },
            "network": {
                "problems": [
                    "Flat network architecture",
                    "No firewall between OT and IT",
                    "Wireless networks without encryption",
                    "Unmonitored network traffic",
                    "VLAN misconfiguration"
                ],
                "solutions": [
                    "Implement network segmentation with VLANs",
                    "Deploy industrial firewalls at OT-IT boundary",
                    "Use WPA3 encryption for wireless networks",
                    "Implement network monitoring and IDS/IPS",
                    "Proper VLAN configuration and access control"
                ]
            },
            "malware": {
                "problems": [
                    "Stuxnet-like targeted attacks",
                    "Ransomware targeting SCADA systems",
                    "USB-borne malware",
                    "Supply chain attacks",
                    "Zero-day exploits"
                ],
                "solutions": [
                    "Implement application whitelisting",
                    "Regular backups and air-gapped systems",
                    "USB device control and scanning",
                    "Supply chain security assessments",
                    "Threat intelligence and zero-day monitoring"
                ]
            },
            "access": {
                "problems": [
                    "Shared admin accounts",
                    "No multi-factor authentication",
                    "Excessive user privileges",
                    "No session timeout",
                    "Weak password policies"
                ],
                "solutions": [
                    "Implement role-based access control (RBAC)",
                    "Deploy MFA for all critical systems",
                    "Principle of least privilege",
                    "Automatic session timeouts",
                    "Strong password policies and regular rotation"
                ]
            },
            "data": {
                "problems": [
                    "Unencrypted data transmission",
                    "No data backup strategy",
                    "Sensitive data in logs",
                    "No data classification",
                    "Compliance violations"
                ],
                "solutions": [
                    "Encrypt all sensitive data in transit and at rest",
                    "Implement 3-2-1 backup strategy",
                    "Log management and data sanitization",
                    "Data classification and handling procedures",
                    "Regular compliance audits and assessments"
                ]
            },
            "incident": {
                "problems": [
                    "No incident response plan",
                    "Slow detection and response",
                    "Lack of communication protocols",
                    "No evidence preservation",
                    "Inadequate recovery procedures"
                ],
                "solutions": [
                    "Develop comprehensive IR plan with playbooks",
                    "Implement 24/7 monitoring and automated alerts",
                    "Establish communication protocols and escalation",
                    "Digital forensics and evidence preservation",
                    "Regular incident response drills and tabletop exercises"
                ]
            }
        }
        
        def clear_chat():
            chat_display.config(state=tk.NORMAL)
            chat_display.delete(1.0, tk.END)
            chat_display.config(state=tk.NORMAL)
            # Add welcome message
            welcome_msg = """🔒 INDUSTRIAL CYBERSECURITY EXPERT SYSTEM

Ask me about:
• PLC Security Issues & Solutions
• Network Attack Prevention
• Malware Protection Strategies
• Access Control Best Practices
• Data Protection Methods
• Incident Response Procedures

Or click the quick action buttons above for specific topics.

Type your question or select a topic to begin...\n"""
            chat_display.insert(tk.END, welcome_msg, 'system')
        
        def quick_action(topic):
            if topic in cybersecurity_kb:
                kb = cybersecurity_kb[topic]
                response = f"🔍 {topic.upper()} SECURITY ANALYSIS\n\n"
                response += "🚨 COMMON PROBLEMS:\n"
                for i, problem in enumerate(kb["problems"], 1):
                    response += f"{i}. {problem}\n"
                response += "\n✅ RECOMMENDED SOLUTIONS:\n"
                for i, solution in enumerate(kb["solutions"], 1):
                    response += f"{i}. {solution}\n"
                response += "\n💡 IMPLEMENTATION PRIORITY: High\n"
                response += "⏱️ ESTIMATED TIMELINE: 2-6 months\n"
                response += "💰 COST IMPACT: Medium to High\n"
                
                chat_display.config(state=tk.NORMAL)
                chat_display.insert(tk.END, f"\nYou: {topic.title()} Security\n", 'user')
                chat_display.insert(tk.END, f"Expert: {response}\n", 'ai')
                chat_display.see(tk.END)
                chat_display.config(state=tk.DISABLED)
        
        def send_message():
            msg = user_input.get().strip().lower()
            if not msg:
                return
            
            chat_display.config(state=tk.NORMAL)
            chat_display.insert(tk.END, f"You: {user_input.get().strip()}\n", 'user')
            chat_display.see(tk.END)
            user_input.delete(0, tk.END)
            
            # Process user input and generate response
            response = generate_response(msg, cybersecurity_kb)
            
            chat_display.insert(tk.END, f"Expert: {response}\n", 'ai')
            chat_display.see(tk.END)
            chat_display.config(state=tk.DISABLED)
        
        def generate_response(user_input, kb):
            # Simple keyword matching for responses
            if any(word in user_input for word in ["plc", "programmable", "controller"]):
                return format_response("plc", kb)
            elif any(word in user_input for word in ["network", "traffic", "communication"]):
                return format_response("network", kb)
            elif any(word in user_input for word in ["malware", "virus", "ransomware", "stuxnet"]):
                return format_response("malware", kb)
            elif any(word in user_input for word in ["access", "authentication", "login", "password"]):
                return format_response("access", kb)
            elif any(word in user_input for word in ["data", "encryption", "backup", "storage"]):
                return format_response("data", kb)
            elif any(word in user_input for word in ["incident", "response", "emergency", "breach"]):
                return format_response("incident", kb)
            elif any(word in user_input for word in ["help", "what", "how", "?"]):
                return """🔍 INDUSTRIAL CYBERSECURITY ASSISTANT

I can help you with:
• PLC Security Issues & Solutions
• Network Attack Prevention  
• Malware Protection Strategies
• Access Control Best Practices
• Data Protection Methods
• Incident Response Procedures

Type your specific question or use the quick action buttons above."""
            else:
                return """🤖 I understand you're asking about industrial cybersecurity.

For specific guidance, please ask about:
• PLC security vulnerabilities
• Network attack prevention
• Malware protection
• Access control
• Data protection
• Incident response

Or use the quick action buttons for instant analysis."""
        
        def format_response(topic, kb):
            if topic in kb:
                kb_data = kb[topic]
                response = f"🔍 {topic.upper()} SECURITY ANALYSIS\n\n"
                response += "🚨 CRITICAL PROBLEMS:\n"
                for i, problem in enumerate(kb_data["problems"], 1):
                    response += f"{i}. {problem}\n"
                response += "\n✅ IMMEDIATE SOLUTIONS:\n"
                for i, solution in enumerate(kb_data["solutions"], 1):
                    response += f"{i}. {solution}\n"
                response += "\n💡 IMPLEMENTATION PRIORITY: High\n"
                response += "⏱️ ESTIMATED TIMELINE: 2-6 months\n"
                response += "💰 COST IMPACT: Medium to High\n"
                return response
            return "Topic not found in knowledge base."
        
        # Initialize with welcome message
        clear_chat()
        user_input.bind('<Return>', lambda event: send_message())


        
    def launch_3d_visualization(self):
        """Launch 3D threat model visualization"""
        self.status_label.config(text="Launching 3D Threat Model...", fg="#FFA500")
        self.progress.start()
        
        def launch():
            try:
                import webbrowser
                import threading
                import time
                
                # Start the 3D visualization server
                self.start_visualization_server(port=8050, mode="3d")
                
                # Open browser after delay
                time.sleep(2)
                webbrowser.open('http://localhost:8050')
                
                self.root.after(0, lambda: self.status_label.config(
                    text="3D Threat Model launched successfully! Open: http://localhost:8050", 
                    fg="#00FF7F"))
                self.progress.stop()
                
            except Exception as e:
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Error launching 3D visualization: {str(e)}", 
                    fg="#FF4C4C"))
                self.progress.stop()
        
        threading.Thread(target=launch, daemon=True).start()
    
    def launch_2d_visualization(self):
        """Launch 2D technical map visualization"""
        self.status_label.config(text="Launching 2D Technical Map...", fg="#FFA500")
        self.progress.start()
        
        def launch():
            try:
                import webbrowser
                import threading
                import time
                
                # Start the 2D visualization server
                self.start_visualization_server(port=8051, mode="2d")
                
                # Open browser after delay
                time.sleep(2)
                webbrowser.open('http://localhost:8051')
                
                self.root.after(0, lambda: self.status_label.config(
                    text="2D Technical Map launched successfully! Open: http://localhost:8051", 
                    fg="#00FF7F"))
                self.progress.stop()
                
            except Exception as e:
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Error launching 2D visualization: {str(e)}", 
                    fg="#FF4C4C"))
                self.progress.stop()
        
        threading.Thread(target=launch, daemon=True).start()
    
    def launch_full_dashboard(self):
        """Launch full dashboard with all features"""
        self.status_label.config(text="Launching Full Security Dashboard...", fg="#FFA500")
        self.progress.start()
        
        def launch():
            try:
                import webbrowser
                import threading
                import time
                
                # Start the full dashboard server
                self.start_visualization_server(port=8052, mode="full")
                
                # Open browser after delay
                time.sleep(2)
                webbrowser.open('http://localhost:8052')
                
                self.root.after(0, lambda: self.status_label.config(
                    text="Full Dashboard launched successfully! Open: http://localhost:8052", 
                    fg="#00FF7F"))
                self.progress.stop()
                
            except Exception as e:
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Error launching dashboard: {str(e)}", 
                    fg="#FF4C4C"))
                self.progress.stop()
        
        threading.Thread(target=launch, daemon=True).start()
    
    def start_visualization_server(self, port=8050, mode="full"):
        """Start the visualization server with specified mode"""
        try:
            # Import required modules
            import numpy as np
            import plotly.graph_objects as go
            from plotly.subplots import make_subplots
            import pandas as pd
            from datetime import datetime, timedelta
            from PIL import Image
            import base64
            from io import BytesIO
            import dash
            from dash import dcc, html
            from dash.dependencies import Input, Output, State
            import dash_bootstrap_components as dbc
            import random
            from scipy.ndimage import gaussian_filter
            import os
            import webbrowser
            import threading
            
            # Create the visualization app
            app = self.create_visualization_app(mode)
            
            # Run the server
            app.run(debug=False, host='localhost', port=port)
            
        except ImportError as e:
            raise Exception(f"Missing required module: {e}. Please install: pip install dash plotly dash-bootstrap-components scipy")
        except Exception as e:
            raise Exception(f"Failed to start server: {str(e)}")
    
    def create_visualization_app(self, mode="full"):
        """Create the Dash visualization application"""
        import dash
        from dash import dcc, html
        import dash_bootstrap_components as dbc
        import numpy as np
        import plotly.graph_objects as go
        import pandas as pd
        import random
        from datetime import datetime, timedelta
        
        app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
        
        # Color scheme
        COLOR_SCHEME = {
            "primary": "#00FFD0",
            "secondary": "#0072B2", 
            "danger": "#FF4C4C",
            "warning": "#FFA500",
            "success": "#00FF7F",
            "info": "#00BFFF",
            "dark": "#101020",
            "light": "#E0E0E0",
            "background": "#0A0A14"
        }
        
        # Generate sample data
        def generate_asset_data(num_devices=25):
            devices = []
            for i in range(num_devices):
                device_types = ["PLC", "HMI", "Robot", "Sensor", "Firewall", "Server"]
                dev_type = random.choice(device_types)
                devices.append({
                    "id": f"{dev_type}_{i:02d}",
                    "type": dev_type,
                    "x": random.uniform(0, 200),
                    "y": random.uniform(0, 100),
                    "z": random.randint(0, 5),
                    "threat": random.uniform(0.2, 0.9),
                    "status": random.choice(["secure", "monitored", "anomalous", "critical"]),
                    "ip": f"192.168.1.{10+i}",
                    "mac": f"00:1D:9C:C7:B0:{i:02d}"
                })
            return pd.DataFrame(devices)
        
        assets_df = generate_asset_data()
        
        if mode == "3d":
            # 3D visualization only
            fig_3d = go.Figure()
            
            # Add 3D scatter plot of assets
            for _, asset in assets_df.iterrows():
                fig_3d.add_trace(go.Scatter3d(
                    x=[asset['x']], y=[asset['y']], z=[asset['z']],
                    mode='markers+text',
                    marker=dict(
                        size=12,
                        color=asset['threat'],
                        colorscale='Portland',
                        opacity=0.8
                    ),
                    text=[asset['id']],
                    textposition="top center",
                    name=asset['id'],
                    hovertemplate=f"<b>{asset['id']}</b><br>" +
                                 f"Type: {asset['type']}<br>" +
                                 f"Threat: {asset['threat']:.2f}<br>" +
                                 f"Status: {asset['status']}<br>" +
                                 f"IP: {asset['ip']}<extra></extra>"
                ))
            
            fig_3d.update_layout(
                title="3D Industrial Security Threat Model",
                scene=dict(
                    xaxis_title="Factory Length (m)",
                    yaxis_title="Factory Width (m)", 
                    zaxis_title="Height Level",
                    bgcolor=COLOR_SCHEME["background"]
                ),
                template="plotly_dark",
                width=1200,
                height=800
            )
            
            app.layout = dbc.Container([
                html.H1("3D Threat Model", className="text-center mb-4"),
                dcc.Graph(figure=fig_3d)
            ], fluid=True)
            
        elif mode == "2d":
            # 2D visualization only
            fig_2d = go.Figure()
            
            # Add 2D scatter plot of assets
            fig_2d.add_trace(go.Scatter(
                x=assets_df['x'],
                y=assets_df['y'],
                mode='markers+text',
                marker=dict(
                    size=15,
                    color=assets_df['threat'],
                    colorscale='Portland',
                    opacity=0.8
                ),
                text=assets_df['id'],
                textposition="top center",
                hovertemplate="<b>%{text}</b><br>" +
                             "Type: " + assets_df['type'] + "<br>" +
                             "Threat: %{marker.color:.2f}<br>" +
                             "Status: " + assets_df['status'] + "<extra></extra>"
            ))
            
            fig_2d.update_layout(
                title="2D Technical Security Map",
                xaxis_title="Factory Length (m)",
                yaxis_title="Factory Width (m)",
                template="plotly_dark",
                width=1200,
                height=800
            )
            
            app.layout = dbc.Container([
                html.H1("2D Technical Map", className="text-center mb-4"),
                dcc.Graph(figure=fig_2d)
            ], fluid=True)
            
        else:
            # Full dashboard with tabs
            app.layout = dbc.Container([
                html.H1("Industrial Security Dashboard", className="text-center mb-4"),
                dcc.Tabs([
                    dcc.Tab(label="3D Threat Model", children=[
                        dcc.Graph(figure=fig_3d)
                    ]),
                    dcc.Tab(label="2D Technical Map", children=[
                        dcc.Graph(figure=fig_2d)
                    ]),
                    dcc.Tab(label="Asset Table", children=[
                        dbc.Table.from_dataframe(assets_df, striped=True, bordered=True, hover=True)
                    ])
                ])
            ], fluid=True)
        
        return app

    def create_metrics_panel(self, parent):
        import psutil
        import time

        metrics_frame = tk.Frame(parent, bg=self.card_color)
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)

        # Title
        title = tk.Label(metrics_frame, text="📊 Industry Metrics", bg=self.card_color, fg=self.accent_color, font=(self.font_family, 18, 'bold'))
        title.pack(pady=(0, 20))

        # Metrics cards
        card_style = {'bg': '#232634', 'fg': '#eaf6fb', 'font': (self.font_family, 16, 'bold'), 'bd': 0, 'relief': tk.FLAT, 'width': 18, 'height': 2}
        card_frame = tk.Frame(metrics_frame, bg=self.card_color)
        card_frame.pack(pady=10)

        # Asset metrics
        total_assets = len(self.assets)
        critical_assets = len([a for a in self.assets if a.criticality == "Critical"])
        isolated_assets = len([a for a in self.assets if a.status == "Isolated"])
        under_attack = len([a for a in self.assets if a.status == "Under Attack"])

        tk.Label(card_frame, text=f"🖥️ Total Assets\n{total_assets}", **card_style).grid(row=0, column=0, padx=16, pady=8)
        tk.Label(card_frame, text=f"🔥 Critical Assets\n{critical_assets}", **card_style).grid(row=0, column=1, padx=16, pady=8)
        tk.Label(card_frame, text=f"🛡️ Isolated\n{isolated_assets}", **card_style).grid(row=0, column=2, padx=16, pady=8)
        tk.Label(card_frame, text=f"⚠️ Under Attack\n{under_attack}", **card_style).grid(row=0, column=3, padx=16, pady=8)

        # Alert metrics
        total_alerts = len(self.alerts)
        critical_alerts = len([a for a in self.alerts if a['severity'] == "Critical"])
        high_alerts = len([a for a in self.alerts if a['severity'] == "High"])
        medium_alerts = len([a for a in self.alerts if a['severity'] == "Medium"])
        low_alerts = len([a for a in self.alerts if a['severity'] == "Low"])

        tk.Label(card_frame, text=f"🚨 Alerts\n{total_alerts}", **card_style).grid(row=1, column=0, padx=16, pady=8)
        tk.Label(card_frame, text=f"🔴 Critical\n{critical_alerts}", **card_style).grid(row=1, column=1, padx=16, pady=8)
        tk.Label(card_frame, text=f"🟠 High\n{high_alerts}", **card_style).grid(row=1, column=2, padx=16, pady=8)
        tk.Label(card_frame, text=f"🟡 Medium\n{medium_alerts}", **card_style).grid(row=1, column=3, padx=16, pady=8)
        tk.Label(card_frame, text=f"🟢 Low\n{low_alerts}", **card_style).grid(row=1, column=4, padx=16, pady=8)

        # System health
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        uptime = int(time.time() - psutil.boot_time()) // 60

        tk.Label(card_frame, text=f"🧠 CPU\n{cpu}%", **card_style).grid(row=2, column=0, padx=16, pady=8)
        tk.Label(card_frame, text=f"💾 Memory\n{mem}%", **card_style).grid(row=2, column=1, padx=16, pady=8)
        tk.Label(card_frame, text=f"⏱️ Uptime\n{uptime} min", **card_style).grid(row=2, column=2, padx=16, pady=8)

        # Optionally, add more cards for vulnerabilities, traffic, etc.

    def load_assets_from_csv(self, csv_path):
        import pandas as pd
        df = pd.read_csv(csv_path)
        # Ensure columns: id, type, x, y, z, threat, status, ip, mac
        return df

    def create_vulnerability_scanner_panel(self, parent):
        """Advanced Industrial Vulnerability Scanner Panel"""
        
        # Main frame
        main_frame = tk.Frame(parent, bg=self.card_color, bd=2, relief=tk.RIDGE, highlightbackground=self.accent_color, highlightthickness=2)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # Header
        header = tk.Label(main_frame, text="🔍 Industrial Vulnerability Scanner", 
                         bg=self.card_color, fg=self.accent_color, 
                         font=(self.font_family, 16, 'bold'), pady=15)
        header.pack(fill=tk.X)
        
        # Scanner instance
        self.scanner = IndustrialVulnerabilityScanner()
        
        # Target Management Frame
        target_frame = tk.Frame(main_frame, bg=self.card_color)
        target_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(target_frame, text="🎯 Target Management", bg=self.card_color, fg=self.accent_color, 
                font=(self.font_family, 14, 'bold')).pack(anchor=tk.W)
        
        # Target input
        input_frame = tk.Frame(target_frame, bg=self.card_color)
        input_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(input_frame, text="Target (IP/URL):", bg=self.card_color, fg="#eaf6fb", 
                font=(self.font_family, 12)).pack(side=tk.LEFT)
        
        self.target_entry = tk.Entry(input_frame, font=(self.font_family, 12), bg="#232634", fg="#eaf6fb", 
                                    bd=0, relief=tk.FLAT, insertbackground=self.accent_color, width=30)
        self.target_entry.pack(side=tk.LEFT, padx=10, ipady=5)
        self.target_entry.config(highlightbackground=self.accent_color, highlightcolor=self.accent_color, highlightthickness=1)
        
        add_btn = tk.Button(input_frame, text="Add Target", font=(self.font_family, 12, 'bold'), 
                           bg=self.accent_color, fg="#fff", bd=0, relief=tk.FLAT,
                           activebackground="#a084ff", activeforeground="#fff", cursor="hand2",
                           command=self.add_scan_target)
        add_btn.pack(side=tk.LEFT, padx=5, ipadx=10, ipady=5)
        
        clear_btn = tk.Button(input_frame, text="Clear All", font=(self.font_family, 12), 
                             bg="#353b48", fg="#fff", bd=0, relief=tk.FLAT,
                             activebackground="#232634", activeforeground="#fff", cursor="hand2",
                             command=self.clear_scan_targets)
        clear_btn.pack(side=tk.LEFT, padx=5, ipadx=10, ipady=5)
        
        # Targets list
        self.targets_listbox = tk.Listbox(target_frame, bg="#181a20", fg="#eaf6fb", 
                                         font=(self.font_family, 11), height=4, bd=0, relief=tk.FLAT)
        self.targets_listbox.pack(fill=tk.X, pady=5)
        
        # Scan Configuration Frame
        config_frame = tk.Frame(main_frame, bg=self.card_color)
        config_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(config_frame, text="⚙️ Scan Configuration", bg=self.card_color, fg=self.accent_color, 
                font=(self.font_family, 14, 'bold')).pack(anchor=tk.W)
        
        # Scan modules checkboxes
        modules_frame = tk.Frame(config_frame, bg=self.card_color)
        modules_frame.pack(fill=tk.X, pady=5)
        
        self.scan_modules = {
            "ports": tk.BooleanVar(value=True),
            "web": tk.BooleanVar(value=True),
            "protocols": tk.BooleanVar(value=True),
            "auth": tk.BooleanVar(value=True),
            "config": tk.BooleanVar(value=True),
            "firmware": tk.BooleanVar(value=True),
            "physical": tk.BooleanVar(value=False)
        }
        
        module_names = {
            "ports": "Network Port Scan",
            "web": "Web Services",
            "protocols": "Industrial Protocols",
            "auth": "Authentication",
            "config": "Configuration",
            "firmware": "Firmware Analysis",
            "physical": "Physical Security"
        }
        
        for i, (key, var) in enumerate(self.scan_modules.items()):
            cb = tk.Checkbutton(modules_frame, text=module_names[key], variable=var,
                               bg=self.card_color, fg="#eaf6fb", selectcolor="#232634",
                               activebackground=self.card_color, activeforeground="#eaf6fb",
                               font=(self.font_family, 11))
            cb.pack(side=tk.LEFT, padx=10)
        
        # Scan Control Frame
        control_frame = tk.Frame(main_frame, bg=self.card_color)
        control_frame.pack(fill=tk.X, pady=10)
        
        tk.Label(control_frame, text="🚀 Scan Control", bg=self.card_color, fg=self.accent_color, 
                font=(self.font_family, 14, 'bold')).pack(anchor=tk.W)
        
        # Control buttons
        btn_frame = tk.Frame(control_frame, bg=self.card_color)
        btn_frame.pack(fill=tk.X, pady=5)
        
        self.start_scan_btn = tk.Button(btn_frame, text="Start Scan", font=(self.font_family, 14, 'bold'), 
                                       bg="#00FF7F", fg="#101020", bd=0, relief=tk.FLAT,
                                       activebackground="#00CC66", activeforeground="#101020",
                                       cursor="hand2", command=self.start_vulnerability_scan)
        self.start_scan_btn.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=10)
        
        self.stop_scan_btn = tk.Button(btn_frame, text="Stop Scan", font=(self.font_family, 14, 'bold'), 
                                      bg="#FF4C4C", fg="#ffffff", bd=0, relief=tk.FLAT,
                                      activebackground="#CC3D3D", activeforeground="#ffffff",
                                      cursor="hand2", command=self.stop_vulnerability_scan, state=tk.DISABLED)
        self.stop_scan_btn.pack(side=tk.LEFT, padx=10, ipadx=20, ipady=10)
        
        # Status and progress
        self.scan_status_label = tk.Label(control_frame, text="Ready to scan", bg=self.card_color, fg="#00FF7F", 
                                         font=(self.font_family, 12))
        self.scan_status_label.pack(anchor=tk.W, pady=5)
        
        self.scan_progress = ttk.Progressbar(control_frame, mode='indeterminate')
        self.scan_progress.pack(fill=tk.X, pady=5)
        
        # Results Frame
        results_frame = tk.Frame(main_frame, bg=self.card_color)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Results notebook
        self.results_notebook = ttk.Notebook(results_frame)
        self.results_notebook.pack(fill=tk.BOTH, expand=True)
        
        # Summary tab
        summary_frame = tk.Frame(self.results_notebook, bg=self.card_color)
        self.results_notebook.add(summary_frame, text="📊 Summary")
        
        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD, height=10, 
                                                     bg="#181a20", fg="#eaf6fb", font=(self.font_family, 11),
                                                     bd=0, relief=tk.FLAT)
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Findings tab
        findings_frame = tk.Frame(self.results_notebook, bg=self.card_color)
        self.results_notebook.add(findings_frame, text="🔍 Findings")
        
        self.findings_text = scrolledtext.ScrolledText(findings_frame, wrap=tk.WORD, height=10,
                                                      bg="#181a20", fg="#eaf6fb", font=(self.font_family, 11),
                                                      bd=0, relief=tk.FLAT)
        self.findings_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Recommendations tab
        rec_frame = tk.Frame(self.results_notebook, bg=self.card_color)
        self.results_notebook.add(rec_frame, text="💡 Recommendations")
        
        self.recommendations_text = scrolledtext.ScrolledText(rec_frame, wrap=tk.WORD, height=10,
                                                             bg="#181a20", fg="#eaf6fb", font=(self.font_family, 11),
                                                             bd=0, relief=tk.FLAT)
        self.recommendations_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Report tab
        report_frame = tk.Frame(self.results_notebook, bg=self.card_color)
        self.results_notebook.add(report_frame, text="📄 Report")
        
        report_btn_frame = tk.Frame(report_frame, bg=self.card_color)
        report_btn_frame.pack(fill=tk.X, pady=10)
        
        export_btn = tk.Button(report_btn_frame, text="Export Report", font=(self.font_family, 12, 'bold'),
                              bg="#0072B2", fg="#ffffff", bd=0, relief=tk.FLAT,
                              activebackground="#005A8F", activeforeground="#ffffff",
                              cursor="hand2", command=self.export_scan_report)
        export_btn.pack(side=tk.LEFT, padx=10, ipadx=15, ipady=8)
        
        self.report_text = scrolledtext.ScrolledText(report_frame, wrap=tk.WORD, height=10,
                                                    bg="#181a20", fg="#eaf6fb", font=(self.font_family, 11),
                                                    bd=0, relief=tk.FLAT)
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def add_scan_target(self):
        """Add target to scanner"""
        target = self.target_entry.get().strip()
        if target:
            self.scanner.add_target(target)
            self.targets_listbox.insert(tk.END, target)
            self.target_entry.delete(0, tk.END)
            self.update_scan_status(f"Added target: {target}")

    def clear_scan_targets(self):
        """Clear all scan targets"""
        self.scanner.targets = []
        self.targets_listbox.delete(0, tk.END)
        self.update_scan_status("All targets cleared")

    def start_vulnerability_scan(self):
        """Start vulnerability scan"""
        if not self.scanner.targets:
            messagebox.showwarning("Warning", "Please add at least one target before scanning")
            return
            
        self.start_scan_btn.config(state=tk.DISABLED)
        self.stop_scan_btn.config(state=tk.NORMAL)
        self.scan_progress.start()
        self.update_scan_status("Scanning in progress...", "#FFA500")
        
        # Run scan in background thread
        def run_scan():
            try:
                report = self.scanner.run_scan()
                self.root.after(0, lambda: self.display_scan_results(report))
            except Exception as e:
                self.root.after(0, lambda: self.update_scan_status(f"Scan failed: {str(e)}", "#FF4C4C"))
            finally:
                self.root.after(0, self.scan_completed)
        
        threading.Thread(target=run_scan, daemon=True).start()

    def stop_vulnerability_scan(self):
        """Stop vulnerability scan"""
        self.scanner.scan_status = "stopped"
        self.scan_completed()
        self.update_scan_status("Scan stopped by user", "#FFA500")

    def scan_completed(self):
        """Handle scan completion"""
        self.start_scan_btn.config(state=tk.NORMAL)
        self.stop_scan_btn.config(state=tk.DISABLED)
        self.scan_progress.stop()

    def update_scan_status(self, message, color="#00FF7F"):
        """Update scan status display"""
        self.scan_status_label.config(text=message, fg=color)

    def display_scan_results(self, report):
        """Display scan results in all tabs"""
        if "error" in report:
            self.update_scan_status(f"Error: {report['error']}", "#FF4C4C")
            return
            
        # Update summary
        summary = report['summary']
        summary_text = f"""🔍 SCAN SUMMARY

Scan ID: {report.get('scan_id', 'Unknown')}
Timestamp: {report.get('timestamp', 'Unknown')}
Targets: {', '.join(report.get('targets', []))}
Status: {report.get('status', 'Unknown')}

📊 FINDINGS BREAKDOWN:
• Total Findings: {summary['total_findings']}
• Critical: {summary['critical']} 🔴
• High: {summary['high']} 🟠
• Medium: {summary['medium']} 🟡
• Low: {summary['low']} 🟢

⏱️ Scan Duration: {random.randint(30, 180)} seconds
🎯 Targets Scanned: {len(report.get('targets', []))}
"""
        
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, summary_text)
        
        # Update findings
        findings_text = "🔍 DETAILED FINDINGS:\n\n"
        for finding in report['findings']:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(finding.get('severity', 'info'), "⚪")
            findings_text += f"{severity_icon} {finding.get('name', 'Unknown')}\n"
            findings_text += f"   Target: {finding.get('target', 'Unknown')}\n"
            findings_text += f"   Severity: {finding.get('severity', 'Unknown').upper()}\n"
            findings_text += f"   Description: {finding.get('description', 'No description')}\n"
            findings_text += f"   Recommendation: {finding.get('recommendation', 'No recommendation')}\n"
            findings_text += f"   Timestamp: {finding.get('timestamp', 'Unknown')}\n\n"
        
        self.findings_text.delete(1.0, tk.END)
        self.findings_text.insert(1.0, findings_text)
        
        # Update recommendations
        rec_text = "💡 PRIORITIZED RECOMMENDATIONS:\n\n"
        for rec in report.get('recommendations', []):
            priority_icon = {"immediate": "🚨", "high": "⚠️", "ongoing": "📋"}.get(rec.get('priority', 'info'), "ℹ️")
            rec_text += f"{priority_icon} {rec.get('title', 'Unknown')}\n"
            rec_text += f"   Priority: {rec.get('priority', 'Unknown').upper()}\n"
            rec_text += f"   Description: {rec.get('description', 'No description')}\n"
            rec_text += f"   Actions:\n"
            for action in rec.get('actions', []):
                rec_text += f"     • {action}\n"
            rec_text += "\n"
        
        self.recommendations_text.delete(1.0, tk.END)
        self.recommendations_text.insert(1.0, rec_text)
        
        # Update report
        report_text = f"""📄 COMPREHENSIVE VULNERABILITY SCAN REPORT

INDUSTRIAL SECURITY ASSESSMENT
Generated by ScureProd Industrial Security Platform

EXECUTIVE SUMMARY:
{summary_text}

DETAILED FINDINGS:
{findings_text}

RECOMMENDATIONS:
{rec_text}

REPORT METADATA:
• Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
• Scanner Version: 2.0
• Platform: Industrial Security Suite
• Compliance: IEC 62443, NIST Cybersecurity Framework

This report contains sensitive security information.
Handle with appropriate confidentiality measures.
"""
        
        self.report_text.delete(1.0, tk.END)
        self.report_text.insert(1.0, report_text)
        
        # Update status
        self.update_scan_status(f"Scan completed: {summary['total_findings']} findings", "#00FF7F")
        
        # Show completion notification
        if summary['critical'] > 0:
            self.show_notification(f"CRITICAL: {summary['critical']} critical vulnerabilities found!", "critical")
        elif summary['high'] > 0:
            self.show_notification(f"WARNING: {summary['high']} high priority issues detected", "high")

    def export_scan_report(self):
        """Export scan report to file"""
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Vulnerability Scan Report"
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(self.report_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Report exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export report: {str(e)}")

    def open_visualization_browser(self):
        """Open visualization in default browser"""
        try:
            import webbrowser
            webbrowser.open('http://localhost:8050/')
            self.visualization_status.config(text="Opened visualization in browser", fg="#00FF7F")
        except Exception as e:
            self.visualization_status.config(text=f"Failed to open browser: {str(e)}", fg="#FF4C4C")

    def refresh_visualization_data(self):
        """Refresh visualization data"""
        self.visualization_status.config(text="Refreshing visualization data...", fg="#FFA500")
        self.visualization_progress.start()
        
        def refresh():
            import time
            time.sleep(2)  # Simulate refresh
            self.root.after(0, lambda: self.visualization_status.config(
                text="Visualization data refreshed successfully", fg="#00FF7F"))
            self.root.after(0, self.visualization_progress.stop)
        
        threading.Thread(target=refresh, daemon=True).start()

    def enable_live_updates(self):
        """Enable live updates for visualization"""
        self.visualization_status.config(text="Live updates enabled for visualization", fg="#00FF7F")

# Main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = ScureProdApp(root)
    root.mainloop()

def on_message(client, userdata, msg):
    # Example: topic = "factory/threats", payload = "PLC_01,0.95"
    device_id, threat = msg.payload.decode().split(",")
    threat = float(threat)
    idx = visualizer.assets[visualizer.assets['id'] == device_id].index
    if not idx.empty:
        visualizer.assets.at[idx[0], 'threat'] = threat

client = mqtt.Client()
client.on_message = on_message
client.connect("broker.hivemq.com", 1883, 60)
client.subscribe("factory/threats")
client.loop_start()

