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
import openai  # Make sure to install: pip install openai
import scapy.all as scapy
import trimesh
import paho.mqtt.client as mqtt
import os
import requests
from io import BytesIO

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
        self.chat_history = []
        
        # Initialize OpenAI API (you'll need to set your API key)
        self.openai_api_key = None
        self.openai_model = "gpt-3.5-turbo"  # Default model
        
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
        
        # Heatmap 3D tab
        heatmap_tab = ttk.Frame(notebook)
        self.create_heatmap3d_panel(heatmap_tab)
        notebook.add(heatmap_tab, text="Heatmap 3D")
        
        # AI Chatbot tab
        chatbot_tab = ttk.Frame(notebook)
        self.create_chatbot_panel(chatbot_tab)
        notebook.add(chatbot_tab, text="AI Chatbot")
        
        # Metrics tab
        metrics_tab = ttk.Frame(notebook)
        self.create_metrics_panel(metrics_tab)
        notebook.add(metrics_tab, text="Industry Metrics")
    
    def create_chatbot_panel(self, parent):
        """Create the AI Chatbot panel with conversation interface"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Chat display area
        chat_frame = ttk.Frame(main_frame, style='Card.TFrame')
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=20,
            bg=self.card_color, 
            fg=self.text_color,
            font=(self.font_family, 10)
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chat_display.config(state=tk.DISABLED)
        
        # Input area
        input_frame = ttk.Frame(main_frame, style='Card.TFrame')
        input_frame.pack(fill=tk.X, pady=5)
        
        # API key entry
        api_frame = ttk.Frame(input_frame)
        api_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(api_frame, text="OpenAI API Key:").pack(side=tk.LEFT)
        self.api_key_entry = ttk.Entry(api_frame, width=40, show="*")
        self.api_key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(api_frame, text="Set Key", command=self.set_api_key).pack(side=tk.LEFT)
        
        # Model selection
        model_frame = ttk.Frame(input_frame)
        model_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(model_frame, text="Model:").pack(side=tk.LEFT)
        self.model_var = tk.StringVar(value="gpt-3.5-turbo")
        model_options = ["gpt-3.5-turbo", "gpt-4"]  # Add more models as needed
        self.model_menu = ttk.Combobox(model_frame, textvariable=self.model_var, values=model_options)
        self.model_menu.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # User input
        input_area = ttk.Frame(input_frame)
        input_area.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.user_input = tk.Text(input_area, height=4, bg=self.card_color, fg=self.text_color, 
                                font=(self.font_family, 10), wrap=tk.WORD)
        self.user_input.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        send_button = ttk.Button(input_area, text="Send", command=self.send_chat_message)
        send_button.pack(side=tk.RIGHT, fill=tk.Y, padx=5)
        
        # Add welcome message
        self.add_chat_message("system", "Welcome to ScureProd AI Assistant. How can I help you with industrial security today?")
    
    def set_api_key(self):
        """Set the OpenAI API key"""
        api_key = self.api_key_entry.get()
        if api_key:
            self.openai_api_key = api_key
            self.add_chat_message("system", "API key set successfully.")
        else:
            self.add_chat_message("system", "Please enter a valid API key.")
    
    def send_chat_message(self):
        """Send user message to chatbot and get response"""
        user_message = self.user_input.get("1.0", tk.END).strip()
        if not user_message:
            return
            
        # Add user message to chat
        self.add_chat_message("user", user_message)
        self.user_input.delete("1.0", tk.END)
        
        # Get AI response
        threading.Thread(target=self.get_ai_response, args=(user_message,)).start()
    
    def get_ai_response(self, user_message):
        """Get response from OpenAI API"""
        if not self.openai_api_key:
            self.add_chat_message("system", "Error: Please set your OpenAI API key first.")
            return
            
        try:
            # Prepare the chat history
            messages = [
                {"role": "system", "content": "You are an industrial cybersecurity expert assistant for ScureProd. Provide concise, technical answers focused on industrial control systems, OT security, and incident response."}
            ]
            
            # Add previous chat history (last 5 messages)
            for msg in self.chat_history[-5:]:
                messages.append({"role": msg["role"], "content": msg["content"]})
            
            # Add the new user message
            messages.append({"role": "user", "content": user_message})
            
            # Call OpenAI API
            import openai
            openai.api_key = self.openai_api_key
            
            response = openai.ChatCompletion.create(
                model=self.model_var.get(),
                messages=messages,
                temperature=0.7,
                max_tokens=500
            )
            
            # Add AI response to chat
            ai_response = response.choices[0].message.content
            self.add_chat_message("assistant", ai_response)
            
        except Exception as e:
            self.add_chat_message("system", f"Error getting AI response: {str(e)}")
    
    def add_chat_message(self, role, content):
        """Add a message to the chat display"""
        self.chat_display.config(state=tk.NORMAL)
        
        # Configure tags for different message types
        self.chat_display.tag_config("user", foreground=self.accent_color)
        self.chat_display.tag_config("assistant", foreground=self.safe_color)
        self.chat_display.tag_config("system", foreground=self.info_color)
        
        # Add the message with appropriate tag
        if role == "user":
            prefix = "You: "
            tag = "user"
        elif role == "assistant":
            prefix = "AI: "
            tag = "assistant"
        else:
            prefix = "System: "
            tag = "system"
        
        self.chat_display.insert(tk.END, f"{prefix}{content}\n\n", tag)
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.see(tk.END)
        
        # Add to chat history
        self.chat_history.append({"role": role, "content": content})
    
    # [Previous methods remain unchanged...]
    
    def create_heatmap3d_panel(self, parent):
        """Create the 3D heatmap visualization panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create figure
        fig = plt.Figure(figsize=(10, 8), dpi=100)
        ax = fig.add_subplot(111, projection='3d')
        
        # Generate some sample data (replace with real asset data)
        x = np.random.rand(20) * 100
        y = np.random.rand(20) * 100
        z = np.random.rand(20) * 10
        values = np.random.rand(20) * 100  # Risk values
        
        # Create scatter plot with color mapping
        sc = ax.scatter(x, y, z, c=values, cmap='viridis', s=100)
        
        # Add colorbar
        fig.colorbar(sc, ax=ax, label='Risk Level')
        
        # Labels and title
        ax.set_xlabel('X Coordinate')
        ax.set_ylabel('Y Coordinate')
        ax.set_zlabel('Z Coordinate')
        ax.set_title('3D Asset Risk Heatmap')
        
        # Create canvas
        canvas = FigureCanvasTkAgg(fig, master=main_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Add toolbar
        toolbar = NavigationToolbar2Tk(canvas, main_frame)
        toolbar.update()
        canvas._tkcanvas.pack(fill=tk.BOTH, expand=True)
        
        # Function to update heatmap
        def update_heatmap():
            # Simulate updating data (replace with real updates)
            new_values = np.random.rand(20) * 100
            sc.set_array(new_values)
            fig.canvas.draw_idle()
            main_frame.after(5000, update_heatmap)  # Update every 5 seconds
        
        # Start periodic updates
        update_heatmap()
    
    def create_metrics_panel(self, parent):
        """Create the metrics dashboard panel"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create cards for metrics
        cards_frame = ttk.Frame(main_frame)
        cards_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Asset metrics card
        asset_card = ttk.Frame(cards_frame, style='Card.TFrame', padding=10)
        asset_card.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(asset_card, text="Asset Metrics", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        self.asset_count_label = ttk.Label(asset_card, text="Total: 0", font=('Arial', 10))
        self.asset_count_label.pack(anchor=tk.W)
        
        self.critical_assets_label = ttk.Label(asset_card, text="Critical: 0", font=('Arial', 10))
        self.critical_assets_label.pack(anchor=tk.W)
        
        # Alert metrics card
        alert_card = ttk.Frame(cards_frame, style='Card.TFrame', padding=10)
        alert_card.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(alert_card, text="Alert Metrics", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        self.alert_count_label = ttk.Label(alert_card, text="Total: 0", font=('Arial', 10))
        self.alert_count_label.pack(anchor=tk.W)
        
        self.critical_alerts_label = ttk.Label(alert_card, text="Critical: 0", font=('Arial', 10))
        self.critical_alerts_label.pack(anchor=tk.W)
        
        # Protocol metrics card
        protocol_card = ttk.Frame(cards_frame, style='Card.TFrame', padding=10)
        protocol_card.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(protocol_card, text="Protocol Metrics", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        self.protocol_count_label = ttk.Label(protocol_card, text="Active: 0", font=('Arial', 10))
        self.protocol_count_label.pack(anchor=tk.W)
        
        self.anomalous_protocols_label = ttk.Label(protocol_card, text="Anomalous: 0", font=('Arial', 10))
        self.anomalous_protocols_label.pack(anchor=tk.W)
        
        # System metrics card
        system_card = ttk.Frame(cards_frame, style='Card.TFrame', padding=10)
        system_card.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        
        ttk.Label(system_card, text="System Metrics", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        self.cpu_usage_label = ttk.Label(system_card, text="CPU: 0%", font=('Arial', 10))
        self.cpu_usage_label.pack(anchor=tk.W)
        
        self.memory_usage_label = ttk.Label(system_card, text="Memory: 0%", font=('Arial', 10))
        self.memory_usage_label.pack(anchor=tk.W)
        
        # Configure grid weights
        cards_frame.columnconfigure(0, weight=1)
        cards_frame.columnconfigure(1, weight=1)
        cards_frame.rowconfigure(0, weight=1)
        cards_frame.rowconfigure(1, weight=1)
        
        # Start updating metrics
        self.update_metrics()
    
    def update_metrics(self):
        """Update the metrics display"""
        # Asset metrics
        total_assets = len(self.assets)
        critical_assets = len([a for a in self.assets if a.criticality == "Critical"])
        self.asset_count_label.config(text=f"Total: {total_assets}")
        self.critical_assets_label.config(text=f"Critical: {critical_assets}")
        
        # Alert metrics
        total_alerts = len(self.alerts)
        critical_alerts = len([a for a in self.alerts if a['severity'] == "Critical"])
        self.alert_count_label.config(text=f"Total: {total_alerts}")
        self.critical_alerts_label.config(text=f"Critical: {critical_alerts}")
        
        # Protocol metrics
        active_protocols = len([p for p, t in self.protocol_traffic.items() if t])
        anomalous_protocols = len([p for p, t in self.protocol_traffic.items() 
                                 if t and max(list(t)[-10:]) > 2 * (sum(list(t)[-10:])/len(list(t)[-10:]))])
        self.protocol_count_label.config(text=f"Active: {active_protocols}")
        self.anomalous_protocols_label.config(text=f"Anomalous: {anomalous_protocols}")
        
        # System metrics
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        self.cpu_usage_label.config(text=f"CPU: {cpu:.1f}%")
        self.memory_usage_label.config(text=f"Memory: {mem:.1f}%")
        
        # Schedule next update
        self.root.after(2000, self.update_metrics)
    
    # [Rest of the methods remain unchanged...]

# Main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = ScureProdApp(root)
    root.mainloop()