
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
import ll  # Import VulnScanner from ll.py

# =============================================
# 1. SYSTEM CONFIGURATION AND CONSTANTS
# =============================================

# Factory dimensions and parameters
FACTORY_LENGTH = 200  # meters
FACTORY_WIDTH = 100   # meters
HEIGHT_LEVELS = 6     # floors/industrial racks
GRID_RESOLUTION = 80  # points along length axis

# Visualization parameters
THREAT_OPACITY = 0.15
HEATMAP_OPACITY = 0.6
DEVICE_MARKER_SIZE = 16
NETWORK_LINE_WIDTH = 5
ATTACK_LINE_WIDTH = 4

# Color schemes
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

STATUS_COLORS = {
    "secure": "#2ECC40",
    "monitored": "#3498DB",
    "anomalous": "#FF851B",
    "critical": "#FF4136",
    "compromised": "#B10DC9",
    "offline": "#AAAAAA",
    "moving": "#7FDBFF"
}

# Device type configurations
DEVICE_TYPES = {
    "PLC": {"symbol": "diamond", "color": COLOR_SCHEME["primary"]},
    "HMI": {"symbol": "square", "color": COLOR_SCHEME["warning"]},
    "Robot": {"symbol": "circle", "color": COLOR_SCHEME["danger"]},
    "Sensor": {"symbol": "cross", "color": "#FFD700"},
    "Firewall": {"symbol": "x", "color": COLOR_SCHEME["info"]},
    "Server": {"symbol": "diamond-open", "color": "#B266FF"},
    "Vehicle": {"symbol": "circle-open", "color": COLOR_SCHEME["success"]},
    "UAV": {"symbol": "square-open", "color": "#CCCCCC"},
    "Other": {"symbol": "circle", "color": "#888888"}
}

# 2D symbol mapping
SYMBOLS_2D = {
    "PLC": "square",
    "HMI": "diamond",
    "Robot": "circle",
    "Server": "cross",
    "Firewall": "x",
    "Vehicle": "star",
    "UAV": "pentagon"
}

# =============================================
# 2. DATA GENERATION AND SIMULATION
# =============================================

class IndustrialDataGenerator:
    def __init__(self, factory_dimensions=(FACTORY_LENGTH, FACTORY_WIDTH, HEIGHT_LEVELS)):
        self.length, self.width, self.height = factory_dimensions
        self.x = np.linspace(0, self.length, GRID_RESOLUTION)
        self.y = np.linspace(0, self.width, int(GRID_RESOLUTION * (self.width/self.length)))
        self.z = np.linspace(0, self.height, HEIGHT_LEVELS)
        self.X, self.Y, self.Z = np.meshgrid(self.x, self.y, self.z)
        
    def generate_threat_surface(self, production_lines=None, network_hotspots=None):
        """Generate 3D threat surface with configurable hotspots"""
        base_threat = np.zeros_like(self.X)
        
        # Default production lines if none provided
        if production_lines is None:
            production_lines = [
                {"x": 30, "y": 20, "radius": 15, "threat": 0.8},  # Automotive assembly
                {"x": 120, "y": 60, "radius": 20, "threat": 0.7},  # Packaging robots
                {"x": 180, "y": 30, "radius": 12, "threat": 0.9}   # High-precision CNC
            ]
        
        # Default network hotspots if none provided
        if network_hotspots is None:
            network_hotspots = [
                (50, 80, 0.6),  # OT-DMZ gateway
                (150, 20, 0.7),  # SCADA server room
                (90, 40, 0.5)    # Wireless AP cluster
            ]
        
        # Add production line vulnerabilities
        for line in production_lines:
            dist = np.sqrt((self.X-line["x"])**2 + (self.Y-line["y"])**2)
            base_threat += line["threat"] * np.exp(-dist**2/(2*line["radius"]**2))
        
        # Add network infrastructure risks
        for xc, yc, threat in network_hotspots:
            base_threat += threat * np.exp(-((self.X-xc)**2 + (self.Y-yc)**2)/300)
        
        # Height-based vulnerabilities (ground floor most exposed)
        base_threat *= (1 + 0.3*np.cos(self.Z*0.5))
        
        # Add random anomalies (emerging threats)
        base_threat += 0.15 * np.random.weibull(0.8, size=self.X.shape)
        
        # Apply Gaussian smoothing for more realistic threat spread
        base_threat = gaussian_filter(base_threat, sigma=1)
        
        # Normalize to 0-1 range
        return (base_threat - base_threat.min()) / (base_threat.max() - base_threat.min())
    
    def generate_asset_data(self, num_devices=20):
        """Generate realistic industrial asset data"""
        devices = []
        
        # Critical OT Devices
        devices.extend([
            {"id": f"PLC_{i:02d}", "type": "Siemens S7-1500", 
             "x": random.uniform(20, 180), "y": random.uniform(15, 85), "z": random.randint(0, 2),
             "threat": random.uniform(0.7, 0.9), "status": random.choice(["secure", "monitored", "anomalous", "critical"]),
             "ip": f"192.168.1.{10+i}", "mac": f"00:1D:9C:C7:B0:{i:02d}"}
            for i in range(5)
        ])
        
        # HMIs
        devices.extend([
            {"id": f"HMI_{i:02d}", "type": "Allen-Bradley PanelView", 
             "x": random.uniform(20, 180), "y": random.uniform(15, 85), "z": random.randint(0, 2),
             "threat": random.uniform(0.6, 0.8), "status": random.choice(["secure", "monitored", "anomalous"]),
             "ip": f"192.168.2.{10+i}", "mac": f"00:1D:9C:C7:B1:{i:02d}"}
            for i in range(3)
        ])
        
        # Network Infrastructure
        devices.extend([
            {"id": "SCADA_MAIN", "type": "ICS Server", 
             "x": 150, "y": 20, "z": 3,
             "threat": 0.7, "status": "monitored",
             "ip": "192.168.1.100", "mac": "00:1D:9C:C7:B0:FF"},
            
            {"id": "FW_OT", "type": "Industrial Firewall", 
             "x": 50, "y": 80, "z": 2,
             "threat": 0.55, "status": "secure",
             "ip": "192.168.1.1", "mac": "00:1D:9C:C7:B0:FE"}
        ])
        
        # IIoT Devices
        devices.extend([
            {"id": f"DRONE_{i:02d}", "type": "Inspection UAV", 
             "x": random.uniform(0, self.length), "y": random.uniform(0, self.width), "z": random.randint(3, 5),
             "threat": random.uniform(0.3, 0.5), "status": random.choice(["offline", "moving"]),
             "ip": f"192.168.3.{10+i}", "mac": f"00:1D:9C:C7:B2:{i:02d}"}
            for i in range(2)
        ])
        
        # Fill remaining with random devices
        remaining = num_devices - len(devices)
        device_types = ["Robot", "Sensor", "Vehicle", "Other"]
        for i in range(remaining):
            dev_type = random.choice(device_types)
            devices.append({
                "id": f"{dev_type.upper()}_{i:02d}",
                "type": f"{dev_type} Device",
                "x": random.uniform(0, self.length),
                "y": random.uniform(0, self.width),
                "z": random.randint(0, self.height-1),
                "threat": random.uniform(0.2, 0.8),
                "status": random.choice(list(STATUS_COLORS.keys())),
                "ip": f"192.168.{random.randint(1,4)}.{random.randint(10, 250)}",
                "mac": f"00:1D:9C:C7:{random.randint(0x10, 0xFF):02X}:{random.randint(0x10, 0xFF):02X}"
            })
        
        return pd.DataFrame(devices)
    
    def generate_network_links(self, assets, connection_prob=0.3):
        """Generate realistic network connections between devices"""
        links = []
        asset_ids = assets['id'].tolist()
        
        # Always connect PLCs to HMIs and SCADA
        plcs = [id for id in asset_ids if "PLC" in id]
        hmis = [id for id in asset_ids if "HMI" in id]
        scada = [id for id in asset_ids if "SCADA" in id]
        
        for plc in plcs:
            # Connect PLC to HMI
            for hmi in hmis:
                if random.random() < 0.8:  # High probability of connection
                    links.append((plc, hmi))
            
            # Connect PLC to SCADA
            for sc in scada:
                links.append((plc, sc))
        
        # Connect SCADA to Firewall
        firewalls = [id for id in asset_ids if "FW" in id]
        for sc in scada:
            for fw in firewalls:
                links.append((sc, fw))
        
        # Random connections between other devices
        for i, src in enumerate(asset_ids):
            for j, dst in enumerate(asset_ids[i+1:]):
                if random.random() < connection_prob:
                    links.append((src, dst))
        
        return list(set(links))  # Remove duplicates
    
    def generate_attack_vectors(self, assets, num_attacks=3):
        """Generate simulated attack vectors"""
        attacks = []
        external_points = [
            (5, 90, 0),   # North-west entry
            (195, 5, 0),  # South-east entry
            (100, 95, 0)  # North entry
        ]
        
        high_value_targets = assets[assets['threat'] > 0.7]['id'].tolist()
        
        for i in range(num_attacks):
            if not high_value_targets:
                break
                
            target = random.choice(high_value_targets)
            high_value_targets.remove(target)
            
            start_point = random.choice(external_points)
            target_row = assets[assets['id'] == target].iloc[0]
            end_point = (target_row['x'], target_row['y'], target_row['z'])
            
            attack_types = ["RCE", "Credential Theft", "Malware", "DoS", "Lateral Movement"]
            attacks.append({
                "start": start_point,
                "end": end_point,
                "type": random.choice(attack_types),
                "time": datetime.now() - timedelta(minutes=random.randint(1, 30))
            })
        
        return attacks

# =============================================
# 3. VISUALIZATION SYSTEM
# =============================================

class IndustrialSecurityVisualizer:
    def __init__(self, data_generator=None):
        self.data_generator = data_generator or IndustrialDataGenerator()
        self.threat_data = None
        self.assets = None
        self.network_links = None
        self.attack_vectors = None
        
    def load_data(self, num_devices=25):
        """Generate or load all required data"""
        self.threat_data = self.data_generator.generate_threat_surface()
        self.assets = self.data_generator.generate_asset_data(num_devices)
        self.network_links = self.data_generator.generate_network_links(self.assets)
        self.attack_vectors = self.data_generator.generate_attack_vectors(self.assets)
        
    def create_3d_threat_model(self):
        """Create interactive 3D visualization of cyber-physical threats"""
        fig = go.Figure()
        
        # 3D Threat Volume
        fig.add_trace(go.Volume(
            x=self.data_generator.X.flatten(),
            y=self.data_generator.Y.flatten(),
            z=self.data_generator.Z.flatten(),
            value=self.threat_data.flatten(),
            isomin=0.3,
            isomax=0.9,
            opacity=THREAT_OPACITY,
            surface_count=35,
            colorscale="Portland",
            colorbar=dict(
                title="<b>THREAT INDEX</b>",
                tickvals=[0.3, 0.6, 0.9],
                ticktext=["LOW", "MEDIUM", "CRITICAL"],
                x=0.82,
                thickness=20,
                len=0.5
            ),
            name="Threat Surface",
            hoverinfo="skip"
        ))
        
        # Add factory structural grid
        self._add_factory_grid(fig)
        
        # Add network connections
        self._add_network_connections(fig)
        
        # Add industrial assets
        for _, asset in self.assets.iterrows():
            fig.add_trace(self._create_asset_marker(asset))
            
        # Add attack vectors
        self._add_attack_vectors(fig)
        
        # Configure layout
        self._configure_3d_layout(fig)
        
        return fig
    
    def create_2d_technical_map(self, floorplan_path):
        """Create 2D technical map with floorplan and threat visualization"""
        # Load and process floorplan
        floorplan = get_or_create_floorplan_image(floorplan_path)
        width, height = floorplan.size
        img_uri = self._image_to_uri(floorplan)
        
        # Generate threat heatmap
        heatmap = self._generate_2d_threat_heatmap(width, height)
        
        fig = go.Figure()
        
        # Add floorplan background
        fig.add_layout_image(
            dict(
                source=img_uri,
                xref="x", yref="y",
                x=0, y=height,
                sizex=width, sizey=height,
                sizing="stretch",
                opacity=1,
                layer="below"
            )
        )
        
        # Add threat heatmap
        fig.add_trace(go.Heatmap(
            z=heatmap,
            x=np.linspace(0, width, 200),
            y=np.linspace(0, height, 200),
            colorscale="Portland",
            opacity=HEATMAP_OPACITY,
            colorbar=dict(title="Threat Level"),
            name="Threat Heatmap"
        ))
        
        # Add assets
        for _, asset in self.assets.iterrows():
            fig.add_trace(self._create_2d_asset_marker(asset))
        
        # Add network connections
        self._add_2d_network_connections(fig, width, height)
        
        # Add attack vectors
        self._add_2d_attack_vectors(fig)
        
        # Configure layout
        self._configure_2d_layout(fig, width, height)
        
        return fig
    
    def _add_factory_grid(self, fig):
        """Add factory structural grid to 3D visualization"""
        # Vertical grid lines (x-axis)
        for gx in range(0, int(self.data_generator.length)+1, 20):
            fig.add_trace(go.Scatter3d(
                x=[gx, gx], 
                y=[0, self.data_generator.width], 
                z=[0, 0],
                mode="lines", 
                line=dict(color="rgba(200,200,200,0.1)", width=1.5), 
                showlegend=False, 
                hoverinfo="skip",
                name=f"Grid X{gx}"
            ))
        
        # Horizontal grid lines (y-axis)
        for gy in range(0, int(self.data_generator.width)+1, 20):
            fig.add_trace(go.Scatter3d(
                x=[0, self.data_generator.length], 
                y=[gy, gy], 
                z=[0, 0],
                mode="lines", 
                line=dict(color="rgba(200,200,200,0.1)", width=1.5), 
                showlegend=False, 
                hoverinfo="skip",
                name=f"Grid Y{gy}"
            ))
        
        # Height markers (z-axis)
        for gz in range(1, self.data_generator.height):
            fig.add_trace(go.Scatter3d(
                x=[0, self.data_generator.length], 
                y=[0, 0], 
                z=[gz, gz],
                mode="lines", 
                line=dict(color="rgba(200,200,200,0.08)", width=1), 
                showlegend=False, 
                hoverinfo="skip",
                name=f"Floor {gz}"
            ))
    
    def _add_network_connections(self, fig):
        """Add network connections between devices in 3D"""
        for src, dst in self.network_links:
            src_row = self.assets[self.assets['id'] == src]
            dst_row = self.assets[self.assets['id'] == dst]
            
            if not src_row.empty and not dst_row.empty:
                fig.add_trace(go.Scatter3d(
                    x=[src_row.iloc[0]['x'], dst_row.iloc[0]['x']],
                    y=[src_row.iloc[0]['y'], dst_row.iloc[0]['y']],
                    z=[src_row.iloc[0]['z'], dst_row.iloc[0]['z']],
                    mode="lines",
                    line=dict(
                        color=f"rgba(0, 255, 208, 0.25)",
                        width=NETWORK_LINE_WIDTH
                    ),
                    showlegend=False,
                    hoverinfo="skip",
                    name=f"{src}-{dst} Connection"
                ))
    
    def _create_asset_marker(self, asset):
        """Create a 3D marker for an industrial asset"""
        asset_type = self._classify_device_type(asset)
        config = DEVICE_TYPES.get(asset_type, DEVICE_TYPES["Other"])
        
        return go.Scatter3d(
            x=[asset["x"]],
            y=[asset["y"]],
            z=[asset["z"]],
            mode="markers+text",
            marker=dict(
                size=DEVICE_MARKER_SIZE,
                color=config["color"],
                symbol=config["symbol"],
                line=dict(width=3, color="#222"),
                opacity=0.95
            ),
            text=f"{asset['id']}",
            textposition="top center",
            textfont=dict(size=12, color=COLOR_SCHEME["light"], family="Arial"),
            name=asset["id"],
            hovertemplate=self._create_hover_template(asset),
            customdata=[asset.to_dict()]
        )
    
    def _add_attack_vectors(self, fig):
        """Add 3D attack vectors to visualization"""
        for attack in self.attack_vectors:
            fig.add_trace(go.Scatter3d(
                x=[attack["start"][0], attack["end"][0]],
                y=[attack["start"][1], attack["end"][1]],
                z=[attack["start"][2], attack["end"][2]],
                mode="lines",
                line=dict(
                    width=ATTACK_LINE_WIDTH,
                    color=COLOR_SCHEME["danger"],
                    dash="dot"
                ),
                name=f"{attack['type']} Attack",
                hovertemplate=(
                    f"<b>{attack['type']} ATTACK</b><br>"
                    f"Detected: {attack['time'].strftime('%Y-%m-%d %H:%M:%S')}<br>"
                    "Severity: <span style='color:red'>CRITICAL</span>"
                    "<extra></extra>"
                )
            ))
    
    def _configure_3d_layout(self, fig):
        """Configure 3D visualization layout"""
        fig.update_layout(
            title=dict(
                text="<b>INDUSTRIAL CYBER-PHYSICAL SECURITY DASHBOARD</b><br>"
                     "<span style='font-size:16px;color:#00FFD0'>Real-Time Threat Intelligence</span>",
                x=0.5, y=0.97,
                xanchor="center",
                yanchor="top",
                font=dict(size=24, family="Arial Black", color=COLOR_SCHEME["primary"])
            ),
            scene=dict(
                xaxis=dict(
                    title="<b>FACTORY LENGTH (m)</b>",
                    gridcolor="rgba(100,100,100,0.3)",
                    color=COLOR_SCHEME["light"],
                    showbackground=True,
                    backgroundcolor="rgba(0,0,0,0.7)",
                    zerolinecolor=COLOR_SCHEME["primary"]
                ),
                yaxis=dict(
                    title="<b>FACTORY WIDTH (m)</b>",
                    gridcolor="rgba(100,100,100,0.3)",
                    color=COLOR_SCHEME["light"],
                    showbackground=True,
                    backgroundcolor="rgba(0,0,0,0.7)",
                    zerolinecolor=COLOR_SCHEME["primary"]
                ),
                zaxis=dict(
                    title="<b>HEIGHT LEVEL</b>",
                    gridcolor="rgba(100,100,100,0.3)",
                    color=COLOR_SCHEME["light"],
                    showbackground=True,
                    backgroundcolor="rgba(0,0,0,0.7)",
                    zerolinecolor=COLOR_SCHEME["primary"]
                ),
                bgcolor=COLOR_SCHEME["background"],
                camera=dict(
                    eye=dict(x=1.8, y=-1.8, z=1.2),
                    up=dict(x=0, y=0, z=1)
                )
            ),
            margin=dict(l=0, r=0, b=0, t=100),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="center",
                x=0.5,
                font=dict(size=12, color=COLOR_SCHEME["primary"], family="Arial"),
                itemsizing="constant",
                bgcolor="rgba(0,0,0,0.7)",
                bordercolor=COLOR_SCHEME["primary"],
                borderwidth=2
            ),
            hoverlabel=dict(
                bgcolor="rgba(0,0,0,0.9)",
                font=dict(size=12, color=COLOR_SCHEME["primary"], family="Arial"),
                bordercolor=COLOR_SCHEME["primary"]
            ),
            template="plotly_dark",
            width=1400,
            height=900,
            paper_bgcolor=COLOR_SCHEME["dark"],
            plot_bgcolor=COLOR_SCHEME["dark"]
        )
        
        # Add interactive controls
        self._add_dashboard_controls(fig)
    
    def _generate_2d_threat_heatmap(self, width, height):
        """Generate 2D threat heatmap based on asset locations"""
        grid_x, grid_y = np.meshgrid(np.linspace(0, width, 200), np.linspace(0, height, 200))
        heatmap = np.zeros_like(grid_x, dtype=float)
        
        # Scale asset coordinates to floorplan dimensions
        x_scale = width / self.data_generator.length
        y_scale = height / self.data_generator.width
        
        for _, asset in self.assets.iterrows():
            x = asset['x'] * x_scale
            y = asset['y'] * y_scale
            dist = np.sqrt((grid_x - x)**2 + (grid_y - y)**2)
            heatmap += asset['threat'] * np.exp(-dist**2 / (2 * 30**2))
        
        # Normalize heatmap
        if np.max(heatmap) > 0:
            heatmap = heatmap / np.max(heatmap)
        
        return heatmap
    
    def _create_2d_asset_marker(self, asset):
        """Create 2D marker for an industrial asset"""
        asset_type = self._classify_device_type(asset)
        symbol = SYMBOLS_2D.get(asset_type.split()[0], "circle")
        
        return go.Scatter(
            x=[asset["x"]],
            y=[asset["y"]],
            mode="markers+text",
            marker=dict(
                size=DEVICE_MARKER_SIZE,
                color=self._get_status_color(asset["status"]),
                symbol=symbol,
                line=dict(width=2, color="white")
            ),
            text=asset["id"],
            textposition="top center",
            textfont=dict(size=10, color="white", family="Arial"),
            name=asset["id"],
            hovertemplate=self._create_hover_template(asset),
            customdata=[asset.to_dict()]
        )
    
    def _add_2d_network_connections(self, fig, width, height):
        """Add network connections to 2D visualization"""
        x_scale = width / self.data_generator.length
        y_scale = height / self.data_generator.width
        
        for src, dst in self.network_links:
            src_row = self.assets[self.assets['id'] == src]
            dst_row = self.assets[self.assets['id'] == dst]
            
            if not src_row.empty and not dst_row.empty:
                fig.add_trace(go.Scatter(
                    x=[src_row.iloc[0]['x'] * x_scale, dst_row.iloc[0]['x'] * x_scale],
                    y=[src_row.iloc[0]['y'] * y_scale, dst_row.iloc[0]['y'] * y_scale],
                    mode="lines",
                    line=dict(
                        color=f"rgba(0, 255, 208, 0.4)",
                        width=3
                    ),
                    showlegend=False,
                    hoverinfo="skip"
                ))
    
    def _add_2d_attack_vectors(self, fig):
        """Add attack vectors to 2D visualization"""
        for attack in self.attack_vectors:
            fig.add_trace(go.Scatter(
                x=[attack["start"][0], attack["end"][0]],
                y=[attack["start"][1], attack["end"][1]],
                mode="lines",
                line=dict(
                    width=3,
                    color=COLOR_SCHEME["danger"],
                    dash="dot"
                ),
                name=f"{attack['type']} Attack",
                hovertemplate=(
                    f"<b>{attack['type']} ATTACK</b><br>"
                    f"Detected: {attack['time'].strftime('%Y-%m-%d %H:%M:%S')}<br>"
                    "Severity: <span style='color:red'>CRITICAL</span>"
                    "<extra></extra>"
                )
            ))
    
    def _configure_2d_layout(self, fig, width, height):
        """Configure 2D visualization layout"""
        fig.update_layout(
            title=dict(
                text="<b>TECHNICAL SECURITY FLOORPLAN</b><br>"
                     "<span style='font-size:14px;color:#00FFD0'>Machine-Level Threat Visualization</span>",
                x=0.5, y=0.98,
                xanchor="center",
                yanchor="top",
                font=dict(size=20, family="Arial Black", color=COLOR_SCHEME["primary"])
            ),
            xaxis=dict(
                visible=False,
                range=[0, width],
                constrain="domain"
            ),
            yaxis=dict(
                visible=False,
                range=[0, height],
                scaleanchor="x"
            ),
            margin=dict(l=0, r=0, t=40, b=0),
            plot_bgcolor=COLOR_SCHEME["dark"],
            paper_bgcolor=COLOR_SCHEME["dark"],
            hovermode="closest",
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="center",
                x=0.5,
                font=dict(size=10, color=COLOR_SCHEME["light"], family="Arial")
            ),
            hoverlabel=dict(
                bgcolor="rgba(0,0,0,0.9)",
                font=dict(size=10, color=COLOR_SCHEME["primary"], family="Arial")
            )
        )
    
    def _add_dashboard_controls(self, fig):
        """Add interactive controls to the dashboard"""
        fig.update_layout(
            updatemenus=[
                dict(
                    type="buttons",
                    direction="left",
                    x=0.5,
                    y=-0.1,
                    xanchor="center",
                    yanchor="top",
                    bgcolor="rgba(20,20,30,0.9)",
                    bordercolor=COLOR_SCHEME["primary"],
                    borderwidth=2,
                    font=dict(color=COLOR_SCHEME["primary"], size=12, family="Arial"),
                    buttons=list([
                        dict(
                            args=[{"scene.camera": {"eye": {"x": 1.8, "y": -1.8, "z": 1.2}}}],
                            label="RESET VIEW",
                            method="relayout"
                        ),
                        dict(
                            args=[{"scene.camera": {"eye": {"x": 0, "y": 0, "z": 2.5}}}],
                            label="TOP VIEW",
                            method="relayout"
                        ),
                        dict(
                            args=[{"scene.camera": {"eye": {"x": 1.8, "y": 1.8, "z": 1.2}}}],
                            label="ROTATE",
                            method="relayout"
                        ),
                        dict(
                            args=["toImage"],
                            label="EXPORT PNG",
                            method="relayout"
                        )
                    ])
                )
            ],
            annotations=[
                dict(
                    x=1.02, y=1.05, xref="paper", yref="paper",
                    text="""
                    <div style="
                        background:rgba(20,20,30,0.95);
                        border:2px solid #00FFD0;
                        border-radius:12px;
                        padding:12px;
                        width:220px;
                        box-shadow:0 0 15px #00FFD033;
                    ">
                        <div style="
                            display:flex;
                            justify-content:space-between;
                            align-items:center;
                            margin-bottom:10px;
                        ">
                            <span style="
                                font-family:Arial Black;
                                color:#00FFD0;
                                font-size:16px;
                            ">CONTROLS</span>
                            <span style="
                                width:12px;
                                height:12px;
                                border-radius:50%;
                                background:#2ECC40;
                                border:2px solid #222;
                            "></span>
                        </div>
                        <div style="
                            display:flex;
                            gap:8px;
                            margin-bottom:10px;
                        ">
                            <button style="
                                flex:1;
                                padding:8px;
                                border:none;
                                border-radius:6px;
                                background:#00FFD0;
                                color:#101020;
                                font-family:Arial;
                                font-weight:bold;
                                cursor:pointer;
                            ">CONNECT</button>
                            <button style="
                                flex:1;
                                padding:8px;
                                border:none;
                                border-radius:6px;
                                background:#222;
                                color:#00FFD0;
                                font-family:Arial;
                                font-weight:bold;
                                cursor:pointer;
                            ">REFRESH</button>
                        </div>
                        <div style="
                            font-family:Arial;
                            color:#BBB;
                            font-size:12px;
                            border-top:1px solid #333;
                            padding-top:8px;
                        ">
                            <div>MODBUS: 192.168.1.10:502</div>
                            <div>OPC UA: opc.tcp://10.0.0.20</div>
                        </div>
                    </div>
                    """,
                    showarrow=False,
                    align="right",
                    xanchor="right",
                    yanchor="top"
                ),
                dict(
                    x=0.5, y=1.12, xref="paper", yref="paper",
                    text="""
                    <div style="
                        display:flex;
                        align-items:center;
                        justify-content:center;
                        gap:10px;
                        font-family:Arial Black;
                        color:#00FFD0;
                        font-size:14px;
                    ">
                        <svg width="20" height="20" viewBox="0 0 20 20">
                            <circle cx="10" cy="10" r="8" stroke="#00FFD0" stroke-width="4" fill="none"
                            stroke-dasharray="60" stroke-dashoffset="40">
                            <animateTransform attributeName="transform" type="rotate" from="0 10 10" to="360 10 10" dur="1.5s" repeatCount="indefinite"/>
                            </circle>
                        </svg>
                        LIVE DATA STREAMING
                    </div>
                    """,
                    showarrow=False,
                    align="center",
                    xanchor="center",
                    yanchor="bottom"
                ),
                dict(
                    x=0.5, y=-0.15, xref="paper", yref="paper",
                    text="<b style='color:#00FFD0;font-family:Arial Black'>SECUREPROD™ | INDUSTRIAL CYBERSECURITY PLATFORM</b>",
                    showarrow=False,
                    font=dict(size=14),
                    align="center"
                )
            ]
        )
    
    def _classify_device_type(self, asset):
        """Classify device based on ID and type"""
        device_id = asset["id"].upper()
        device_type = asset["type"].upper()
        
        if "PLC" in device_id or "PLC" in device_type:
            return "PLC"
        elif "HMI" in device_id or "HMI" in device_type:
            return "HMI"
        elif "ROBOT" in device_type:
            return "Robot"
        elif "SERVER" in device_type:
            return "Server"
        elif "FIREWALL" in device_type or "FW" in device_id:
            return "Firewall"
        elif "VEHICLE" in device_type or "AGV" in device_id:
            return "Vehicle"
        elif "UAV" in device_id or "DRONE" in device_id:
            return "UAV"
        elif "SENSOR" in device_type:
            return "Sensor"
        else:
            return "Other"
    
    def _get_status_color(self, status):
        """Get color for device status"""
        return STATUS_COLORS.get(status, "#AAAAAA")
    
    def _create_hover_template(self, asset):
        """Generate hover template for assets"""
        return (
            f"<b>{asset['id']}</b><br>"
            f"Type: {asset['type']}<br>"
            f"Status: <span style='color:{self._get_status_color(asset['status'])}'>{asset['status'].upper()}</span><br>"
            f"Threat: {asset['threat']*100:.0f}%<br>"
            f"IP: {asset['ip']}<br>"
            f"MAC: {asset['mac']}<br>"
            f"Location: ({asset['x']:.1f}m, {asset['y']:.1f}m, Floor {int(asset['z'])})"
            "<extra></extra>"
        )
    
    def _image_to_uri(self, img):
        """Convert PIL image to base64 URI"""
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buffered.getvalue()).decode()

def get_or_create_floorplan_image(floorplan_path, width=800, height=600):
    """
    Try to open the floorplan image. If not found, generate a blank placeholder image.
    Returns a PIL Image object.
    """
    from PIL import Image, ImageDraw
    import os
    if os.path.exists(floorplan_path):
        return Image.open(floorplan_path)
    # Create a blank placeholder with a grid
    img = Image.new('RGB', (width, height), color=(240, 240, 240))
    draw = ImageDraw.Draw(img)
    # Draw grid lines
    for x in range(0, width, 50):
        draw.line([(x, 0), (x, height)], fill=(200, 200, 200), width=1)
    for y in range(0, height, 50):
        draw.line([(0, y), (width, y)], fill=(200, 200, 200), width=1)
    # Add label
    draw.text((20, 20), "No floorplan found", fill=(180, 0, 0))
    return img

# =============================================
# 4. DASH APPLICATION
# =============================================

def create_dash_app(visualizer):
    """Create interactive Dash application"""
    app = dash.Dash(__name__, external_stylesheets=[dbc.themes.DARKLY])
    
    # Initialize with sample floorplan (replace with your actual path)
    try:
        fig_2d = visualizer.create_2d_technical_map("factory_floorplan.png")
    except:
        # Fallback if floorplan not found
        fig_2d = visualizer.create_2d_technical_map("default_floorplan.png")
    
    fig_3d = visualizer.create_3d_threat_model()
    
    app.layout = dbc.Container(
        fluid=True,
        style={'backgroundColor': COLOR_SCHEME["dark"]},
        children=[
            dcc.Tabs(
                id="visualization-tabs",
                value='3d-tab',
                children=[
                    dcc.Tab(
                        label='3D Threat Model',
                        value='3d-tab',
                        style={'backgroundColor': COLOR_SCHEME["dark"]},
                        selected_style={'backgroundColor': COLOR_SCHEME["background"]},
                        children=[
                            dcc.Graph(
                                id='3d-graph',
                                figure=fig_3d,
                                style={'height': '85vh'},
                                config={
                                    'displayModeBar': True,
                                    'scrollZoom': True,
                                    'displaylogo': False,
                                    'modeBarButtonsToRemove': ['sendDataToCloud', 'lasso2d'],
                                    'toImageButtonOptions': {
                                        'format': 'png',
                                        'filename': 'industrial_threat_3d',
                                        'scale': 2
                                    }
                                }
                            )
                        ]
                    ),
                    dcc.Tab(
                        label='2D Technical Map',
                        value='2d-tab',
                        style={'backgroundColor': COLOR_SCHEME["dark"]},
                        selected_style={'backgroundColor': COLOR_SCHEME["background"]},
                        children=[
                            dcc.Graph(
                                id='2d-graph',
                                figure=fig_2d,
                                style={'height': '85vh'},
                                config={
                                    'displayModeBar': True,
                                    'scrollZoom': True,
                                    'displaylogo': False,
                                    'modeBarButtonsToRemove': ['sendDataToCloud', 'lasso2d'],
                                    'toImageButtonOptions': {
                                        'format': 'png',
                                        'filename': 'industrial_threat_2d',
                                        'scale': 2
                                    }
                                }
                            )
                        ]
                    )
                ]
            ),
            dbc.Row(
                dbc.Col(
                    html.Div(
                        id='device-details',
                        style={
                            'backgroundColor': 'rgba(20,20,30,0.9)',
                            'border': f'1px solid {COLOR_SCHEME["primary"]}',
                            'borderRadius': '5px',
                            'padding': '10px',
                            'marginTop': '10px',
                            'color': COLOR_SCHEME["light"]
                        }
                    ),
                    width=12
                )
            )
        ]
    )
    
    @app.callback(
        Output('device-details', 'children'),
        [Input('3d-graph', 'hoverData'),
         Input('2d-graph', 'hoverData')]
    )
    def display_hover_data(data_3d, data_2d):
        """Display detailed device information on hover"""
        hover_data = data_3d or data_2d
        
        if hover_data is None:
            return html.Div(
                "Hover over a device to see details",
                style={'textAlign': 'center', 'color': COLOR_SCHEME["light"]}
            )
        
        # Extract device data from hover event
        device_data = hover_data['points'][0]['customdata']
        
        # Create detailed information card
        return dbc.Card(
            [
                dbc.CardHeader(
                    html.H4(
                        f"DEVICE DETAILS: {device_data['id']}",
                        style={
                            'color': COLOR_SCHEME["primary"],
                            'fontFamily': 'Arial Black'
                        }
                    )
                ),
                dbc.CardBody(
                    [
                        dbc.Row(
                            [
                                dbc.Col(
                                    [
                                        html.P(
                                            [
                                                html.Strong("Type: "),
                                                device_data['type']
                                            ],
                                            className="mb-1"
                                        ),
                                        html.P(
                                            [
                                                html.Strong("Status: "),
                                                html.Span(
                                                    device_data['status'].upper(),
                                                    style={
                                                        'color': STATUS_COLORS.get(
                                                            device_data['status'], 
                                                            COLOR_SCHEME["light"]
                                                        )
                                                    }
                                                )
                                            ],
                                            className="mb-1"
                                        ),
                                        html.P(
                                            [
                                                html.Strong("Threat Level: "),
                                                f"{device_data['threat']*100:.0f}%"
                                            ],
                                            className="mb-1"
                                        )
                                    ],
                                    width=6
                                ),
                                dbc.Col(
                                    [
                                        html.P(
                                            [
                                                html.Strong("IP Address: "),
                                                device_data['ip']
                                            ],
                                            className="mb-1"
                                        ),
                                        html.P(
                                            [
                                                html.Strong("MAC Address: "),
                                                device_data['mac']
                                            ],
                                            className="mb-1"
                                        ),
                                        html.P(
                                            [
                                                html.Strong("Location: "),
                                                f"X: {device_data['x']:.1f}m, Y: {device_data['y']:.1f}m, Floor: {int(device_data['z'])}"
                                            ],
                                            className="mb-1"
                                        )
                                    ],
                                    width=6
                                )
                            ]
                        ),
                        html.Hr(),
                        dbc.Row(
                            [
                                dbc.Col(
                                    dbc.Progress(
                                        value=device_data['threat']*100,
                                        color="danger" if device_data['threat'] > 0.7 
                                              else "warning" if device_data['threat'] > 0.4 
                                              else "success",
                                        striped=True,
                                        animated=device_data['threat'] > 0.7,
                                        className="mb-3"
                                    ),
                                    width=12
                                )
                            ]
                        ),
                        dbc.Row(
                            [
                                dbc.Col(
                                    dbc.Button(
                                        "View Network Path",
                                        color="primary",
                                        outline=True,
                                        className="me-1"
                                    ),
                                    width=4
                                ),
                                dbc.Col(
                                    dbc.Button(
                                        "Security Audit",
                                        color="warning",
                                        outline=True,
                                        className="me-1"
                                    ),
                                    width=4
                                ),
                                dbc.Col(
                                    dbc.Button(
                                        "Isolate Device",
                                        color="danger",
                                        outline=True
                                    ),
                                    width=4
                                )
                            ]
                        )
                    ]
                )
            ],
            style={
                'border': f'1px solid {COLOR_SCHEME["primary"]}',
                'boxShadow': f'0 0 10px {COLOR_SCHEME["primary"]}33'
            }
        )

    # Add callback for refreshing data
    @app.callback(
        [Output('3d-graph', 'figure'),
         Output('2d-graph', 'figure')],
        [Input('refresh-interval', 'n_intervals')]
    )
    def refresh_data(n):
        """Periodically refresh the visualization data"""
        visualizer.load_data()
        
        try:
            fig_2d = visualizer.create_2d_technical_map("factory_floorplan.png")
        except:
            fig_2d = visualizer.create_2d_technical_map("default_floorplan.png")
            
        fig_3d = visualizer.create_3d_threat_model()
        
        return fig_3d, fig_2d

    # Add hidden interval component for auto-refresh
    app.layout.children.append(
        dcc.Interval(
            id='refresh-interval',
            interval=60*1000,  # 1 minute
            n_intervals=0
        )
    )

    # Add new Dash layout for scanner
    scanner = ll.VulnScanner()

    scanner_layout = dbc.Container([
        html.H2('Vulnerability Scanner'),
        dbc.Row([
            dbc.Col([
                html.H4('Endpoints'),
                dcc.Input(id='endpoint-input', type='text', placeholder='https://example.com/api', style={'width':'80%'}),
                html.Button('Add', id='add-endpoint-btn', n_clicks=0),
                html.Ul(id='endpoint-list', children=[html.Li(e) for e in scanner.endpoints]),
            ], width=4),
            dbc.Col([
                html.H4('Scan Control'),
                html.Button('Start Scan', id='start-scan-btn', n_clicks=0),
                html.Div(id='scan-status', children='Status: Idle'),
                html.Div(id='scan-progress'),
            ], width=4),
            dbc.Col([
                html.H4('Reports'),
                html.A('Download Last Report', id='download-report-link', href='#', target='_blank'),
                html.Div(id='findings-summary'),
            ], width=4),
        ]),
        html.Hr(),
        html.H4('Findings'),
        html.Div(id='findings-table'),
        html.H4('Sensitive Data'),
        html.Div(id='sensitive-data-table'),
    ], fluid=True)

    # Add scanner tab to Dash app
    app.layout.children.append(
        dcc.Tab(label='Vulnerability Scanner', value='scanner-tab', children=[scanner_layout])
    )

    # Add callbacks for endpoint management, scan control, and report download
    @app.callback(
        Output('endpoint-list', 'children'),
        [Input('add-endpoint-btn', 'n_clicks')],
        [State('endpoint-input', 'value')]
    )
    def update_endpoints(n_clicks, value):
        if n_clicks and value:
            scanner.add_endpoint(value)
        return [html.Li(e) for e in scanner.endpoints]

    @app.callback(
        [Output('scan-status', 'children'), Output('findings-table', 'children'), Output('sensitive-data-table', 'children'), Output('download-report-link', 'href')],
        [Input('start-scan-btn', 'n_clicks')]
    )
    def start_scan(n_clicks):
        if n_clicks:
            scanner.run_all()
            report = scanner.get_report()
            findings = report['findings']
            sensitive = [f for f in findings if f.get('sensitive_data')]
            findings_table = html.Ul([html.Li(str(f)) for f in findings])
            sensitive_table = html.Ul([html.Li(str(f.get('sensitive_data'))) for f in sensitive])
            return f'Status: Done', findings_table, sensitive_table, report['report_file']
        return 'Status: Idle', '', '', '#'

    return app

# =============================================
# 5. MAIN EXECUTION
# =============================================

if __name__ == '__main__':
    # Initialize data generator and visualizer
    data_gen = IndustrialDataGenerator()
    visualizer = IndustrialSecurityVisualizer(data_gen)
    visualizer.load_data(num_devices=30)
    
    # Create and run Dash application
    app = create_dash_app(visualizer)
    import dash
    if isinstance(app, dash.Dash):
        def open_browser():
            webbrowser.open_new('http://localhost:8050')
        threading.Timer(1.5, open_browser).start()
        app.run(debug=True, host='localhost', port=8050)
    else:
        print("Error: 'app' is not a Dash app. Please check your create_dash_app function.")