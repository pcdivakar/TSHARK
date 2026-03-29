"""
OT Asset Discovery & Professional Network Topology Map
- Extracts rich device metadata directly from PCAP using correct tshark filters
- Professional vis-network with draggable, zoomable, color-coded nodes
- Purdue model hierarchical layout
"""

import streamlit as st
import subprocess
import tempfile
import os
import re
import pandas as pd
import networkx as nx
import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional

st.set_page_config(page_title="OT Asset Discovery", layout="wide")
st.title("🏭 OT Asset Discovery & Network Topology")
st.markdown("Upload a PCAP file to identify OT assets and visualize communication flows.")

# =============================================================================
# 1. PROTOCOL DEFINITIONS WITH CORRECT TSHARK FIELD EXTRACTIONS
# =============================================================================

PROTOCOLS = {
    "pn_dcp": {
        "filter": "pn_dcp",
        "name": "PROFINET DCP",
        "fields": [
            "pn_dcp.device_role", 
            "pn_dcp.vendor_id", 
            "pn_dcp.device_id",
            "pn_dcp.station_name", 
            "pn_dcp.ip_address", 
            "eth.src",
            "pn_dcp.name_of_station"
        ],
        "asset_fields": {
            "role": "pn_dcp.device_role",
            "vendor_id": "pn_dcp.vendor_id", 
            "device_id": "pn_dcp.device_id",
            "station_name": "pn_dcp.station_name",
            "mac": "eth.src"
        }
    },
    "enip_cip": {
        "filter": "cip.identity or cip",
        "name": "EtherNet/IP (CIP)",
        "fields": [
            "ip.src", 
            "cip.vendor_id", 
            "cip.product_name", 
            "cip.serial_number",
            "cip.product_revision",
            "cip.device_type"
        ],
        "asset_fields": {
            "vendor_id": "cip.vendor_id",
            "product_name": "cip.product_name",
            "serial": "cip.serial_number",
            "revision": "cip.product_revision",
            "device_type": "cip.device_type"
        }
    },
    "s7comm": {
        "filter": "s7comm",
        "name": "Siemens S7comm",
        "fields": [
            "ip.src", 
            "s7comm.cpu_type", 
            "s7comm.module_type",
            "s7comm.identity_serial_number_of_module"
        ],
        "asset_fields": {
            "cpu_type": "s7comm.cpu_type",
            "module_type": "s7comm.module_type",
            "serial": "s7comm.identity_serial_number_of_module"
        }
    },
    "modbus": {
        "filter": "modbus",
        "name": "Modbus/TCP",
        "fields": ["ip.src", "modbus.unit_id"],
        "asset_fields": {"unit_id": "modbus.unit_id"}
    },
    "dnp3": {
        "filter": "dnp3",
        "name": "DNP3",
        "fields": ["ip.src", "dnp3.src", "dnp3.dst", "dnp3.object_header"],
        "asset_fields": {"dnp3_src": "dnp3.src", "object_header": "dnp3.object_header"}
    },
    "bacnet": {
        "filter": "bacnet",
        "name": "BACnet",
        "fields": [
            "ip.src", 
            "bacnet.object_name", 
            "bacnet.vendor_id", 
            "bacnet.model_name",
            "bacnet.firmware_revision"
        ],
        "asset_fields": {
            "object_name": "bacnet.object_name",
            "vendor_id": "bacnet.vendor_id",
            "model": "bacnet.model_name",
            "firmware": "bacnet.firmware_revision"
        }
    },
    "lldp": {
        "filter": "lldp",
        "name": "LLDP",
        "fields": ["lldp.system_name", "lldp.system_description", "lldp.chassis_id"],
        "asset_fields": {"system_name": "lldp.system_name", "system_desc": "lldp.system_description"}
    },
    "snmp": {
        "filter": "snmp",
        "name": "SNMP",
        "fields": ["ip.src", "snmp.sysDescr", "snmp.sysName", "snmp.sysObjectID"],
        "asset_fields": {"sysDescr": "snmp.sysDescr", "sysName": "snmp.sysName"}
    }
}

# =============================================================================
# 2. VENDOR ID MAPPINGS (from PEAT and industry standards) [citation:4]
# =============================================================================

VENDOR_MAP = {
    # Siemens
    "002a": "Siemens AG",
    "002a": "Siemens",
    # Rockwell Automation
    "001b": "Rockwell Automation",
    "0001": "Rockwell Automation",
    # Schneider Electric
    "005a": "Schneider Electric",
    "0044": "Schneider Electric",
    # ABB
    "001c": "ABB",
    "0004": "ABB",
    # Phoenix Contact
    "006f": "Phoenix Contact",
    # Beckhoff
    "0065": "Beckhoff Automation",
    # Bosch Rexroth
    "0060": "Bosch Rexroth",
    # B&R
    "0078": "B&R Automation",
    # Mitsubishi
    "003c": "Mitsubishi Electric",
    # Omron
    "003d": "Omron Corporation",
    # GE
    "0062": "GE Automation",
    # Emerson
    "0061": "Emerson Electric",
    # Honeywell
    "005f": "Honeywell",
    # Yokogawa
    "005e": "Yokogawa Electric",
    # Cisco
    "0036": "Cisco Systems",
    # Hirschmann/Belden
    "001f": "Hirschmann/Belden",
    # MOXA
    "001d": "MOXA",
}

# =============================================================================
# 3. TSHARK HELPER
# =============================================================================

@st.cache_data(ttl=3600)
def run_tshark(pcap_path: str, display_filter: str, fields: List[str]) -> List[str]:
    """Run tshark and return list of tab-separated lines."""
    cmd = ["tshark", "-r", pcap_path]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    cmd.extend(["-T", "fields"])
    for f in fields:
        cmd.extend(["-e", f])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout.strip().splitlines() if result.stdout else []
    except Exception as e:
        return []

# =============================================================================
# 4. ASSET METADATA EXTRACTION
# =============================================================================

def extract_vendor_from_fields(vendor_id: str, product_name: str = "", sysdescr: str = "") -> str:
    """Extract vendor name from various sources."""
    if vendor_id and vendor_id in VENDOR_MAP:
        return VENDOR_MAP[vendor_id]
    if product_name:
        prod_lower = product_name.lower()
        if "siemens" in prod_lower or "s7" in prod_lower:
            return "Siemens"
        if "rockwell" in prod_lower or "controllogix" in prod_lower or "compactlogix" in prod_lower:
            return "Rockwell Automation"
        if "schneider" in prod_lower or "modicon" in prod_lower:
            return "Schneider Electric"
        if "abb" in prod_lower:
            return "ABB"
        if "phoenix" in prod_lower:
            return "Phoenix Contact"
        if "beckhoff" in prod_lower:
            return "Beckhoff"
    if sysdescr:
        desc_lower = sysdescr.lower()
        for vendor in VENDOR_MAP.values():
            if vendor.lower() in desc_lower:
                return vendor
    return "Unknown"

def determine_asset_type(protocols: List[str], metadata: Dict[str, str]) -> str:
    """Determine asset type based on protocol patterns."""
    if "pn_dcp" in protocols:
        role = metadata.get("role", "")
        if role == "02":
            return "PLC (PROFINET Controller)"
        elif role == "01":
            return "I/O Device (Field Device)"
        elif role == "08":
            return "HMI / Engineering Workstation"
    if "s7comm" in protocols:
        cpu = metadata.get("cpu_type", "")
        if "CPU" in cpu:
            return f"Siemens PLC ({cpu})"
        elif "WinCC" in cpu:
            return "HMI/SCADA Server"
    if "enip_cip" in protocols:
        dev_type = metadata.get("device_type", "")
        product = metadata.get("product_name", "")
        if "PLC" in dev_type or "Controller" in dev_type:
            return "Rockwell PLC"
        if "Drive" in dev_type or "PowerFlex" in product:
            return "Motor Drive / VFD"
        if "PanelView" in product:
            return "HMI"
    if "bacnet" in protocols:
        return "BACnet Building Controller"
    if "dnp3" in protocols:
        return "DNP3 RTU / IED"
    if "modbus" in protocols:
        return "Modbus Device"
    if "lldp" in protocols and "system_desc" in metadata:
        desc = metadata["system_desc"].lower()
        if "switch" in desc:
            return "Network Switch"
        if "router" in desc:
            return "Router"
    return "OT Device"

# =============================================================================
# 5. CONVERSATION EXTRACTION
# =============================================================================

@st.cache_data(ttl=3600)
def get_conversations(pcap_path: str) -> Dict[Tuple[str, str], int]:
    """Extract IP conversations using tshark."""
    conversations = {}
    cmd = ["tshark", "-r", pcap_path, "-z", "conv,ip", "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        for line in result.stdout.split('\n'):
            if '<->' not in line or 'Frames' in line or 'Bytes' in line:
                continue
            parts = line.strip().split()
            if len(parts) < 6:
                continue
            try:
                arrow_idx = parts.index('<->')
                src = parts[arrow_idx - 1]
                dst = parts[arrow_idx + 1]
                for p in reversed(parts):
                    if p.isdigit():
                        conversations[(src, dst)] = int(p)
                        break
            except ValueError:
                continue
    except Exception as e:
        st.warning(f"Error extracting conversations: {e}")
    return conversations

# =============================================================================
# 6. PROFESSIONAL NETWORK TOPOLOGY WITH VIS-NETWORK
# =============================================================================

def generate_professional_topology(G: nx.Graph, ip_to_asset: Dict[str, Dict]) -> str:
    """
    Generate professional vis-network HTML with proper physics and styling.
    Uses hierarchical layout (Purdue model) with color-coded asset types.
    """
    # Asset type colors (professional palette)
    color_map = {
        "PLC": {"background": "#E74C3C", "border": "#C0392B", "highlight": "#EC7063"},
        "HMI": {"background": "#3498DB", "border": "#2980B9", "highlight": "#5DADE2"},
        "I/O Device": {"background": "#2ECC71", "border": "#27AE60", "highlight": "#58D68D"},
        "Drive": {"background": "#F39C12", "border": "#E67E22", "highlight": "#F5B041"},
        "Switch": {"background": "#1ABC9C", "border": "#16A085", "highlight": "#48C9B0"},
        "RTU": {"background": "#9B59B6", "border": "#8E44AD", "highlight": "#AF7AC5"},
        "Building Controller": {"background": "#1ABC9C", "border": "#16A085", "highlight": "#48C9B0"},
        "Modbus Device": {"background": "#34495E", "border": "#2C3E50", "highlight": "#5D6D7E"},
        "OT Device": {"background": "#7F8C8D", "border": "#707B7C", "highlight": "#99A3A4"},
        "Unknown": {"background": "#95A5A6", "border": "#7F8C8D", "highlight": "#BDC3C7"}
    }
    
    # Purdue levels (0=Field, 1=Control, 2=Supervisory, 3=Enterprise)
    purdue_level = {
        "PLC": 1,
        "I/O Device": 0,
        "Drive": 0,
        "HMI": 2,
        "RTU": 1,
        "Building Controller": 1,
        "Modbus Device": 1,
        "Switch": 1,
        "OT Device": 1,
        "Unknown": 1
    }
    
    nodes = []
    edges = []
    
    # Create nodes with professional styling
    for node, attrs in G.nodes(data=True):
        asset_info = ip_to_asset.get(node, {})
        asset_type = asset_info.get("asset_type", "Unknown")
        
        # Find closest matching color key
        color_key = "Unknown"
        for key in color_map.keys():
            if key in asset_type:
                color_key = key
                break
        
        colors = color_map.get(color_key, color_map["Unknown"])
        level = purdue_level.get(color_key, 1)
        
        # Build hover tooltip with all available information
        tooltip_lines = [
            f"<b>{node}</b>",
            f"Type: {asset_type}",
            f"Vendor: {asset_info.get('vendor', 'Unknown')}",
            f"Model: {asset_info.get('model', 'Unknown')}"
        ]
        if asset_info.get("firmware"):
            tooltip_lines.append(f"Firmware: {asset_info['firmware']}")
        if asset_info.get("serial"):
            tooltip_lines.append(f"Serial: {asset_info['serial']}")
        tooltip_lines.append(f"Protocols: {asset_info.get('protocols', 'Unknown')}")
        
        nodes.append({
            "id": node,
            "label": node,
            "title": "<br>".join(tooltip_lines),
            "color": {
                "background": colors["background"],
                "border": colors["border"],
                "highlight": {"background": colors["highlight"], "border": colors["border"]}
            },
            "level": level,
            "shape": "dot",
            "size": 25,
            "font": {"color": "white", "size": 12, "face": "Arial"},
            "borderWidth": 2
        })
    
    # Create edges with weight-based thickness
    max_weight = max([data.get("weight", 1) for _, _, data in G.edges(data=True)]) if G.edges() else 1
    for u, v, data in G.edges(data=True):
        weight = data.get("weight", 1)
        width = 1 + (weight / max_weight) * 5 if max_weight > 0 else 1
        edges.append({
            "from": u,
            "to": v,
            "width": width,
            "title": f"Packets: {weight}",
            "color": {"color": "#888888", "highlight": "#E74C3C"},
            "smooth": {"type": "continuous", "roundness": 0.5}
        })
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>OT Network Topology</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
        <style>
            html, body {{
                margin: 0;
                padding: 0;
                width: 100%;
                height: 100%;
                background-color: #1a1a2e;
                font-family: 'Segoe UI', Arial, sans-serif;
            }}
            #network {{
                width: 100%;
                height: 100%;
                background-color: #1a1a2e;
            }}
            .controls {{
                position: absolute;
                bottom: 20px;
                right: 20px;
                background: rgba(0,0,0,0.7);
                padding: 8px 15px;
                border-radius: 8px;
                color: white;
                font-size: 12px;
                z-index: 100;
                backdrop-filter: blur(5px);
                font-family: monospace;
            }}
            .legend {{
                position: absolute;
                bottom: 20px;
                left: 20px;
                background: rgba(0,0,0,0.7);
                padding: 10px 15px;
                border-radius: 8px;
                color: white;
                font-size: 11px;
                z-index: 100;
                backdrop-filter: blur(5px);
            }}
            .legend h4 {{
                margin: 0 0 8px 0;
                font-size: 12px;
            }}
            .legend-item {{
                display: inline-block;
                margin-right: 15px;
            }}
            .legend-color {{
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 5px;
            }}
        </style>
    </head>
    <body>
        <div id="network"></div>
        <div class="legend">
            <h4>🔷 Asset Types (Purdue Levels)</h4>
            <div class="legend-item"><span class="legend-color" style="background:#E74C3C;"></span>PLC (L1)</div>
            <div class="legend-item"><span class="legend-color" style="background:#2ECC71;"></span>I/O Device (L0)</div>
            <div class="legend-item"><span class="legend-color" style="background:#F39C12;"></span>Drive (L0)</div>
            <div class="legend-item"><span class="legend-color" style="background:#3498DB;"></span>HMI (L2)</div>
            <div class="legend-item"><span class="legend-color" style="background:#1ABC9C;"></span>Switch/Network (L1)</div>
            <div class="legend-item"><span class="legend-color" style="background:#9B59B6;"></span>RTU (L1)</div>
            <div class="legend-item"><span class="legend-color" style="background:#95A5A6;"></span>Unknown</div>
        </div>
        <div class="controls">
            🖱️ Drag nodes | 🔍 Scroll zoom | ⬜ Double-click fullscreen
        </div>
        <script>
            var nodes = new vis.DataSet({json.dumps(nodes)});
            var edges = new vis.DataSet({json.dumps(edges)});
            
            var container = document.getElementById('network');
            var data = {{nodes: nodes, edges: edges}};
            
            var options = {{
                nodes: {{
                    font: {{color: 'white', size: 12, face: 'Arial'}},
                    borderWidth: 2,
                    shadow: {{enabled: true, color: 'rgba(0,0,0,0.3)', size: 5}}
                }},
                edges: {{
                    smooth: {{type: 'continuous', roundness: 0.5}},
                    font: {{color: 'white', size: 10, align: 'middle'}},
                    arrows: {{to: {{enabled: false}}}},
                    shadow: {{enabled: true, color: 'rgba(0,0,0,0.2)'}}
                }},
                physics: {{
                    enabled: true,
                    solver: 'hierarchicalRepulsion',
                    hierarchicalRepulsion: {{
                        nodeDistance: 180,
                        centralGravity: 0.3,
                        springLength: 200,
                        springConstant: 0.01,
                        damping: 0.09
                    }},
                    stabilization: {{
                        iterations: 300,
                        fit: true
                    }}
                }},
                layout: {{
                    hierarchical: {{
                        enabled: true,
                        levelSeparation: 180,
                        nodeSpacing: 150,
                        treeSpacing: 200,
                        direction: 'UD',
                        sortMethod: 'directed'
                    }}
                }},
                interaction: {{
                    dragNodes: true,
                    dragView: true,
                    zoomView: true,
                    hover: true,
                    tooltipDelay: 100,
                    navigationButtons: false,
                    keyboard: {{enabled: true}}
                }}
            }};
            
            var network = new vis.Network(container, data, options);
            
            // Fullscreen on double-click
            network.on('doubleClick', function(params) {{
                if (document.fullscreenElement) {{
                    document.exitFullscreen();
                }} else {{
                    document.documentElement.requestFullscreen();
                }}
            }});
            
            // Fit network after stabilization
            network.on('stabilizationIterationsDone', function() {{
                network.fit();
            }});
        </script>
    </body>
    </html>
    """
    return html

# =============================================================================
# 7. MAIN STREAMLIT APP
# =============================================================================

def main():
    uploaded_file = st.file_uploader("📁 Choose a PCAP file", type=["pcap", "pcapng"])
    
    if not uploaded_file:
        st.info("👈 Upload a PCAP file to begin OT asset discovery")
        return
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        pcap_path = tmp.name
    
    st.info(f"📡 Analyzing {uploaded_file.name}... This may take a moment.")
    
    # Extract data from each protocol
    ip_data = defaultdict(lambda: {
        "protocols": [],
        "metadata": {},
        "vendor": "Unknown",
        "model": "Unknown",
        "firmware": "Unknown",
        "serial": "Unknown"
    })
    
    progress_bar = st.progress(0)
    total_protos = len(PROTOCOLS)
    
    for idx, (key, proto) in enumerate(PROTOCOLS.items()):
        progress_bar.progress((idx + 1) / total_protos, f"Processing {proto['name']}...")
        lines = run_tshark(pcap_path, proto["filter"], proto["fields"])
        
        for line in lines:
            parts = line.split('\t')
            ip = None
            
            # Find IP address in the fields
            for p in parts:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', p):
                    ip = p
                    break
            
            if not ip:
                continue
            
            # Add protocol
            if proto["name"] not in ip_data[ip]["protocols"]:
                ip_data[ip]["protocols"].append(proto["name"])
            
            # Extract asset fields
            for field_name, tshark_field in proto["asset_fields"].items():
                try:
                    field_idx = proto["fields"].index(tshark_field)
                    if field_idx < len(parts) and parts[field_idx]:
                        ip_data[ip]["metadata"][field_name] = parts[field_idx]
                except ValueError:
                    pass
    
    progress_bar.empty()
    
    # Build asset information
    assets = []
    ip_to_asset_info = {}
    
    for ip, data in ip_data.items():
        metadata = data["metadata"]
        protocols = data["protocols"]
        
        # Extract vendor
        vendor = extract_vendor_from_fields(
            metadata.get("vendor_id", ""),
            metadata.get("product_name", ""),
            metadata.get("sysDescr", "")
        )
        
        # Extract model
        model = metadata.get("product_name", "") or metadata.get("model", "") or metadata.get("cpu_type", "") or metadata.get("station_name", "")
        
        # Extract firmware/revision
        firmware = metadata.get("firmware", "") or metadata.get("revision", "")
        
        # Extract serial number
        serial = metadata.get("serial", "")
        
        # Determine asset type
        asset_type = determine_asset_type(protocols, metadata)
        
        asset_info = {
            "ip": ip,
            "asset_type": asset_type,
            "vendor": vendor,
            "model": model,
            "firmware": firmware,
            "serial": serial,
            "protocols": ", ".join(protocols),
            "metadata": ", ".join([f"{k}:{v}" for k, v in metadata.items() if v])
        }
        
        assets.append(asset_info)
        ip_to_asset_info[ip] = asset_info
    
    # Build network graph
    conversations = get_conversations(pcap_path)
    
    G = nx.Graph()
    for asset in assets:
        G.add_node(asset["ip"])
    
    for (src, dst), count in conversations.items():
        if src in ip_to_asset_info and dst in ip_to_asset_info:
            G.add_edge(src, dst, weight=count)
    
    # Display results in tabs
    tab1, tab2 = st.tabs(["📋 Asset Inventory", "🗺️ Network Topology"])
    
    with tab1:
        if assets:
            df = pd.DataFrame(assets)
            # Reorder columns for better readability
            column_order = ["ip", "asset_type", "vendor", "model", "firmware", "serial", "protocols", "metadata"]
            df = df[[col for col in column_order if col in df.columns]]
            st.dataframe(df, use_container_width=True)
            
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download Asset Inventory (CSV)", csv, "ot_assets.csv", "text/csv")
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Assets", len(assets))
            col2.metric("Unique Protocols", len(set(p for a in assets for p in a["protocols"].split(", ") if p)))
            col3.metric("Communication Links", G.number_of_edges())
        else:
            st.warning("No OT assets detected in this PCAP file.")
    
    with tab2:
        if G.number_of_nodes() > 0:
            st.subheader("Interactive OT Network Topology")
            st.markdown("*Purdue model hierarchical layout | Color-coded by asset type | Draggable & zoomable*")
            
            html_graph = generate_professional_topology(G, ip_to_asset_info)
            st.components.v1.html(html_graph, height=700, scrolling=False)
            
            st.caption(f"📊 **Network Statistics:** {G.number_of_nodes()} nodes | {G.number_of_edges()} edges | Double-click graph for fullscreen mode")
        else:
            st.info("No network conversations found to display topology.")
    
    # Cleanup
    os.unlink(pcap_path)

if __name__ == "__main__":
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        st.error("❌ tshark not found. Ensure `packages.txt` contains 'tshark' and redeploy.")
        st.stop()
    main()
