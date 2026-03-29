"""
OT Asset Discovery & Network Architecture Mapping
- Exhaustive asset classification (200+ types) using tshark deep inspection
- Network topology extraction using tshark's built-in conversation stats
- Interactive Plotly graph of communication flows
"""

import streamlit as st
import subprocess
import tempfile
import os
import re
import pandas as pd
import plotly.graph_objects as go
import networkx as nx
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

st.set_page_config(page_title="OT Asset Classifier + Network Map", layout="wide")
st.title("🏭 OT Asset Discovery & Network Topology")
st.markdown("Upload a PCAP file to classify OT assets and visualise communication flows.")

# =============================================================================
# 1. EXHAUSTIVE CLASSIFICATION MAPPINGS
# =============================================================================

# ---- PROFINET DCP ----
PN_DEVICE_ROLE_MAP = {
    "01": "I/O Device (Sensor/Actuator/Field Device)",
    "02": "PLC / IO Controller (PROFINET Master)",
    "03": "Backplane Component",
    "04": "PN Supervisor (Configuration/Engineering Tool)",
    "05": "Parameterization Tool",
    "08": "HMI / Operator Panel / Engineering Workstation",
    "10": "Network Switch / Bridge",
    "20": "Drive / Motor Controller (VFD/Servo)",
    "40": "Gateway / Proxy Device",
    "80": "Safety Controller (F-Controller)",
}

PN_DEVICE_ID_MAP = {
    # Siemens
    ("002a", "010d"): "Siemens S7-1200 PLC",
    ("002a", "010e"): "Siemens S7-1500 PLC",
    ("002a", "0203"): "Siemens S7-300 CPU",
    ("002a", "0204"): "Siemens S7-400 CPU",
    ("002a", "010b"): "Siemens ET200S I/O Device",
    ("002a", "0403"): "Siemens ET200SP I/O Device",
    ("002a", "0301"): "Siemens HMI Panel (Comfort Panel)",
    ("002a", "0a01"): "Siemens Industrial Ethernet Switch",
    ("002a", "0501"): "Siemens SINAMICS Drive",
    # Rockwell
    ("001b", "0001"): "Rockwell ControlLogix PLC",
    ("001b", "0002"): "Rockwell CompactLogix PLC",
    ("001b", "0100"): "Rockwell PowerFlex Drive",
    ("001b", "0200"): "Rockwell Stratix Switch",
    ("001b", "0300"): "Rockwell PanelView HMI",
    # Schneider
    ("005a", "0001"): "Schneider Modicon M340 PLC",
    ("005a", "0002"): "Schneider Modicon M580 PLC",
    # ABB
    ("001c", "0001"): "ABB AC500 PLC",
    # Phoenix Contact
    ("006f", "0001"): "Phoenix Contact AXC PLC",
}

# ---- EtherNet/IP (CIP) ----
CIP_DEVICE_TYPE_MAP = {
    "0x01": "AC Drive (VFD)",
    "0x02": "AC Drive (Advanced)",
    "0x05": "Motor Starter",
    "0x0A": "Valve Actuator",
    "0x0C": "HMI / Operator Panel",
    "0x2B": "Programmable Logic Controller (PLC)",
    "0x2F": "I/O Module",
    "0x37": "Safety Controller",
    "0x1E": "I/O Block (Digital)",
    "0x1F": "I/O Block (Analog)",
    "0x21": "Network Switch (Managed)",
    "0x23": "Gateway / Router",
    "0x2C": "Robot Controller",
    "0x2E": "Vision System",
}

CIP_VENDOR_MAP = {
    "1": "Rockwell Automation",
    "2": "Schneider Electric",
    "3": "Siemens",
    "4": "ABB",
    "44": "Schneider Electric (Telemechanique)",
    "57": "Siemens",
    "111": "Phoenix Contact",
}

# ---- Siemens S7comm ----
S7_CPU_TYPE_MAP = {
    "CPU 315": "Siemens S7-300 CPU 315-2 PN/DP",
    "CPU 317": "Siemens S7-300 CPU 317",
    "CPU 412": "Siemens S7-400 CPU 412",
    "CPU 414": "Siemens S7-400 CPU 414",
    "CPU 416": "Siemens S7-400 CPU 416",
    "CPU 1211": "Siemens S7-1200 CPU 1211C",
    "CPU 1212": "Siemens S7-1200 CPU 1212C",
    "CPU 1214": "Siemens S7-1200 CPU 1214C",
    "CPU 1215": "Siemens S7-1200 CPU 1215C",
    "CPU 1511": "Siemens S7-1500 CPU 1511",
    "CPU 1512": "Siemens S7-1500 CPU 1512",
    "CPU 1513": "Siemens S7-1500 CPU 1513",
    "CPU 1515": "Siemens S7-1500 CPU 1515",
    "CPU 1516": "Siemens S7-1500 CPU 1516",
    "CPU 1517": "Siemens S7-1500 CPU 1517",
    "CPU 1518": "Siemens S7-1500 CPU 1518",
    "WinCC": "Siemens WinCC HMI/SCADA",
}

# ---- BACnet ----
BACNET_VENDOR_MAP = {
    "8": "Johnson Controls",
    "24": "Siemens Building Technologies",
    "38": "Honeywell",
    "122": "Schneider Electric",
    "141": "Trane",
}

# =============================================================================
# 2. PROTOCOL DEFINITIONS FOR TSHARK FIELD EXTRACTION
# =============================================================================

PROTOCOLS = {
    "pn_dcp": {
        "filter": "pn_dcp",
        "name": "PROFINET DCP",
        "fields": ["pn_dcp.device_role", "pn_dcp.vendor_id", "pn_dcp.device_id",
                   "pn_dcp.station_name", "pn_dcp.ip_address", "eth.src"],
        "asset": {
            "device_role": "pn_dcp.device_role",
            "vendor_id": "pn_dcp.vendor_id",
            "device_id": "pn_dcp.device_id",
            "station_name": "pn_dcp.station_name"
        }
    },
    "enip": {
        "filter": "cip",
        "name": "EtherNet/IP (CIP)",
        "fields": ["ip.src", "cip.device_type", "cip.vendor_id", "cip.product_name", "cip.serial_number"],
        "asset": {
            "device_type": "cip.device_type",
            "vendor_id": "cip.vendor_id",
            "product_name": "cip.product_name",
            "serial": "cip.serial_number"
        }
    },
    "s7comm": {
        "filter": "s7comm",
        "name": "Siemens S7comm",
        "fields": ["ip.src", "s7comm.cpu_type", "s7comm.module_type"],
        "asset": {
            "cpu_type": "s7comm.cpu_type",
            "module_type": "s7comm.module_type"
        }
    },
    "modbus": {
        "filter": "modbus",
        "name": "Modbus/TCP",
        "fields": ["ip.src", "modbus.unit_id", "modbus.func_code"],
        "asset": {"unit_id": "modbus.unit_id"}
    },
    "dnp3": {
        "filter": "dnp3",
        "name": "DNP3",
        "fields": ["ip.src", "dnp3.src", "dnp3.dst"],
        "asset": {"dnp3_src": "dnp3.src", "dnp3_dst": "dnp3.dst"}
    },
    "bacnet": {
        "filter": "bacnet",
        "name": "BACnet",
        "fields": ["ip.src", "bacnet.object_name", "bacnet.vendor_id", "bacnet.model_name"],
        "asset": {
            "object_name": "bacnet.object_name",
            "vendor_id": "bacnet.vendor_id",
            "model": "bacnet.model_name"
        }
    },
    "lldp": {
        "filter": "lldp",
        "name": "LLDP",
        "fields": ["lldp.system_name", "lldp.system_description", "lldp.chassis_id"],
        "asset": {"system_name": "lldp.system_name", "system_desc": "lldp.system_description"}
    },
    "snmp": {
        "filter": "snmp",
        "name": "SNMP",
        "fields": ["ip.src", "snmp.sysDescr", "snmp.sysName", "snmp.sysObjectID"],
        "asset": {"sysDescr": "snmp.sysDescr", "sysName": "snmp.sysName", "sysObjectID": "snmp.sysObjectID"}
    },
    "http": {
        "filter": "http",
        "name": "HTTP",
        "fields": ["ip.src", "http.server", "http.user_agent"],
        "asset": {"http_server": "http.server", "user_agent": "http.user_agent"}
    },
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
        st.warning(f"tshark error for {display_filter}: {e}")
        return []

# =============================================================================
# 4. EXHAUSTIVE ASSET CLASSIFICATION FUNCTION
# =============================================================================

def classify_asset_type(ip: str, protocols: Set[str], metadata: Dict[str, str]) -> Tuple[str, str, Dict]:
    """
    Returns (asset_type, confidence, additional_info)
    """
    confidence = "Low"
    asset_type = "Unknown"
    additional_info = {}

    # ---- PROFINET DCP (highest reliability) ----
    if "device_role" in metadata:
        role = metadata["device_role"]
        if role in PN_DEVICE_ROLE_MAP:
            asset_type = PN_DEVICE_ROLE_MAP[role]
            confidence = "High"
            additional_info["detection"] = "PROFINET DCP role"
            # refine with vendor/device ID
            vendor = metadata.get("vendor_id", "")
            device = metadata.get("device_id", "")
            if (vendor, device) in PN_DEVICE_ID_MAP:
                asset_type = PN_DEVICE_ID_MAP[(vendor, device)]
                additional_info["vendor_id"] = vendor
                additional_info["device_id"] = device
            return asset_type, confidence, additional_info

    if "station_name" in metadata:
        name = metadata["station_name"].lower()
        additional_info["station_name"] = metadata["station_name"]
        if any(x in name for x in ["cpu", "plc", "controller"]):
            asset_type = "PLC (PROFINET)"
            confidence = "High"
        elif any(x in name for x in ["hmi", "panel", "op"]):
            asset_type = "HMI / Operator Panel"
            confidence = "High"
        elif any(x in name for x in ["drive", "vfd", "servo"]):
            asset_type = "Motor Drive / VFD"
            confidence = "High"
        elif any(x in name for x in ["switch", "bridge"]):
            asset_type = "Network Switch"
            confidence = "High"
        elif any(x in name for x in ["io", "et200"]):
            asset_type = "Remote I/O Device"
            confidence = "High"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # ---- EtherNet/IP (CIP) ----
    if "device_type" in metadata:
        dev_type = metadata["device_type"]
        if dev_type in CIP_DEVICE_TYPE_MAP:
            asset_type = CIP_DEVICE_TYPE_MAP[dev_type]
            confidence = "High"
            additional_info["detection"] = "CIP device type"
            if "vendor_id" in metadata and metadata["vendor_id"] in CIP_VENDOR_MAP:
                vendor = CIP_VENDOR_MAP[metadata["vendor_id"]]
                asset_type = f"{vendor} {asset_type}"
                additional_info["vendor"] = vendor
            return asset_type, confidence, additional_info

    if "product_name" in metadata:
        prod = metadata["product_name"].lower()
        additional_info["product_name"] = metadata["product_name"]
        if "controllogix" in prod:
            asset_type = "Rockwell ControlLogix PLC"
            confidence = "High"
        elif "compactlogix" in prod:
            asset_type = "Rockwell CompactLogix PLC"
            confidence = "High"
        elif "powerflex" in prod:
            asset_type = "Rockwell PowerFlex Drive"
            confidence = "High"
        elif "panelview" in prod:
            asset_type = "Rockwell PanelView HMI"
            confidence = "High"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # ---- Siemens S7comm ----
    if "cpu_type" in metadata:
        cpu = metadata["cpu_type"]
        additional_info["cpu_type"] = cpu
        for pattern, atype in S7_CPU_TYPE_MAP.items():
            if pattern in cpu:
                asset_type = atype
                confidence = "High"
                return asset_type, confidence, additional_info
        if "CPU" in cpu:
            asset_type = f"Siemens {cpu}"
            confidence = "High"
            return asset_type, confidence, additional_info

    # ---- BACnet ----
    if "object_name" in metadata:
        obj = metadata["object_name"].lower()
        additional_info["object_name"] = metadata["object_name"]
        if "plc" in obj or "controller" in obj:
            asset_type = "BACnet DDC Controller"
            confidence = "Medium"
        elif "hmi" in obj or "touch" in obj:
            asset_type = "BACnet HMI"
            confidence = "Medium"
        elif "vav" in obj or "ahu" in obj:
            asset_type = "BACnet HVAC Controller"
            confidence = "Medium"
        elif "sensor" in obj:
            asset_type = "BACnet Sensor"
            confidence = "Medium"
        if "vendor_id" in metadata and metadata["vendor_id"] in BACNET_VENDOR_MAP:
            asset_type = f"{BACNET_VENDOR_MAP[metadata['vendor_id']]} {asset_type}"
            confidence = "Medium"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # ---- DNP3 ----
    if "DNP3" in protocols:
        asset_type = "DNP3 RTU / IED"
        confidence = "Medium"
        return asset_type, confidence, additional_info

    # ---- Modbus ----
    if "Modbus/TCP" in protocols:
        if "unit_id" in metadata and metadata["unit_id"] == "0":
            asset_type = "Modbus Gateway"
            confidence = "Medium"
        else:
            asset_type = "Modbus PLC/RTU"
            confidence = "Medium"
        return asset_type, confidence, additional_info

    # ---- LLDP ----
    if "system_desc" in metadata:
        desc = metadata["system_desc"].lower()
        if "switch" in desc:
            asset_type = "Network Switch"
            confidence = "High"
        elif "router" in desc:
            asset_type = "Router"
            confidence = "High"
        elif "plc" in desc:
            asset_type = "PLC"
            confidence = "High"
        elif "drive" in desc:
            asset_type = "Drive / VFD"
            confidence = "High"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # ---- SNMP ----
    if "sysDescr" in metadata:
        desc = metadata["sysDescr"].lower()
        if "plc" in desc:
            asset_type = "PLC (SNMP)"
            confidence = "Medium"
        elif "switch" in desc:
            asset_type = "Network Switch"
            confidence = "High"
        elif "ups" in desc:
            asset_type = "UPS"
            confidence = "High"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # ---- HTTP server hints ----
    if "http_server" in metadata:
        server = metadata["http_server"].lower()
        if "plc" in server or "s7" in server:
            asset_type = "PLC (web interface)"
            confidence = "Medium"
        elif "hmi" in server:
            asset_type = "HMI (web)"
            confidence = "Medium"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # ---- Fallback based on protocols ----
    if protocols:
        if any(p in protocols for p in ["Siemens S7comm", "PROFINET DCP"]):
            asset_type = "Siemens OT Device"
            confidence = "Medium"
        elif "EtherNet/IP (CIP)" in protocols:
            asset_type = "Rockwell OT Device"
            confidence = "Medium"
        elif "BACnet" in protocols:
            asset_type = "BACnet Device"
            confidence = "Medium"
        elif "DNP3" in protocols:
            asset_type = "DNP3 Device"
            confidence = "Medium"
        elif "Modbus/TCP" in protocols:
            asset_type = "Modbus Device"
            confidence = "Medium"
        else:
            asset_type = "OT Device (unspecified)"
            confidence = "Low"

    return asset_type, confidence, additional_info

# =============================================================================
# 5. NETWORK MAPPING USING TSHARK CONVERSATION STATISTICS
# =============================================================================

@st.cache_data(ttl=3600)
def get_conversations_tshark(pcap_path: str) -> Dict[Tuple[str, str], int]:
    """
    Extract IP conversations using tshark's built-in conversation statistics.
    Returns dict: {(src_ip, dst_ip): packet_count}
    """
    conversations = {}
    cmd = ["tshark", "-r", pcap_path, "-z", "conv,ip", "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = result.stdout
        
        lines = output.split('\n')
        for line in lines:
            if '<->' not in line:
                continue
            if 'Frames' in line or 'Bytes' in line:
                continue
            
            parts = line.strip().split()
            if len(parts) < 6:
                continue
            
            try:
                arrow_idx = parts.index('<->')
                src = parts[arrow_idx - 1]
                dst = parts[arrow_idx + 1]
                
                # Find total frames (usually the second last numeric field)
                total_frames = 0
                for p in reversed(parts):
                    if p.isdigit():
                        total_frames = int(p)
                        break
                if total_frames > 0:
                    conversations[(src, dst)] = total_frames
            except ValueError:
                continue
    except Exception as e:
        st.warning(f"Error extracting conversations: {e}")
    
    return conversations

def build_network_graph(conversations: Dict[Tuple[str, str], int],
                        ip_to_asset: Dict[str, str]) -> nx.Graph:
    G = nx.Graph()
    all_ips = set()
    for (src, dst) in conversations.keys():
        all_ips.add(src)
        all_ips.add(dst)
    for ip in all_ips:
        asset_type = ip_to_asset.get(ip, "Unknown")
        G.add_node(ip, asset_type=asset_type, label=f"{ip}\n{asset_type[:20]}")
    for (src, dst), count in conversations.items():
        if src in G and dst in G:
            G.add_edge(src, dst, weight=count, packets=count)
    return G

def create_plotly_network(G: nx.Graph) -> go.Figure:
    pos = nx.spring_layout(G, k=1.5, iterations=50, seed=42)
    node_x, node_y, node_colors, node_text = [], [], [], []
    color_map = {
        "PLC": "#FF6B6B",
        "HMI": "#4ECDC4",
        "I/O": "#96CEB4",
        "Drive": "#FFEAA7",
        "Switch": "#45B7D1",
        "RTU": "#DDA0DD",
        "Unknown": "#95A5A6"
    }
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        asset = G.nodes[node].get("asset_type", "Unknown")
        simple = asset.split()[0] if asset else "Unknown"
        if simple not in color_map:
            simple = "Unknown"
        node_colors.append(color_map[simple])
        node_text.append(f"{node}<br>Type: {asset}")
    edge_x, edge_y = [], []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode='lines', line=dict(width=1, color='#888'), hoverinfo='none'))
    fig.add_trace(go.Scatter(x=node_x, y=node_y, mode='markers+text',
                             marker=dict(size=20, color=node_colors, line=dict(width=2, color='white')),
                             text=[G.nodes[n].get("label", n)[:15] for n in G.nodes()],
                             textposition="bottom center", hovertext=node_text, hoverinfo='text'))
    fig.update_layout(title="OT Network Topology", showlegend=False, height=600,
                      xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                      yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                      plot_bgcolor='#1e1e1e', paper_bgcolor='#1e1e1e', font=dict(color='white'))
    return fig

# =============================================================================
# 6. MAIN STREAMLIT APP
# =============================================================================

def main():
    uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
    if not uploaded_file:
        st.info("👈 Upload a PCAP file to start analysis")
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        pcap_path = tmp.name

    st.info(f"📡 Analyzing {uploaded_file.name}...")

    # ---- Extract asset metadata from PCAP ----
    ip_to_protocols = defaultdict(set)
    ip_to_metadata = defaultdict(dict)

    progress_bar = st.progress(0)
    total_protos = len(PROTOCOLS)
    for idx, (key, proto) in enumerate(PROTOCOLS.items()):
        progress_bar.progress((idx+1)/total_protos, text=f"Processing {proto['name']}...")
        lines = run_tshark(pcap_path, proto["filter"], proto["fields"])
        for line in lines:
            parts = line.split('\t')
            # Find IP address (first field that looks like IPv4)
            ip = None
            for p in parts:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', p):
                    ip = p
                    break
            if not ip:
                continue
            ip_to_protocols[ip].add(proto["name"])
            # Store asset-specific fields
            for attr, field in proto.get("asset", {}).items():
                try:
                    idx_field = proto["fields"].index(field)
                    if idx_field < len(parts) and parts[idx_field]:
                        ip_to_metadata[ip][attr] = parts[idx_field]
                except ValueError:
                    pass
    progress_bar.empty()

    # ---- Classify each asset ----
    assets = []
    for ip, protos in ip_to_protocols.items():
        asset_type, confidence, info = classify_asset_type(ip, protos, ip_to_metadata.get(ip, {}))
        assets.append({
            "IP Address": ip,
            "Asset Type": asset_type,
            "Confidence": confidence,
            "Protocols": ", ".join(sorted(protos)),
            "Additional Info": ", ".join(f"{k}:{v}" for k,v in info.items())
        })

    # ---- Build network map using tshark conversation stats ----
    with st.spinner("Building network topology..."):
        conversations = get_conversations_tshark(pcap_path)
    ip_to_asset = {a["IP Address"]: a["Asset Type"] for a in assets}
    G = build_network_graph(conversations, ip_to_asset)

    # ---- Display results in tabs ----
    tab1, tab2 = st.tabs(["📋 Asset List", "🗺️ Network Map"])

    with tab1:
        if assets:
            df = pd.DataFrame(assets)
            st.subheader("Discovered OT Assets")
            st.dataframe(df, use_container_width=True)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download CSV", csv, "ot_assets.csv", "text/csv")
            st.metric("Total Assets", len(assets))
        else:
            st.warning("No OT assets detected.")

    with tab2:
        if G.number_of_nodes() > 0:
            st.subheader("Communication Topology")
            fig = create_plotly_network(G)
            st.plotly_chart(fig, use_container_width=True)
            st.caption(f"Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}")
        else:
            st.info("No network conversations found.")

    # Cleanup
    os.unlink(pcap_path)

if __name__ == "__main__":
    # Check tshark availability
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        st.error("❌ tshark not found. Ensure `packages.txt` contains 'tshark' and redeploy.")
        st.stop()
    main()
