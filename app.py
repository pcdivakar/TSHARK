"""
OT/IT Asset Discovery – CyberMesh OT/IT Analyzer
- Exhaustive protocol detection (OT & IT) using tshark
- MAC OUI & vendor ID lookups
- Professional vis-network topology (draggable, zoomable, full-screen)
- Dark theme with cyan/teal accents
"""

import streamlit as st
import subprocess
import tempfile
import os
import re
import pandas as pd
import json
import networkx as nx
from collections import defaultdict

# =============================================================================
# PAGE CONFIG & PROFESSIONAL DARK THEME
# =============================================================================
st.set_page_config(page_title="CyberMesh OT/IT Analyzer", layout="wide", page_icon="🔍")

# Custom CSS for professional dark theme (cyan/teal accents)
st.markdown("""
<style>
    /* Global background */
    .stApp {
        background-color: #0b0f1c !important;
    }
    /* All text – ensure visibility */
    body, p, div, span, label, .stText, .stMarkdown, .stAlert, .stException,
    .stCodeBlock, code, pre, .stExpander, .stExpander p, .stExpander div {
        color: #e2e8f0 !important;
    }
    /* Headers */
    h1, h2, h3, h4, h5, h6, .stHeader {
        color: #2dd4bf !important;
        font-weight: 600 !important;
    }
    /* Sidebar */
    .css-1d391kg, .stSidebar {
        background-color: #0a0e1a !important;
    }
    /* Tabs at top */
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
        background-color: #111827;
        padding: 10px 20px;
        border-radius: 12px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        color: #e2e8f0 !important;
        font-weight: bold;
        font-size: 16px;
        border-radius: 8px;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #2dd4bf !important;
        color: #0b0f1c !important;
    }
    /* Dataframe */
    .dataframe, .stDataFrame {
        background-color: #111827 !important;
        color: #e2e8f0 !important;
        border-collapse: collapse;
        width: 100%;
    }
    .dataframe th, .stDataFrame th {
        background-color: #1e2a3a !important;
        color: #2dd4bf !important;
        border: 1px solid #2d3748;
        padding: 8px;
    }
    .dataframe td, .stDataFrame td {
        border: 1px solid #2d3748;
        padding: 8px;
        color: #e2e8f0;
    }
    /* Metric boxes */
    .stMetric {
        background-color: #111827 !important;
        border-radius: 12px;
        padding: 12px;
        border-left: 4px solid #2dd4bf;
    }
    .stMetric label, .stMetric .stMetricLabel {
        color: #2dd4bf !important;
    }
    .stMetric .stMetricValue {
        color: #ffffff !important;
        font-size: 28px !important;
        font-weight: bold;
    }
    /* Expander */
    .streamlit-expanderHeader {
        background-color: #111827 !important;
        color: #2dd4bf !important;
        border-radius: 8px;
    }
    .streamlit-expanderContent {
        background-color: #0b0f1c !important;
        color: #e2e8f0 !important;
    }
    /* Info / Success / Warning boxes */
    .stAlert {
        background-color: #111827 !important;
        border-left: 4px solid #2dd4bf !important;
        color: #e2e8f0 !important;
    }
    .stAlert .stMarkdown {
        color: #e2e8f0 !important;
    }
    /* Buttons */
    .stButton button {
        background-color: #2dd4bf !important;
        color: #0b0f1c !important;
        border: none;
        border-radius: 8px;
        padding: 8px 16px;
        font-weight: bold;
    }
    .stButton button:hover {
        background-color: #14b8a6 !important;
        color: #0b0f1c;
    }
    /* File uploader */
    .stFileUploader {
        background-color: #111827 !important;
        border: 1px dashed #2dd4bf !important;
        border-radius: 8px;
    }
    /* Code blocks */
    code, pre {
        background-color: #1e2a3a !important;
        color: #2dd4bf !important;
        border-radius: 6px;
    }
    /* Text input */
    .stTextInput input {
        background-color: #1e2a3a !important;
        color: #e2e8f0 !important;
        border: 1px solid #2dd4bf !important;
        border-radius: 8px;
    }
    /* Success message */
    .stSuccess {
        background-color: #0a2a2a !important;
        border-left-color: #2dd4bf !important;
        color: #e2e8f0 !important;
    }
    /* Error message */
    .stError {
        background-color: #2a1a1a !important;
        border-left-color: #f87171 !important;
        color: #e2e8f0 !important;
    }
    /* Info message */
    .stInfo {
        background-color: #1a2a3a !important;
        border-left-color: #2dd4bf !important;
        color: #e2e8f0 !important;
    }
    /* Captions and small text */
    .stCaption, .stSmallText {
        color: #94a3b8 !important;
    }
</style>
""", unsafe_allow_html=True)

# Optional logo – replace with your own if desired
# st.image("logo.png", width=150)

st.title("🔍 CyberMesh OT/IT Analyzer")
st.markdown("*Exhaustive asset discovery and network mapping for industrial control systems*")

# =============================================================================
# EXHAUSTIVE CONFIGURATION
# =============================================================================
DEBUG = False  # Set to True for detailed tshark command output

# ---------- OT Ports (standard + common non-standard) ----------
KNOWN_OT_PORTS = {
    102: "S7comm", 502: "Modbus", 20000: "DNP3", 44818: "EtherNet/IP",
    2222: "EtherNet/IP", 47808: "BACnet", 2404: "IEC104", 34964: "PROFINET",
    4840: "OPC UA", 9600: "Omron FINS", 5000: "Mitsubishi", 5001: "Mitsubishi",
    5002: "Mitsubishi", 5006: "Mitsubishi", 5007: "Mitsubishi", 5500: "Mitsubishi",
    6000: "Mitsubishi", 10000: "Generic OT", 20000: "DNP3", 20547: "Profinet",
}

# ---------- IT Ports ----------
KNOWN_IT_PORTS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 67: "DHCP", 68: "DHCP",
    161: "SNMP", 162: "SNMP", 22: "SSH", 23: "Telnet", 21: "FTP",
    445: "SMB", 139: "SMB", 123: "NTP", 25: "SMTP", 110: "POP3",
    143: "IMAP", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL",
}

# ---------- Protocol Detectors (exhaustive) ----------
PROTOCOL_DETECTORS = [
    # OT Protocols
    {"filter": "s7comm", "name": "Siemens S7comm", "category": "OT",
     "fields": ["ip.src", "s7comm.cpu_type", "s7comm.module_type", "s7comm.identity_serial_number_of_module"]},
    {"filter": "modbus", "name": "Modbus/TCP", "category": "OT",
     "fields": ["ip.src", "modbus.unit_id", "modbus.func_code"]},
    {"filter": "dnp3", "name": "DNP3", "category": "OT",
     "fields": ["ip.src", "dnp3.src", "dnp3.dst", "dnp3.object_header"]},
    {"filter": "cip", "name": "EtherNet/IP (CIP)", "category": "OT",
     "fields": ["ip.src", "cip.vendor_id", "cip.product_name", "cip.serial_number", "cip.device_type"]},
    {"filter": "bacnet", "name": "BACnet", "category": "OT",
     "fields": ["ip.src", "bacnet.object_name", "bacnet.vendor_id", "bacnet.model_name", "bacnet.firmware_revision"]},
    {"filter": "pn_dcp", "name": "PROFINET DCP", "category": "OT",
     "fields": ["pn_dcp.station_name", "pn_dcp.ip_address", "pn_dcp.device_role", "pn_dcp.vendor_id", "pn_dcp.device_id"]},
    {"filter": "iec104", "name": "IEC 60870-5-104", "category": "OT",
     "fields": ["ip.src", "iec104.asdu_type", "iec104.cot"]},
    {"filter": "opcua", "name": "OPC UA", "category": "OT",
     "fields": ["ip.src", "opcua.ServerUris", "opcua.NamespaceArray"]},
    {"filter": "profinet", "name": "PROFINET IO", "category": "OT",
     "fields": ["ip.src", "pn_io.slot", "pn_io.subslot"]},
    {"filter": "hartip", "name": "HART-IP", "category": "OT",
     "fields": ["ip.src", "hartip.device_id", "hartip.manufacturer_id"]},
    {"filter": "fins", "name": "FINS (Omron)", "category": "OT",
     "fields": ["ip.src", "fins.da", "fins.sa"]},
    {"filter": "melsec", "name": "Melsec (Mitsubishi)", "category": "OT",
     "fields": ["ip.src", "melsec.plc_type", "melsec.station"]},
    # IT Protocols
    {"filter": "http", "name": "HTTP", "category": "IT",
     "fields": ["ip.src", "http.host", "http.user_agent", "http.server"]},
    {"filter": "tls.handshake", "name": "HTTPS/TLS", "category": "IT",
     "fields": ["ip.src", "tls.handshake.extensions_server_name"]},
    {"filter": "dns", "name": "DNS", "category": "IT",
     "fields": ["ip.src", "dns.qry.name", "dns.resp.name"]},
    {"filter": "dhcp", "name": "DHCP", "category": "IT",
     "fields": ["ip.src", "dhcp.option.hostname", "dhcp.option.vendor_class"]},
    {"filter": "snmp", "name": "SNMP", "category": "IT",
     "fields": ["ip.src", "snmp.sysDescr", "snmp.sysName", "snmp.sysObjectID"]},
    {"filter": "ssh", "name": "SSH", "category": "IT",
     "fields": ["ip.src", "ssh.server.version"]},
    {"filter": "telnet", "name": "Telnet", "category": "IT",
     "fields": ["ip.src", "telnet.subnegotiation"]},
    {"filter": "ftp", "name": "FTP", "category": "IT",
     "fields": ["ip.src", "ftp.request.command"]},
    {"filter": "smb", "name": "SMB/CIFS", "category": "IT",
     "fields": ["ip.src", "smb.dialect", "smb.server_component"]},
    {"filter": "ntp", "name": "NTP", "category": "IT",
     "fields": ["ip.src", "ntp.ref_id", "ntp.stratum"]},
    {"filter": "lldp", "name": "LLDP", "category": "IT",
     "fields": ["lldp.system_name", "lldp.system_description"]},
]

# ---------- MAC OUI Database (exhaustive) ----------
OUI_DB = {
    # Virtual / Hypervisors
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V", "00:16:3E": "Xensource",
    # Networking
    "00:1C:42": "Cisco", "00:0F:FE": "Huawei", "00:0D:4B": "Phoenix Contact",
    "00:1B:21": "Rockwell Automation", "00:0A:35": "Schneider Electric",
    # Industrial
    "00:0F:9F": "Siemens", "00:0E:8F": "ABB", "00:1E:37": "Mitsubishi Electric",
    "00:0E:6B": "Omron", "00:80:F4": "GE Fanuc", "00:1F:45": "Beckhoff",
    "00:30:48": "WAGO", "00:02:68": "Hirschmann", "00:04:A3": "Moxa",
    # General IT
    "00:14:22": "Dell", "00:1A:6B": "HP", "B8:27:EB": "Raspberry Pi",
    "00:25:9C": "Apple", "00:0C:F1": "Samsung", "00:1E:EC": "Intel",
    # More
    "00:0A:E4": "SMC", "00:0B:CD": "Honeywell", "00:0C:41": "Yokogawa",
    "00:10:FA": "Eaton", "00:20:4A": "Rockwell", "00:50:C2": "Siemens",
}

# ---------- CIP Vendor ID Map (EtherNet/IP) ----------
CIP_VENDOR_MAP = {
    "1": "Rockwell Automation", "2": "Schneider Electric", "3": "Siemens",
    "4": "ABB", "5": "Honeywell", "6": "Emerson", "7": "Yokogawa",
    "8": "Mitsubishi Electric", "9": "Omron", "10": "Keyence",
    "11": "Panasonic", "12": "Fuji Electric", "13": "Hitachi",
    "14": "Toshiba", "15": "Eaton", "16": "Parker Hannifin",
    "17": "Bosch Rexroth", "18": "Beckhoff", "19": "B&R Automation",
    "20": "Phoenix Contact", "21": "WAGO", "22": "Turck",
    "23": "Ifm Electronic", "24": "Balluff", "25": "Pepperl+Fuchs",
    "44": "Schneider Electric (Telemechanique)", "57": "Siemens",
    "111": "Phoenix Contact",
}

# ---------- PROFINET Vendor ID Map ----------
PN_VENDOR_MAP = {
    "002a": "Siemens", "001b": "Rockwell Automation", "005a": "Schneider Electric",
    "001c": "ABB", "006f": "Phoenix Contact", "0060": "Bosch Rexroth",
    "0078": "B&R Automation", "003c": "Mitsubishi Electric", "003d": "Omron",
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
def run_tshark(pcap_path, display_filter, fields, decode_as=None):
    cmd = ["tshark", "-r", pcap_path]
    if decode_as:
        cmd.extend(["-d", decode_as])
    if display_filter:
        cmd.extend(["-Y", display_filter])
    cmd.extend(["-T", "fields"])
    for f in fields:
        cmd.extend(["-e", f])
    if not DEBUG:
        cmd.append("-q")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout.strip().splitlines() if result.stdout else [], None
    except Exception as e:
        return [], str(e)

def detect_ips_by_ports(pcap_path, port_map):
    ips = set()
    for port in port_map.keys():
        cmd = ["tshark", "-r", pcap_path, "-Y", f"tcp.port=={port} or udp.port=={port}",
               "-T", "fields", "-e", "ip.src", "-e", "ip.dst"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            for line in result.stdout.split('\n'):
                for ip in line.split():
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        ips.add(ip)
        except:
            pass
    return ips

def detect_ips_by_protocol_string(pcap_path):
    ot_keywords = ['s7comm', 'modbus', 'dnp3', 'cip', 'bacnet', 'profinet', 'iec104', 'opcua', 'hartip', 'fins', 'melsec']
    it_keywords = ['http', 'dns', 'dhcp', 'snmp', 'ssh', 'telnet', 'ftp', 'smb', 'ntp', 'lldp']
    keywords = ot_keywords + it_keywords
    ips = set()
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "ip.src", "-e", "frame.protocols"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        for line in result.stdout.split('\n'):
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) >= 2:
                ip = parts[0]
                protocols = parts[1].lower()
                if any(kw in protocols for kw in keywords):
                    ips.add(ip)
    except:
        pass
    return ips

def extract_macs(pcap_path):
    ip_to_mac = {}
    # ARP
    cmd = ["tshark", "-r", pcap_path, "-Y", "arp", "-T", "fields", "-e", "arp.src.proto_ipv4", "-e", "arp.src.hw_mac"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        for line in result.stdout.split('\n'):
            if line and '\t' in line:
                parts = line.split('\t')
                if len(parts) >= 2 and parts[0] and parts[1]:
                    ip_to_mac[parts[0]] = parts[1]
    except:
        pass
    # Ethernet + IP
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "ip.src", "-e", "eth.src"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        for line in result.stdout.split('\n'):
            if line and '\t' in line:
                parts = line.split('\t')
                if len(parts) >= 2 and parts[0] and parts[1]:
                    if parts[0] not in ip_to_mac:
                        ip_to_mac[parts[0]] = parts[1]
    except:
        pass
    return ip_to_mac

def extract_assets(pcap_path, custom_decode_ports):
    ip_data = defaultdict(lambda: {
        "protocols": set(), "category": set(), "metadata": {}, "packet_count": 0
    })
    ot_port_ips = detect_ips_by_ports(pcap_path, KNOWN_OT_PORTS)
    it_port_ips = detect_ips_by_ports(pcap_path, KNOWN_IT_PORTS)
    string_ips = detect_ips_by_protocol_string(pcap_path)
    candidate_ips = ot_port_ips.union(it_port_ips, string_ips)
    if not candidate_ips:
        return ip_data

    # Ports to try decode-as (common non-standard)
    ports_to_decode = [5000, 5001, 5002, 5006, 5007, 5500, 6000, 9600, 10000, 20000, 34964]
    if custom_decode_ports:
        ports_to_decode.extend(custom_decode_ports)

    for det in PROTOCOL_DETECTORS:
        lines, _ = run_tshark(pcap_path, det["filter"], det["fields"])
        if not lines:
            for port in ports_to_decode:
                decode_str = f"tcp.port=={port},{det['filter']}"
                lines, _ = run_tshark(pcap_path, det["filter"], det["fields"], decode_str)
                if lines:
                    break
        for line in lines:
            parts = line.split('\t')
            ip = None
            for p in parts:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', p):
                    ip = p
                    break
            if not ip or ip not in candidate_ips:
                continue
            ip_data[ip]["protocols"].add(det["name"])
            ip_data[ip]["category"].add(det["category"])
            ip_data[ip]["packet_count"] += 1
            for i, field in enumerate(det["fields"]):
                if i < len(parts) and parts[i] and field != "ip.src":
                    ip_data[ip]["metadata"][field.replace(".", "_")] = parts[i]
    # Fallback
    for ip in candidate_ips:
        if not ip_data[ip]["protocols"]:
            ip_data[ip]["protocols"].add("Unknown (detected by port)")
            ip_data[ip]["category"].add("Unknown")
    return ip_data

def get_vendor(metadata, mac):
    # MAC OUI first
    if mac and mac != "Unknown":
        vendor = get_vendor_from_mac(mac)
        if vendor != "Unknown":
            return vendor
    # CIP vendor ID
    if "cip_vendor_id" in metadata and metadata["cip_vendor_id"] in CIP_VENDOR_MAP:
        return CIP_VENDOR_MAP[metadata["cip_vendor_id"]]
    # PROFINET vendor ID
    if "pn_dcp_vendor_id" in metadata and metadata["pn_dcp_vendor_id"] in PN_VENDOR_MAP:
        return PN_VENDOR_MAP[metadata["pn_dcp_vendor_id"]]
    # BACnet vendor ID
    if "bacnet_vendor_id" in metadata:
        bacnet_vendors = {"8": "Johnson Controls", "24": "Siemens", "38": "Honeywell", "122": "Schneider Electric"}
        if metadata["bacnet_vendor_id"] in bacnet_vendors:
            return bacnet_vendors[metadata["bacnet_vendor_id"]]
    # HTTP server header
    if "http_server" in metadata:
        server = metadata["http_server"].lower()
        if "apache" in server:
            return "Apache"
        if "nginx" in server:
            return "Nginx"
        if "iis" in server:
            return "Microsoft IIS"
    # SNMP sysDescr
    if "sysDescr" in metadata:
        desc = metadata["sysDescr"].lower()
        if "cisco" in desc:
            return "Cisco"
        if "linux" in desc:
            return "Linux"
        if "windows" in desc:
            return "Windows"
    return "Unknown"

def get_vendor_from_mac(mac):
    if not mac or mac == "Unknown":
        return "Unknown"
    mac_upper = mac.upper()
    for prefix, vendor in OUI_DB.items():
        if mac_upper.startswith(prefix.upper()):
            return vendor
    return "Unknown"

def get_model(metadata):
    return (metadata.get("cip_product_name") or metadata.get("bacnet_model_name") or
            metadata.get("s7comm_cpu_type") or metadata.get("pn_dcp_station_name") or
            metadata.get("http_server") or "Unknown")

def get_conversations(pcap_path):
    conv = {}
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
                arrow = parts.index('<->')
                src = parts[arrow-1]
                dst = parts[arrow+1]
                for p in reversed(parts):
                    if p.isdigit():
                        conv[(src, dst)] = int(p)
                        break
            except ValueError:
                continue
    except Exception as e:
        st.warning(f"Conversation error: {e}")
    return conv

def generate_vis_network(nodes_data, edges_data):
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>CyberMesh Network Topology</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
        <style>
            html, body, #network {{
                margin: 0;
                padding: 0;
                width: 100%;
                height: 100%;
                background-color: #0b0f1c;
            }}
            .controls {{
                position: absolute;
                bottom: 20px;
                right: 20px;
                background: rgba(0,0,0,0.8);
                padding: 8px 15px;
                border-radius: 8px;
                color: #2dd4bf;
                font-size: 12px;
                font-family: monospace;
                z-index: 100;
                backdrop-filter: blur(5px);
                border-left: 3px solid #2dd4bf;
            }}
        </style>
    </head>
    <body>
        <div id="network"></div>
        <div class="controls">
            🖱️ Drag nodes | 🔍 Scroll zoom | ⬜ Double‑click fullscreen | 🎨 OT=#e74c3c, IT=#3498db, Unknown=#95a5a6
        </div>
        <script>
            var nodes = new vis.DataSet({json.dumps(nodes_data)});
            var edges = new vis.DataSet({json.dumps(edges_data)});
            var container = document.getElementById('network');
            var data = {{nodes: nodes, edges: edges}};
            var options = {{
                nodes: {{
                    font: {{color: 'white', size: 14, face: 'Arial'}},
                    borderWidth: 2,
                    shadow: {{enabled: true, color: 'rgba(0,0,0,0.5)'}},
                    shape: 'dot',
                    size: 25
                }},
                edges: {{
                    smooth: {{type: 'continuous', roundness: 0.5}},
                    color: {{color: '#2dd4bf', highlight: '#ffffff'}},
                    width: 2,
                    arrows: {{to: {{enabled: false}}}}
                }},
                physics: {{
                    enabled: true,
                    solver: 'hierarchicalRepulsion',
                    hierarchicalRepulsion: {{nodeDistance: 180, centralGravity: 0.3, springLength: 200}},
                    stabilization: {{iterations: 300, fit: true}}
                }},
                layout: {{
                    hierarchical: {{
                        enabled: true,
                        levelSeparation: 180,
                        nodeSpacing: 150,
                        direction: 'UD',
                        sortMethod: 'directed'
                    }}
                }},
                interaction: {{
                    dragNodes: true,
                    dragView: true,
                    zoomView: true,
                    hover: true,
                    tooltipDelay: 100
                }}
            }};
            var network = new vis.Network(container, data, options);
            network.on('doubleClick', function() {{
                if (document.fullscreenElement) document.exitFullscreen();
                else document.documentElement.requestFullscreen();
            }});
        </script>
    </body>
    </html>
    """
    return html

# =============================================================================
# MAIN APP
# =============================================================================
def main():
    uploaded = st.file_uploader("📁 Choose a PCAP file", type=["pcap", "pcapng"])
    if not uploaded:
        st.info("👈 Upload a PCAP file to begin analysis")
        with st.expander("ℹ️ How to verify your PCAP locally"):
            st.code("""
# Show all protocols
tshark -r your.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn | head -20
# Show used TCP ports
tshark -r your.pcap -T fields -e tcp.port | sort | uniq -c | sort -rn
""", language="bash")
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded.getbuffer())
        pcap_path = tmp.name

    st.info(f"📡 Analyzing {uploaded.name}... This may take a moment.")

    custom_ports_input = st.text_input(
        "Optional: additional TCP ports to decode as OT protocols (comma separated)",
        placeholder="e.g., 5500,6000,10000"
    )
    custom_ports = []
    if custom_ports_input:
        try:
            custom_ports = [int(p.strip()) for p in custom_ports_input.split(",") if p.strip().isdigit()]
        except:
            st.warning("Invalid port list, ignoring.")

    ip_data = extract_assets(pcap_path, custom_ports)
    ip_to_mac = extract_macs(pcap_path)

    assets = []
    for ip, data in ip_data.items():
        mac = ip_to_mac.get(ip, "Unknown")
        vendor = get_vendor(data["metadata"], mac)
        model = get_model(data["metadata"])
        asset = {
            "IP Address": ip,
            "MAC Address": mac,
            "Vendor": vendor,
            "Model": model,
            "Asset Type": next(iter(data["protocols"])) if data["protocols"] else "Unknown",
            "Category": ", ".join(data["category"]) if data["category"] else "Unknown",
            "Hostname": data["metadata"].get("dhcp_option_hostname") or data["metadata"].get("dns_qry_name") or "",
            "OS / Service": data["metadata"].get("sysDescr", "")[:60] or data["metadata"].get("http_server", "")[:60],
            "Protocols": ", ".join(data["protocols"]),
            "Packet Count": data["packet_count"]
        }
        assets.append(asset)

    conversations = get_conversations(pcap_path)
    G = nx.Graph()
    for a in assets:
        G.add_node(a["IP Address"])
    ip_set = {a["IP Address"] for a in assets}
    for (src, dst), cnt in conversations.items():
        if src in ip_set and dst in ip_set:
            G.add_edge(src, dst, weight=cnt)

    nodes_vis = []
    for ip, data in ip_data.items():
        category = "OT" if "OT" in data["category"] else ("IT" if "IT" in data["category"] else "Unknown")
        color = "#e74c3c" if category == "OT" else ("#3498db" if category == "IT" else "#95a5a6")
        mac = ip_to_mac.get(ip, "Unknown")
        vendor = get_vendor(data["metadata"], mac)
        title = f"<b>{ip}</b><br>Type: {', '.join(data['protocols'])}<br>MAC: {mac}<br>Vendor: {vendor}"
        nodes_vis.append({"id": ip, "label": ip, "title": title, "color": color, "category": category})
    edges_vis = []
    for (src, dst), cnt in conversations.items():
        if src in ip_set and dst in ip_set:
            edges_vis.append({"from": src, "to": dst, "value": cnt, "title": f"Packets: {cnt}"})

    tab1, tab2 = st.tabs(["📋 Asset Inventory", "🗺️ Network Topology"])

    with tab1:
        if assets:
            df = pd.DataFrame(assets)
            st.dataframe(df, use_container_width=True)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download Asset Inventory (CSV)", csv, "ot_it_assets.csv", "text/csv")
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Assets", len(assets))
            col2.metric("OT Assets", sum(1 for a in assets if "OT" in a["Category"]))
            col3.metric("IT Assets", sum(1 for a in assets if "IT" in a["Category"]))
        else:
            st.error("No assets detected. Try adding custom decode-as ports or check your PCAP.")

    with tab2:
        if nodes_vis and edges_vis:
            st.success(f"✅ Visualizing {len(nodes_vis)} assets and {len(edges_vis)} communication links")
            html_graph = generate_vis_network(nodes_vis, edges_vis)
            st.components.v1.html(html_graph, height=700, scrolling=False)
            st.caption("💡 Tip: Drag nodes to reorganise | Scroll to zoom | Double‑click for full‑screen")
        else:
            st.info("Not enough data to build a network map.")

    os.unlink(pcap_path)

if __name__ == "__main__":
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
        main()
    except (subprocess.CalledProcessError, FileNotFoundError):
        st.error("❌ tshark not found. Ensure `packages.txt` contains 'tshark' and redeploy.")
