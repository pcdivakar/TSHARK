"""
OT & IT Asset Discovery – Deloitte Black & Green Theme
- Exhaustive asset identification (OT + IT) using tshark
- MAC OUI vendor lookup
- Professional vis-network topology (draggable, zoomable, full-screen)
- Tabs at the top (Asset Inventory / Network Map)
- Fully optimised for dark background readability
"""

import streamlit as st
import subprocess
import tempfile
import os
import re
import pandas as pd
import json
import networkx as nx          # <-- FIXED: added missing import
from collections import defaultdict

# =============================================================================
# PAGE CONFIG & DELOITTE DARK THEME (BLACK + GREEN)
# =============================================================================
st.set_page_config(page_title="Deloitte OT/IT Asset Discovery", layout="wide", page_icon="🔒")

# Custom CSS for complete Deloitte black & green theme (improved visibility)
st.markdown("""
<style>
    /* Global background */
    .stApp {
        background-color: #0a0a0a !important;
    }
    /* All text – ensure visibility */
    body, p, div, span, label, .stText, .stMarkdown, .stAlert, .stException,
    .stCodeBlock, code, pre, .stExpander, .stExpander p, .stExpander div {
        color: #e0e0e0 !important;
    }
    /* Headers */
    h1, h2, h3, h4, h5, h6, .stHeader {
        color: #00ff9d !important;
        font-weight: 600 !important;
    }
    /* Sidebar */
    .css-1d391kg, .stSidebar {
        background-color: #000000 !important;
    }
    /* Tabs at top */
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
        background-color: #1a1a1a;
        padding: 10px 20px;
        border-radius: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent;
        color: #e0e0e0 !important;
        font-weight: bold;
        font-size: 16px;
        border-radius: 8px;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #00ff9d !important;
        color: #000000 !important;
    }
    /* Dataframe */
    .dataframe, .stDataFrame {
        background-color: #1e1e1e !important;
        color: #e0e0e0 !important;
        border-collapse: collapse;
        width: 100%;
    }
    .dataframe th, .stDataFrame th {
        background-color: #2a2a2a !important;
        color: #00ff9d !important;
        border: 1px solid #333;
        padding: 8px;
    }
    .dataframe td, .stDataFrame td {
        border: 1px solid #333;
        padding: 8px;
        color: #e0e0e0;
    }
    /* Metric boxes */
    .stMetric {
        background-color: #1a1a1a !important;
        border-radius: 8px;
        padding: 10px;
        border-left: 4px solid #00ff9d;
    }
    .stMetric label, .stMetric .stMetricLabel {
        color: #00ff9d !important;
    }
    .stMetric .stMetricValue {
        color: #ffffff !important;
        font-size: 28px !important;
        font-weight: bold;
    }
    /* Expander */
    .streamlit-expanderHeader {
        background-color: #1a1a1a !important;
        color: #00ff9d !important;
        border-radius: 8px;
    }
    .streamlit-expanderContent {
        background-color: #0a0a0a !important;
        color: #e0e0e0 !important;
    }
    /* Info / Success / Warning boxes */
    .stAlert {
        background-color: #1a1a1a !important;
        border-left: 4px solid #00ff9d !important;
        color: #e0e0e0 !important;
    }
    .stAlert .stMarkdown {
        color: #e0e0e0 !important;
    }
    /* Buttons */
    .stButton button {
        background-color: #00ff9d !important;
        color: #000000 !important;
        border: none;
        border-radius: 8px;
        padding: 8px 16px;
        font-weight: bold;
    }
    .stButton button:hover {
        background-color: #00cc7a !important;
        color: #000000;
    }
    /* File uploader */
    .stFileUploader {
        background-color: #1a1a1a !important;
        border: 1px dashed #00ff9d !important;
        border-radius: 8px;
    }
    /* Code blocks */
    code, pre {
        background-color: #1e1e1e !important;
        color: #00ff9d !important;
        border-radius: 6px;
    }
    /* Text input */
    .stTextInput input {
        background-color: #1e1e1e !important;
        color: #e0e0e0 !important;
        border: 1px solid #00ff9d !important;
        border-radius: 8px;
    }
    /* Success message */
    .stSuccess {
        background-color: #0a2a1a !important;
        border-left-color: #00ff9d !important;
        color: #e0e0e0 !important;
    }
    /* Error message */
    .stError {
        background-color: #2a1a1a !important;
        border-left-color: #ff5555 !important;
        color: #e0e0e0 !important;
    }
    /* Info message */
    .stInfo {
        background-color: #1a2a3a !important;
        border-left-color: #3498db !important;
        color: #e0e0e0 !important;
    }
    /* Captions and small text */
    .stCaption, .stSmallText {
        color: #a0a0a0 !important;
    }
</style>
""", unsafe_allow_html=True)

# Optional logo (place a file named "deloitte_logo.png" in the repo)
try:
    st.image("deloitte_logo.png", width=150)
except:
    pass

st.title("🔒 Deloitte OT & IT Asset Discovery")
st.markdown("*Professional network mapping for industrial control systems*")

# =============================================================================
# CONFIGURATION
# =============================================================================
DEBUG = False

KNOWN_OT_PORTS = {
    102: "S7comm", 502: "Modbus", 20000: "DNP3", 44818: "EtherNet/IP",
    2222: "EtherNet/IP", 47808: "BACnet", 2404: "IEC104", 34964: "PROFINET",
    4840: "OPC UA", 9600: "Omron FINS", 5000: "Mitsubishi", 5001: "Mitsubishi",
    5002: "Mitsubishi", 5006: "Mitsubishi", 5007: "Mitsubishi", 5500: "Mitsubishi"
}

KNOWN_IT_PORTS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 67: "DHCP", 68: "DHCP",
    161: "SNMP", 162: "SNMP", 22: "SSH", 23: "Telnet", 21: "FTP",
    445: "SMB", 139: "SMB", 123: "NTP", 25: "SMTP", 110: "POP3",
    143: "IMAP", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"
}

PROTOCOL_DETECTORS = [
    # OT
    {"filter": "s7comm", "name": "Siemens S7comm", "category": "OT", "fields": ["ip.src", "s7comm.cpu_type", "s7comm.module_type"]},
    {"filter": "modbus", "name": "Modbus/TCP", "category": "OT", "fields": ["ip.src", "modbus.unit_id"]},
    {"filter": "dnp3", "name": "DNP3", "category": "OT", "fields": ["ip.src", "dnp3.src"]},
    {"filter": "cip", "name": "EtherNet/IP (CIP)", "category": "OT", "fields": ["ip.src", "cip.vendor_id", "cip.product_name"]},
    {"filter": "bacnet", "name": "BACnet", "category": "OT", "fields": ["ip.src", "bacnet.object_name", "bacnet.vendor_id"]},
    {"filter": "pn_dcp", "name": "PROFINET DCP", "category": "OT", "fields": ["pn_dcp.station_name", "pn_dcp.ip_address"]},
    {"filter": "iec104", "name": "IEC 60870-5-104", "category": "OT", "fields": ["ip.src"]},
    {"filter": "opcua", "name": "OPC UA", "category": "OT", "fields": ["ip.src"]},
    {"filter": "profinet", "name": "PROFINET IO", "category": "OT", "fields": ["ip.src"]},
    # IT
    {"filter": "http", "name": "HTTP", "category": "IT", "fields": ["ip.src", "http.host", "http.user_agent", "http.server"]},
    {"filter": "tls.handshake", "name": "HTTPS/TLS", "category": "IT", "fields": ["ip.src", "tls.handshake.extensions_server_name"]},
    {"filter": "dns", "name": "DNS", "category": "IT", "fields": ["ip.src", "dns.qry.name", "dns.resp.name"]},
    {"filter": "dhcp", "name": "DHCP", "category": "IT", "fields": ["ip.src", "dhcp.option.hostname", "dhcp.option.vendor_class"]},
    {"filter": "snmp", "name": "SNMP", "category": "IT", "fields": ["ip.src", "snmp.sysDescr", "snmp.sysName"]},
    {"filter": "ssh", "name": "SSH", "category": "IT", "fields": ["ip.src", "ssh.server.version"]},
    {"filter": "telnet", "name": "Telnet", "category": "IT", "fields": ["ip.src"]},
    {"filter": "ftp", "name": "FTP", "category": "IT", "fields": ["ip.src"]},
    {"filter": "smb", "name": "SMB/CIFS", "category": "IT", "fields": ["ip.src"]},
    {"filter": "ntp", "name": "NTP", "category": "IT", "fields": ["ip.src"]},
    {"filter": "lldp", "name": "LLDP", "category": "IT", "fields": ["lldp.system_name", "lldp.system_description"]},
]

# MAC OUI database (sample)
OUI_DB = {
    "00:0C:29": "VMware", "00:50:56": "VMware", "00:1C:42": "Cisco",
    "00:0F:FE": "Huawei", "00:0F:9F": "Siemens", "00:1B:21": "Rockwell Automation",
    "00:0A:35": "Schneider Electric", "00:0E:8F": "ABB", "00:0D:4B": "Phoenix Contact",
    "08:00:27": "Oracle VirtualBox", "00:15:5D": "Microsoft Hyper-V", "B8:27:EB": "Raspberry Pi",
    "00:14:22": "Dell", "00:1A:6B": "HP", "00:16:3E": "Xensource",
    "00:1E:37": "Mitsubishi Electric", "00:0E:6B": "Omron", "00:80:F4": "GE Fanuc",
    "00:1F:45": "Beckhoff", "00:30:48": "WAGO",
}

def get_vendor_from_mac(mac):
    if not mac or mac == "Unknown":
        return "Unknown"
    mac_upper = mac.upper()
    for prefix, vendor in OUI_DB.items():
        if mac_upper.startswith(prefix.upper()):
            return vendor
    return "Unknown"

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
    ot_keywords = ['s7comm', 'modbus', 'dnp3', 'cip', 'bacnet', 'profinet', 'iec104', 'opcua']
    it_keywords = ['http', 'dns', 'dhcp', 'snmp', 'ssh', 'telnet', 'ftp', 'smb', 'ntp']
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
        <title>OT/IT Network Topology</title>
        <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
        <style>
            html, body, #network {{
                margin: 0;
                padding: 0;
                width: 100%;
                height: 100%;
                background-color: #0a0a0a;
            }}
            .controls {{
                position: absolute;
                bottom: 20px;
                right: 20px;
                background: rgba(0,0,0,0.8);
                padding: 8px 15px;
                border-radius: 8px;
                color: #00ff9d;
                font-size: 12px;
                font-family: monospace;
                z-index: 100;
                backdrop-filter: blur(5px);
                border-left: 3px solid #00ff9d;
            }}
        </style>
    </head>
    <body>
        <div id="network"></div>
        <div class="controls">
            🖱️ Drag nodes | 🔍 Scroll zoom | ⬜ Double‑click fullscreen | 🎨 OT=Red, IT=Blue, Unknown=Grey
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
                    color: {{color: '#00ff9d', highlight: '#ffffff'}},
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
        vendor_mac = get_vendor_from_mac(mac)
        vendor = vendor_mac if vendor_mac != "Unknown" else "Unknown"
        if vendor == "Unknown" and "cip_vendor_id" in data["metadata"]:
            vendor_ids = {"002a": "Siemens", "001b": "Rockwell", "005a": "Schneider"}
            vendor = vendor_ids.get(data["metadata"]["cip_vendor_id"], "Unknown")
        asset = {
            "IP Address": ip,
            "MAC Address": mac,
            "Vendor (OUI)": vendor_mac,
            "Asset Type": next(iter(data["protocols"])) if data["protocols"] else "Unknown",
            "Category": ", ".join(data["category"]) if data["category"] else "Unknown",
            "Hostname": data["metadata"].get("dhcp_option_hostname") or data["metadata"].get("dns_qry_name") or "",
            "OS / Service": data["metadata"].get("sysDescr", "")[:60] or data["metadata"].get("http_server", "")[:60],
            "Protocols": ", ".join(data["protocols"]),
            "Packet Count": data["packet_count"]
        }
        assets.append(asset)

    conversations = get_conversations(pcap_path)
    # Use networkx only if needed (for potential future use, but not required for vis-network)
    # We'll keep it for consistency
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
        title = f"<b>{ip}</b><br>Type: {', '.join(data['protocols'])}<br>MAC: {ip_to_mac.get(ip, 'Unknown')}<br>Vendor: {get_vendor_from_mac(ip_to_mac.get(ip, ''))}"
        nodes_vis.append({"id": ip, "label": ip, "title": title, "color": color, "category": category})
    edges_vis = []
    for (src, dst), cnt in conversations.items():
        if src in ip_set and dst in ip_set:
            edges_vis.append({"from": src, "to": dst, "value": cnt, "title": f"Packets: {cnt}"})

    # Tabs at the top
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
