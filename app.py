"""
CyberShield OT/IT Asset Discovery
- Exhaustive asset identification using tshark
- Interactive network topology with Plotly
- Geospatial visualization with Folium
- MAC OUI vendor lookup
"""

import streamlit as st
import subprocess
import tempfile
import os
import re
import pandas as pd
import networkx as nx
import plotly.graph_objects as go
import folium
from folium.plugins import MarkerCluster
from collections import defaultdict
import json

# =============================================================================
# PAGE CONFIG & THEME
# =============================================================================
st.set_page_config(page_title="CyberShield OT/IT Asset Discovery", layout="wide", page_icon="🛡️")

# Professional dark theme (teal accents)
st.markdown("""
<style>
    .stApp { background-color: #0f0f0f !important; }
    body, p, div, span, label, .stText, .stMarkdown, .stAlert, .stException,
    .stCodeBlock, code, pre, .stExpander, .stExpander p, .stExpander div {
        color: #e0e0e0 !important;
    }
    h1, h2, h3, h4, h5, h6, .stHeader { color: #2ecc71 !important; font-weight: 600 !important; }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px; background-color: #1e1e1e; padding: 10px 20px; border-radius: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: transparent; color: #e0e0e0 !important; font-weight: bold;
        font-size: 16px; border-radius: 8px; padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #2ecc71 !important; color: #000000 !important;
    }
    .dataframe, .stDataFrame {
        background-color: #1e1e1e !important; color: #e0e0e0 !important;
    }
    .dataframe th, .stDataFrame th {
        background-color: #2a2a2a !important; color: #2ecc71 !important;
    }
    .stMetric {
        background-color: #1e1e1e !important; border-left: 4px solid #2ecc71;
    }
    .stMetric label, .stMetric .stMetricLabel { color: #2ecc71 !important; }
    .stMetric .stMetricValue { color: #ffffff !important; font-size: 28px !important; }
    .stButton button {
        background-color: #2ecc71 !important; color: #000000 !important;
        border-radius: 8px; font-weight: bold;
    }
    .stFileUploader {
        background-color: #1e1e1e !important; border: 1px dashed #2ecc71 !important;
    }
    .stFileUploader label, .stFileUploader .stMarkdown { color: #e0e0e0 !important; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ CyberShield OT/IT Asset Discovery")
st.markdown("*Professional network mapping for industrial control and IT systems*")

# =============================================================================
# EXHAUSTIVE PROTOCOL & PORT CONFIGURATION
# =============================================================================
KNOWN_OT_PORTS = {
    102: "S7comm", 502: "Modbus", 20000: "DNP3", 44818: "EtherNet/IP",
    2222: "EtherNet/IP", 47808: "BACnet", 2404: "IEC104", 34964: "PROFINET",
    4840: "OPC UA", 9600: "Omron FINS", 5000: "Mitsubishi", 5001: "Mitsubishi",
    5002: "Mitsubishi", 5006: "Mitsubishi", 5007: "Mitsubishi", 5500: "Mitsubishi",
    2455: "CoDeSys", 11740: "EtherCAT", 1100: "Beckhoff ADS",
    4000: "Siemens S7", 1111: "EtherNet/IP", 2221: "EtherNet/IP",
    30718: "LonWorks", 1000: "Modbus", 8080: "Modbus", 5020: "Modbus"
}

KNOWN_IT_PORTS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 67: "DHCP", 68: "DHCP",
    161: "SNMP", 162: "SNMP", 22: "SSH", 23: "Telnet", 21: "FTP",
    445: "SMB", 139: "SMB", 123: "NTP", 25: "SMTP", 110: "POP3",
    143: "IMAP", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    389: "LDAP", 636: "LDAPS", 514: "Syslog", 500: "IPsec",
    4500: "IPsec", 1812: "RADIUS", 1813: "RADIUS"
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
    {"filter": "goose", "name": "IEC 61850 GOOSE", "category": "OT", "fields": ["ip.src", "goose.appid"]},
    {"filter": "mms", "name": "IEC 61850 MMS", "category": "OT", "fields": ["ip.src", "mms.domain"]},
    {"filter": "fins", "name": "Omron FINS", "category": "OT", "fields": ["ip.src"]},
    {"filter": "melsec", "name": "Mitsubishi Melsec", "category": "OT", "fields": ["ip.src"]},
    {"filter": "hartip", "name": "HART-IP", "category": "OT", "fields": ["ip.src"]},
    {"filter": "ethercat", "name": "EtherCAT", "category": "OT", "fields": ["ip.src"]},
    {"filter": "ads", "name": "Beckhoff ADS", "category": "OT", "fields": ["ip.src"]},
    {"filter": "codesys", "name": "CoDeSys", "category": "OT", "fields": ["ip.src"]},
    {"filter": "lonworks", "name": "LonWorks", "category": "OT", "fields": ["ip.src"]},
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
    {"filter": "cdp", "name": "Cisco CDP", "category": "IT", "fields": ["cdp.device_id", "cdp.platform"]},
    {"filter": "icmp", "name": "ICMP (Ping)", "category": "IT", "fields": ["ip.src"]},
    {"filter": "arp", "name": "ARP", "category": "IT", "fields": ["arp.src.proto_ipv4", "arp.src.hw_mac"]},
]

# MAC OUI database (extended)
OUI_DB = {
    "00:0C:29": "VMware", "00:50:56": "VMware", "08:00:27": "Oracle VirtualBox",
    "00:15:5D": "Microsoft Hyper-V", "00:1C:42": "Cisco", "00:0F:FE": "Huawei",
    "00:0F:9F": "Siemens", "00:1B:21": "Rockwell Automation", "00:0A:35": "Schneider Electric",
    "00:0E:8F": "ABB", "00:0D:4B": "Phoenix Contact", "00:1E:37": "Mitsubishi Electric",
    "00:0E:6B": "Omron", "00:80:F4": "GE Fanuc", "00:1F:45": "Beckhoff", "00:30:48": "WAGO",
    "00:04:AB": "Honeywell", "00:03:BA": "Emerson", "00:1D:9C": "Yokogawa",
    "00:23:CD": "Endress+Hauser", "00:21:9B": "Pepperl+Fuchs", "00:22:FB": "Ifm Electronic",
    "00:1C:CC": "Balluff", "00:07:3E": "Turck", "00:0F:53": "Parker Hannifin",
    "00:1C:B3": "SICK", "00:16:4D": "Keyence", "00:30:DE": "Festo", "00:24:1A": "SMC",
    "00:1A:6B": "HP", "00:14:22": "Dell", "B8:27:EB": "Raspberry Pi", "00:16:3E": "Xensource",
    "00:0C:41": "Juniper", "00:17:5A": "Fortinet", "00:18:73": "Palo Alto", "00:11:22": "Apple",
    "00:1B:63": "Apple", "00:1E:C2": "Apple", "00:25:00": "Apple", "00:0F:EA": "Apple",
    "00:19:D1": "Samsung", "00:21:E6": "Samsung", "00:22:FD": "Samsung", "00:24:54": "Samsung",
    "00:1B:FC": "Google", "00:22:41": "Google", "00:23:7D": "Google", "00:1E:6F": "Amazon",
    "00:22:5F": "Amazon", "00:24:7C": "Amazon", "00:1C:DF": "Microsoft", "00:1F:3B": "Microsoft",
    "00:0D:3A": "Intel", "00:1B:21": "Intel", "00:1C:BF": "Intel",
}

def get_vendor_from_mac(mac):
    if not mac or mac == "Unknown":
        return "Unknown"
    mac_upper = mac.upper().replace("-", ":").replace(".", ":")
    for prefix, vendor in OUI_DB.items():
        if mac_upper.startswith(prefix.upper()):
            return vendor
    return "Unknown"

# =============================================================================
# TSHARK HELPER FUNCTIONS
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
               "-T", "fields", "-e", "ip.src", "-e", "ip.dst", "-q"]
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
    keywords = ['s7comm', 'modbus', 'dnp3', 'cip', 'bacnet', 'profinet', 'iec104', 'opcua',
                'http', 'dns', 'dhcp', 'snmp', 'ssh', 'telnet', 'ftp', 'smb', 'ntp', 'lldp']
    ips = set()
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "ip.src", "-e", "frame.protocols", "-q"]
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
    cmd = ["tshark", "-r", pcap_path, "-Y", "arp", "-T", "fields", "-e", "arp.src.proto_ipv4", "-e", "arp.src.hw_mac", "-q"]
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
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "ip.src", "-e", "eth.src", "-q"]
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

# =============================================================================
# PLOTLY NETWORK GRAPH
# =============================================================================
def create_plotly_network(G, ip_data, ip_to_mac, ip_to_category):
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)
    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        category = ip_to_category.get(node, "Unknown")
        if category == "OT":
            color = "#e74c3c"  # red
        elif category == "IT":
            color = "#3498db"  # blue
        else:
            color = "#95a5a6"  # grey
        node_color.append(color)
        asset_info = ip_data.get(node, {})
        protocols = ", ".join(asset_info.get("protocols", []))
        mac = ip_to_mac.get(node, "Unknown")
        vendor = get_vendor_from_mac(mac)
        hover_text = (
            f"<b>{node}</b><br>"
            f"Category: {category}<br>"
            f"Protocols: {protocols}<br>"
            f"MAC: {mac}<br>"
            f"Vendor: {vendor}<br>"
            f"Packets: {asset_info.get('packet_count', 0)}"
        )
        node_text.append(hover_text)
        node_size.append(20)
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        marker=dict(size=node_size, color=node_color, line=dict(width=2, color='white')),
        text=[node for node in G.nodes()],
        textposition="bottom center",
        textfont=dict(size=10, color='white'),
        hovertext=node_text,
        hoverinfo='text'
    )
    edge_traces = []
    for edge in G.edges(data=True):
        src, dst, data = edge
        weight = data.get('weight', 1)
        width = 1 + min(8, weight / 100)
        x0, y0 = pos[src]
        x1, y1 = pos[dst]
        edge_trace = go.Scatter(
            x=[x0, x1, None], y=[y0, y1, None],
            mode='lines',
            line=dict(width=width, color='#888888'),
            hoverinfo='none'
        )
        edge_traces.append(edge_trace)
    fig = go.Figure(data=edge_traces + [node_trace])
    fig.update_layout(
        title="OT/IT Network Topology",
        title_font=dict(color='white'),
        showlegend=False,
        hovermode='closest',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='#0f0f0f',
        paper_bgcolor='#0f0f0f',
        font=dict(color='white'),
        height=700
    )
    return fig

# =============================================================================
# FOLIUM MAP (placeholder; can be extended with geoIP)
# =============================================================================
def create_folium_map(assets_df):
    # Check if we have lat/lon columns
    if 'lat' not in assets_df.columns or 'lon' not in assets_df.columns:
        return None
    map_df = assets_df.dropna(subset=['lat', 'lon'])
    if map_df.empty:
        return None
    center_lat = map_df.iloc[0]['lat']
    center_lon = map_df.iloc[0]['lon']
    m = folium.Map(location=[center_lat, center_lon], zoom_start=12, tiles='CartoDB dark_matter')
    marker_cluster = MarkerCluster().add_to(m)
    for _, row in map_df.iterrows():
        popup_text = f"""
        <b>{row['ip_address']}</b><br>
        Type: {row['asset_type']}<br>
        Vendor: {row['vendor']}<br>
        Protocols: {row['protocols']}
        """
        folium.Marker(
            location=[row['lat'], row['lon']],
            popup=popup_text,
            icon=folium.Icon(color='green' if row['category'] == 'OT' else 'blue')
        ).add_to(marker_cluster)
    return m

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

    # Build asset list
    assets = []
    ip_to_category = {}
    for ip, data in ip_data.items():
        mac = ip_to_mac.get(ip, "Unknown")
        vendor_mac = get_vendor_from_mac(mac)
        vendor = vendor_mac if vendor_mac != "Unknown" else "Unknown"
        if vendor == "Unknown" and "cip_vendor_id" in data["metadata"]:
            vendor_ids = {"002a": "Siemens", "001b": "Rockwell", "005a": "Schneider"}
            vendor = vendor_ids.get(data["metadata"]["cip_vendor_id"], "Unknown")
        category = ", ".join(data["category"]) if data["category"] else "Unknown"
        ip_to_category[ip] = "OT" if "OT" in data["category"] else ("IT" if "IT" in data["category"] else "Unknown")
        asset = {
            "ip_address": ip,
            "mac_address": mac,
            "vendor": vendor,
            "asset_type": next(iter(data["protocols"])) if data["protocols"] else "Unknown",
            "category": category,
            "hostname": data["metadata"].get("dhcp_option_hostname") or data["metadata"].get("dns_qry_name") or "",
            "os_service": data["metadata"].get("sysDescr", "")[:60] or data["metadata"].get("http_server", "")[:60],
            "protocols": ", ".join(data["protocols"]),
            "packet_count": data["packet_count"],
            # Placeholder for location (you can add geoIP lookup here)
            "lat": None,
            "lon": None
        }
        assets.append(asset)

    conversations = get_conversations(pcap_path)
    G = nx.Graph()
    for a in assets:
        G.add_node(a["ip_address"])
    ip_set = {a["ip_address"] for a in assets}
    for (src, dst), cnt in conversations.items():
        if src in ip_set and dst in ip_set:
            G.add_edge(src, dst, weight=cnt)

    # Tabs
    tab1, tab2, tab3 = st.tabs(["📋 Asset Inventory", "🗺️ Network Topology", "📍 Map View"])

    with tab1:
        if assets:
            df = pd.DataFrame(assets)
            display_cols = ["ip_address", "mac_address", "vendor", "asset_type", "category",
                            "hostname", "os_service", "protocols", "packet_count"]
            df_display = df[display_cols].copy()
            st.dataframe(df_display, use_container_width=True)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download Asset Inventory (CSV)", csv, "cybershield_assets.csv", "text/csv")
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Assets", len(assets))
            col2.metric("OT Assets", sum(1 for a in assets if "OT" in a["category"]))
            col3.metric("IT Assets", sum(1 for a in assets if "IT" in a["category"]))
        else:
            st.error("No assets detected. Try adding custom decode-as ports or check your PCAP.")

    with tab2:
        if G.number_of_nodes() > 0:
            fig = create_plotly_network(G, ip_data, ip_to_mac, ip_to_category)
            st.plotly_chart(fig, use_container_width=True)
            st.caption("💡 Tip: Hover over nodes for details | Drag to zoom | Scroll to pan")
        else:
            st.info("Not enough data to build a network graph.")

    with tab3:
        # Build DataFrame for map
        map_df = pd.DataFrame(assets)
        map_obj = create_folium_map(map_df)
        if map_obj:
            st.components.v1.html(map_obj._repr_html_(), height=600)
            st.caption("📍 Asset locations (if coordinates are available)")
        else:
            st.info("Map view requires latitude/longitude data. You can add geoIP lookup to populate coordinates.")
            st.markdown("""
            **To add geolocation**:  
            - Install `maxminddb` or use a free geoIP service  
            - Add `lat` and `lon` columns to the asset data  
            - The map will automatically show markers for assets with coordinates
            """)

    os.unlink(pcap_path)

if __name__ == "__main__":
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
        main()
    except (subprocess.CalledProcessError, FileNotFoundError):
        st.error("❌ tshark not found. Ensure `packages.txt` contains 'tshark' and redeploy.")
