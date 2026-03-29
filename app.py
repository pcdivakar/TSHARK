"""
OT & IT Asset Discovery – Exhaustive Detection
- Detects OT protocols (S7, Modbus, DNP3, CIP, BACnet, PROFINET, etc.)
- Detects IT protocols (HTTP, DNS, DHCP, SNMP, SSH, Telnet, FTP, SMB, NTP)
- Extracts rich metadata: hostname, OS, service versions, open ports
- Builds unified asset inventory and network graph
"""

import streamlit as st
import subprocess
import tempfile
import os
import re
import pandas as pd
import networkx as nx
from collections import defaultdict

st.set_page_config(page_title="OT & IT Asset Discovery", layout="wide")
st.title("🏭 OT & IT Asset Discovery & Network Topology")

# =============================================================================
# CONFIGURATION
# =============================================================================
DEBUG = True   # Set to False to hide detailed tshark commands

# Known OT ports (standard)
KNOWN_OT_PORTS = {
    102: "S7comm", 502: "Modbus", 20000: "DNP3", 44818: "EtherNet/IP",
    2222: "EtherNet/IP", 47808: "BACnet", 2404: "IEC104", 34964: "PROFINET",
    4840: "OPC UA", 9600: "Omron FINS", 5000: "Mitsubishi", 5001: "Mitsubishi",
    5002: "Mitsubishi", 5006: "Mitsubishi", 5007: "Mitsubishi", 5500: "Mitsubishi"
}

# Known IT ports (common services)
KNOWN_IT_PORTS = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 67: "DHCP", 68: "DHCP",
    161: "SNMP", 162: "SNMP", 22: "SSH", 23: "Telnet", 21: "FTP",
    445: "SMB", 139: "SMB", 123: "NTP", 25: "SMTP", 110: "POP3",
    143: "IMAP", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    27017: "MongoDB", 6379: "Redis"
}

# OT keywords for frame.protocols detection
OT_KEYWORDS = [
    's7comm', 'modbus', 'dnp3', 'cip', 'bacnet', 'profinet', 'iec104', 'opcua',
    'pn_dcp', 'etherip', 'enip', 'mms', 'goose', 'sv', 'fins', 'melsec', 'hart'
]

# IT keywords for frame.protocols detection
IT_KEYWORDS = [
    'http', 'dns', 'dhcp', 'snmp', 'ssh', 'telnet', 'ftp', 'smb', 'ntp',
    'ssl', 'tls', 'smtp', 'pop3', 'imap', 'rdp', 'mysql', 'postgres'
]

# =============================================================================
# PROTOCOL DETECTORS (both OT and IT)
# =============================================================================
PROTOCOL_DETECTORS = [
    # OT protocols
    {"filter": "s7comm", "name": "Siemens S7comm", "category": "OT", "fields": ["ip.src", "s7comm.cpu_type", "s7comm.module_type"]},
    {"filter": "modbus", "name": "Modbus/TCP", "category": "OT", "fields": ["ip.src", "modbus.unit_id"]},
    {"filter": "dnp3", "name": "DNP3", "category": "OT", "fields": ["ip.src", "dnp3.src"]},
    {"filter": "cip", "name": "EtherNet/IP (CIP)", "category": "OT", "fields": ["ip.src", "cip.vendor_id", "cip.product_name"]},
    {"filter": "bacnet", "name": "BACnet", "category": "OT", "fields": ["ip.src", "bacnet.object_name", "bacnet.vendor_id"]},
    {"filter": "pn_dcp", "name": "PROFINET DCP", "category": "OT", "fields": ["pn_dcp.station_name", "pn_dcp.ip_address"]},
    {"filter": "iec104", "name": "IEC 60870-5-104", "category": "OT", "fields": ["ip.src"]},
    {"filter": "opcua", "name": "OPC UA", "category": "OT", "fields": ["ip.src"]},
    {"filter": "profinet", "name": "PROFINET IO", "category": "OT", "fields": ["ip.src"]},
    # IT protocols
    {"filter": "http", "name": "HTTP", "category": "IT", "fields": ["ip.src", "http.host", "http.user_agent", "http.server"]},
    {"filter": "tls.handshake", "name": "HTTPS/TLS", "category": "IT", "fields": ["ip.src", "tls.handshake.extensions_server_name"]},
    {"filter": "dns", "name": "DNS", "category": "IT", "fields": ["ip.src", "dns.qry.name", "dns.resp.name"]},
    {"filter": "dhcp", "name": "DHCP", "category": "IT", "fields": ["ip.src", "dhcp.option.hostname", "dhcp.option.vendor_class"]},
    {"filter": "snmp", "name": "SNMP", "category": "IT", "fields": ["ip.src", "snmp.sysDescr", "snmp.sysName", "snmp.sysObjectID"]},
    {"filter": "ssh", "name": "SSH", "category": "IT", "fields": ["ip.src", "ssh.server.version"]},
    {"filter": "telnet", "name": "Telnet", "category": "IT", "fields": ["ip.src", "telnet.subnegotiation"]},
    {"filter": "ftp", "name": "FTP", "category": "IT", "fields": ["ip.src", "ftp.request.command"]},
    {"filter": "smb", "name": "SMB/CIFS", "category": "IT", "fields": ["ip.src", "smb.dialect", "smb.server_component"]},
    {"filter": "ntp", "name": "NTP", "category": "IT", "fields": ["ip.src", "ntp.ref_id", "ntp.stratum"]},
    {"filter": "lldp", "name": "LLDP", "category": "IT", "fields": ["lldp.system_name", "lldp.system_description"]},
]

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
    if DEBUG:
        st.code(f"Running: {' '.join(cmd)}", language="bash")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        lines = result.stdout.strip().splitlines() if result.stdout else []
        if DEBUG and result.stderr:
            st.warning(f"tshark stderr: {result.stderr[:500]}")
        return lines, None
    except Exception as e:
        return [], str(e)

def detect_ips_by_ports(pcap_path, port_map):
    """Return set of IPs that communicate over given port map."""
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

def detect_ips_by_protocol_string(pcap_path, keywords):
    """Return set of IPs where frame.protocols contains any keyword."""
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

def extract_assets(pcap_path, custom_decode_ports=None):
    """Combine OT and IT detection, extract metadata."""
    ip_data = defaultdict(lambda: {
        "protocols": set(),
        "category": set(),
        "metadata": {},
        "packet_count": 0
    })

    # 1. Identify candidate IPs from OT/IT ports and protocol strings
    with st.spinner("Identifying active IPs via port and protocol analysis..."):
        ot_port_ips = detect_ips_by_ports(pcap_path, KNOWN_OT_PORTS)
        it_port_ips = detect_ips_by_ports(pcap_path, KNOWN_IT_PORTS)
        ot_string_ips = detect_ips_by_protocol_string(pcap_path, OT_KEYWORDS)
        it_string_ips = detect_ips_by_protocol_string(pcap_path, IT_KEYWORDS)
        candidate_ips = ot_port_ips.union(it_port_ips, ot_string_ips, it_string_ips)

    if DEBUG:
        st.write(f"**Candidate IPs found:** {len(candidate_ips)}")
        st.write(f"  - OT ports: {len(ot_port_ips)}")
        st.write(f"  - IT ports: {len(it_port_ips)}")
        st.write(f"  - OT strings: {len(ot_string_ips)}")
        st.write(f"  - IT strings: {len(it_string_ips)}")

    if not candidate_ips:
        return ip_data

    # 2. Run protocol detectors
    ports_to_decode = [5000, 5001, 5002, 5006, 5007, 5500, 6000, 9600, 10000, 20000, 34964]
    if custom_decode_ports:
        ports_to_decode.extend(custom_decode_ports)

    progress_bar = st.progress(0)
    total = len(PROTOCOL_DETECTORS)
    for idx, det in enumerate(PROTOCOL_DETECTORS):
        progress_bar.progress((idx+1)/total, f"Trying {det['name']}...")
        lines, _ = run_tshark(pcap_path, det["filter"], det["fields"])
        if not lines:
            for port in ports_to_decode:
                decode_str = f"tcp.port=={port},{det['filter']}"
                lines, _ = run_tshark(pcap_path, det["filter"], det["fields"], decode_str)
                if lines:
                    if DEBUG:
                        st.success(f"Decode-as for {det['name']} on port {port}")
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
    progress_bar.empty()

    # Fallback for candidate IPs with no protocol match
    for ip in candidate_ips:
        if not ip_data[ip]["protocols"]:
            ip_data[ip]["protocols"].add("Unknown (detected by port/protocol string)")
            ip_data[ip]["category"].add("Unknown")

    return ip_data

def get_vendor(metadata):
    vendor_ids = {"002a": "Siemens", "001b": "Rockwell", "005a": "Schneider", "001c": "ABB",
                  "006f": "Phoenix Contact", "003c": "Mitsubishi", "003d": "Omron"}
    if "cip_vendor_id" in metadata:
        return vendor_ids.get(metadata["cip_vendor_id"], "Unknown")
    if "vendor_id" in metadata:
        return vendor_ids.get(metadata["vendor_id"], "Unknown")
    if "cpu_type" in metadata and ("Siemens" in metadata["cpu_type"] or "S7" in metadata["cpu_type"]):
        return "Siemens"
    if "product_name" in metadata:
        prod = metadata["product_name"].lower()
        if "rockwell" in prod or "controllogix" in prod:
            return "Rockwell"
        if "siemens" in prod:
            return "Siemens"
    if "sysDescr" in metadata:
        desc = metadata["sysDescr"].lower()
        if "linux" in desc:
            return "Linux"
        if "windows" in desc:
            return "Windows"
        if "cisco" in desc:
            return "Cisco"
    return "Unknown"

def get_model(metadata):
    return (metadata.get("product_name") or metadata.get("cpu_type") or
            metadata.get("station_name") or metadata.get("sysName") or
            metadata.get("http_server") or "Unknown")

def get_hostname(metadata):
    return (metadata.get("dhcp_option_hostname") or metadata.get("dns_qry_name") or
            metadata.get("sysName") or metadata.get("http_host") or
            metadata.get("tls_handshake_extensions_server_name") or "")

def get_os_info(metadata):
    if "sysDescr" in metadata:
        return metadata["sysDescr"][:100]
    if "http_server" in metadata:
        return metadata["http_server"]
    if "ssh_server_version" in metadata:
        return metadata["ssh_server_version"]
    return ""

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
# MAIN APP
# =============================================================================
def main():
    uploaded = st.file_uploader("📁 Choose a PCAP file", type=["pcap", "pcapng"])
    if not uploaded:
        st.info("👈 Upload a PCAP file to start")
        if DEBUG:
            with st.expander("ℹ️ How to verify your PCAP locally"):
                st.markdown(
                    "**Run these commands:**\n\n"
                    "```bash\n"
                    "# Show all protocols\n"
                    "tshark -r your.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn | head -20\n"
                    "# Show used TCP ports\n"
                    "tshark -r your.pcap -T fields -e tcp.port | sort | uniq -c | sort -rn\n"
                    "```\n"
                )
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded.getbuffer())
        pcap_path = tmp.name

    st.info(f"📡 Analyzing {uploaded.name}...")

    # Optional custom decode-as ports
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

    if DEBUG:
        st.subheader("🔍 Debug Output")
        st.write(f"**Unique IPs with activity:** {len(ip_data)}")
        for ip, d in ip_data.items():
            st.write(f"- {ip}: {', '.join(d['protocols'])} (packets: {d['packet_count']})")

    # Build asset list
    assets = []
    for ip, data in ip_data.items():
        assets.append({
            "ip_address": ip,
            "category": ", ".join(data["category"]) if data["category"] else "Unknown",
            "asset_type": next(iter(data["protocols"])) if data["protocols"] else "Unknown",
            "vendor": get_vendor(data["metadata"]),
            "model": get_model(data["metadata"]),
            "hostname": get_hostname(data["metadata"]),
            "os_info": get_os_info(data["metadata"])[:100],
            "protocols": ", ".join(data["protocols"]),
            "metadata": str(data["metadata"])[:200],
            "packet_count": data["packet_count"]
        })

    conv = get_conversations(pcap_path)
    G = nx.Graph()
    for a in assets:
        G.add_node(a["ip_address"])
    ip_set = {a["ip_address"] for a in assets}
    for (src, dst), cnt in conv.items():
        if src in ip_set and dst in ip_set:
            G.add_edge(src, dst, weight=cnt)

    tab1, tab2 = st.tabs(["📋 Asset Inventory", "🗺️ Network Topology"])

    with tab1:
        if assets:
            df = pd.DataFrame(assets)
            st.dataframe(df, use_container_width=True)
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download CSV", csv, "ot_it_assets.csv", "text/csv")
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Assets", len(assets))
            col2.metric("OT Assets", sum(1 for a in assets if "OT" in a["category"]))
            col3.metric("IT Assets", sum(1 for a in assets if "IT" in a["category"]))
        else:
            st.error("❌ **No assets detected!**")
            st.markdown(
                "### Possible reasons:\n"
                "1. **Non‑standard ports** – Enter custom ports above.\n"
                "2. **Encrypted traffic** – Some protocols may be encrypted.\n"
                "3. **Incomplete PCAP** – The capture may miss handshake packets.\n\n"
                "### Quick verification:\n"
                "```bash\n"
                "tshark -r your_file.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn | head -20\n"
                "```\n"
            )

    with tab2:
        if G.number_of_nodes() > 0:
            st.success(f"✅ Found {G.number_of_nodes()} assets and {G.number_of_edges()} connections")
            try:
                import matplotlib.pyplot as plt
                fig, ax = plt.subplots(figsize=(10, 8))
                pos = nx.spring_layout(G, k=2, iterations=50)
                nx.draw(G, pos, with_labels=True, node_color='lightblue',
                        edge_color='gray', node_size=500, font_size=8, ax=ax)
                st.pyplot(fig)
            except ImportError:
                st.warning("Install matplotlib for graphs: `pip install matplotlib`")
                st.write("**Basic node/edge list:**")
                st.write(f"Nodes: {list(G.nodes())}")
                st.write(f"Edges: {list(G.edges())}")
        else:
            st.info("No network connections found between detected assets.")

    os.unlink(pcap_path)

if __name__ == "__main__":
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
        main()
    except (subprocess.CalledProcessError, FileNotFoundError):
        st.error("❌ tshark not found. Ensure `packages.txt` contains 'tshark' and redeploy.")
