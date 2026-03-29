"""
OT Asset Discovery – Robust Detection
- Uses port, protocol string, and decode‑as methods
- Allows user to add custom decode‑as ports
- Provides fallback asset extraction when metadata is missing
"""

import streamlit as st
import subprocess
import tempfile
import os
import re
import pandas as pd
import networkx as nx
from collections import defaultdict

st.set_page_config(page_title="OT Asset Discovery", layout="wide")
st.title("🏭 OT Asset Discovery & Network Topology")

# =============================================================================
# CONFIGURATION
# =============================================================================
DEBUG = True   # Set to False to hide detailed tshark commands

# Standard OT ports (well‑known)
KNOWN_OT_PORTS = {
    102: "S7comm", 502: "Modbus", 20000: "DNP3", 44818: "EtherNet/IP",
    2222: "EtherNet/IP", 47808: "BACnet", 2404: "IEC104", 34964: "PROFINET",
    4840: "OPC UA", 9600: "Omron FINS", 5000: "Mitsubishi", 5001: "Mitsubishi",
    5002: "Mitsubishi", 5006: "Mitsubishi", 5007: "Mitsubishi", 5500: "Mitsubishi"
}

# Common non‑standard ports to try decode‑as
DECODE_AS_PORTS = [5000, 5001, 5002, 5006, 5007, 5500, 6000, 9600, 10000, 20000, 34964]

# OT keywords for frame.protocols detection
OT_KEYWORDS = [
    's7comm', 'modbus', 'dnp3', 'cip', 'bacnet', 'profinet', 'iec104', 'opcua',
    'pn_dcp', 'etherip', 'enip', 'mms', 'goose', 'sv', 'fins', 'melsec', 'hart'
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

def detect_ot_ips_by_ports(pcap_path):
    """Return set of IPs that communicate over known OT ports."""
    ot_ips = set()
    for port, proto in KNOWN_OT_PORTS.items():
        cmd = ["tshark", "-r", pcap_path, f"-Y", f"tcp.port=={port} or udp.port=={port}",
               "-T", "fields", "-e", "ip.src", "-e", "ip.dst"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            for line in result.stdout.split('\n'):
                for ip in line.split():
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                        ot_ips.add(ip)
        except:
            pass
    return ot_ips

def detect_ot_ips_by_protocol_string(pcap_path):
    """Return set of IPs where frame.protocols contains OT keywords."""
    ot_ips = set()
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
                if any(kw in protocols for kw in OT_KEYWORDS):
                    ot_ips.add(ip)
    except:
        pass
    return ot_ips

def extract_assets_with_robust_methods(pcap_path, custom_decode_ports=None):
    """Combine multiple detection methods and extract metadata."""
    ip_data = defaultdict(lambda: {
        "protocols": set(),
        "metadata": {},
        "packet_count": 0
    })

    # 1. Get candidate OT IPs from port and protocol string detection
    with st.spinner("Identifying OT IPs using port and protocol analysis..."):
        port_ips = detect_ot_ips_by_ports(pcap_path)
        proto_ips = detect_ot_ips_by_protocol_string(pcap_path)
        candidate_ips = port_ips.union(proto_ips)

    if DEBUG:
        st.write(f"**Candidate OT IPs found:** {len(candidate_ips)}")
        st.write(f"  - via ports: {len(port_ips)}")
        st.write(f"  - via protocol strings: {len(proto_ips)}")

    if not candidate_ips:
        return ip_data

    # 2. For each candidate IP, try to extract protocol and metadata
    # We'll use a set of protocol detectors (same as before)
    protocol_detectors = [
        {"filter": "s7comm", "name": "Siemens S7comm", "fields": ["ip.src", "s7comm.cpu_type", "s7comm.module_type"]},
        {"filter": "modbus", "name": "Modbus/TCP", "fields": ["ip.src", "modbus.unit_id"]},
        {"filter": "dnp3", "name": "DNP3", "fields": ["ip.src", "dnp3.src"]},
        {"filter": "cip", "name": "EtherNet/IP (CIP)", "fields": ["ip.src", "cip.vendor_id", "cip.product_name"]},
        {"filter": "bacnet", "name": "BACnet", "fields": ["ip.src", "bacnet.object_name"]},
        {"filter": "pn_dcp", "name": "PROFINET DCP", "fields": ["pn_dcp.station_name", "pn_dcp.ip_address"]},
        {"filter": "iec104", "name": "IEC 60870-5-104", "fields": ["ip.src"]},
        {"filter": "opcua", "name": "OPC UA", "fields": ["ip.src"]},
        {"filter": "profinet", "name": "PROFINET IO", "fields": ["ip.src"]},
        {"filter": "lldp", "name": "LLDP", "fields": ["lldp.system_name"]},
    ]

    progress_bar = st.progress(0)
    total_detectors = len(protocol_detectors)
    for idx, det in enumerate(protocol_detectors):
        progress_bar.progress((idx+1)/total_detectors, f"Trying {det['name']}...")
        # Try without decode-as
        lines, _ = run_tshark(pcap_path, det["filter"], det["fields"])
        # If no lines, try decode-as on candidate ports
        if not lines:
            ports_to_try = DECODE_AS_PORTS
            if custom_decode_ports:
                ports_to_try.extend(custom_decode_ports)
            for port in ports_to_try:
                decode_str = f"tcp.port=={port},{det['filter']}"
                lines, _ = run_tshark(pcap_path, det["filter"], det["fields"], decode_str)
                if lines:
                    if DEBUG:
                        st.success(f"Decode-as worked for {det['name']} on port {port}")
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
            ip_data[ip]["packet_count"] += 1
            for i, field in enumerate(det["fields"]):
                if i < len(parts) and parts[i] and field != "ip.src":
                    ip_data[ip]["metadata"][field.replace(".", "_")] = parts[i]
    progress_bar.empty()

    # For any candidate IP that still has no protocol, add a generic entry
    for ip in candidate_ips:
        if not ip_data[ip]["protocols"]:
            ip_data[ip]["protocols"].add("OT Device (detected by port/protocol string)")
            ip_data[ip]["packet_count"] = 1

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
    return "Unknown"

def get_model(metadata):
    return metadata.get("product_name") or metadata.get("cpu_type") or metadata.get("station_name") or "Unknown"

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
                    "**Run these commands on your PCAP:**\n\n"
                    "```bash\n"
                    "# Show all protocols\n"
                    "tshark -r your.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn | head -20\n"
                    "# Check for OT protocols\n"
                    "tshark -r your.pcap -Y \"s7comm or modbus or dnp3 or cip or bacnet\"\n"
                    "# Show used TCP ports\n"
                    "tshark -r your.pcap -T fields -e tcp.port | sort | uniq -c | sort -rn\n"
                    "```\n"
                )
        return

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded.getbuffer())
        pcap_path = tmp.name

    st.info(f"📡 Analyzing {uploaded.name}...")

    # Optional: user input for additional custom decode-as ports
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

    ip_data = extract_assets_with_robust_methods(pcap_path, custom_ports)

    if DEBUG:
        st.subheader("🔍 Debug Output")
        st.write(f"**Unique OT IPs found:** {len(ip_data)}")
        for ip, d in ip_data.items():
            st.write(f"- {ip}: {', '.join(d['protocols'])} (packets: {d['packet_count']})")

    # Build asset list
    assets = []
    for ip, data in ip_data.items():
        if not data["protocols"]:
            continue
        assets.append({
            "ip_address": ip,
            "asset_type": next(iter(data["protocols"])) if data["protocols"] else "Unknown",
            "vendor": get_vendor(data["metadata"]),
            "model": get_model(data["metadata"]),
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
            st.download_button("⬇️ Download CSV", csv, "ot_assets.csv", "text/csv")
            st.metric("Total Assets", len(assets))
            st.metric("Communication Links", G.number_of_edges())
        else:
            st.error("❌ **No OT assets detected!**")
            st.markdown(
                "### Possible reasons:\n"
                "1. **Non‑standard ports** – Your OT traffic uses custom ports. Enter them above.\n"
                "2. **Encrypted traffic** – Some OT protocols (OPC UA, some S7) may be encrypted.\n"
                "3. **Incomplete PCAP** – The capture may miss initial handshake packets.\n\n"
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
