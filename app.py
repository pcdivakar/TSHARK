"""
OT Asset Discovery - Complete Version
- Detects OT protocols using tshark (with fallback decode-as)
- Shows detailed debug info
- Provides actionable guidance when no assets found
- Displays asset inventory table and network graph
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
# DEBUG MODE
# =============================================================================
DEBUG = True

# =============================================================================
# OT PORT MAPPINGS & PROTOCOL DETECTORS
# =============================================================================
OT_PORTS = {
    102: "s7comm", 502: "modbus", 20000: "dnp3", 44818: "cip",
    2222: "cip", 47808: "bacnet", 2404: "iec104", 34964: "profinet", 4840: "opcua"
}

PROTOCOL_DETECTORS = [
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

def detect_ot_traffic(pcap_path):
    detected = {}
    # frame.protocols method
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "frame.protocols"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    ot_keywords = ['s7comm', 'modbus', 'dnp3', 'cip', 'bacnet', 'profinet', 'iec104', 'opcua', 'pn_dcp']
    for line in result.stdout.split('\n'):
        line_lower = line.lower()
        for kw in ot_keywords:
            if kw in line_lower:
                detected[kw] = detected.get(kw, 0) + 1
    # port method
    port_cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "tcp.port", "-e", "udp.port"]
    port_result = subprocess.run(port_cmd, capture_output=True, text=True, check=False)
    for line in port_result.stdout.split('\n'):
        for port_str in line.split():
            try:
                port = int(port_str)
                if port in OT_PORTS:
                    detected[OT_PORTS[port]] = detected.get(OT_PORTS[port], 0) + 1
            except ValueError:
                pass
    return detected

def extract_assets(pcap_path):
    ip_data = defaultdict(lambda: {"protocols": [], "metadata": {}, "packet_count": 0})
    with st.spinner("Detecting OT protocols..."):
        detected_protos = detect_ot_traffic(pcap_path)
    if DEBUG:
        st.write("📊 **Detected protocols in PCAP:**")
        for proto, cnt in detected_protos.items():
            st.write(f"- {proto}: {cnt} packets")
    progress_bar = st.progress(0)
    for idx, det in enumerate(PROTOCOL_DETECTORS):
        progress_bar.progress((idx+1)/len(PROTOCOL_DETECTORS), f"Trying {det['name']}...")
        lines, _ = run_tshark(pcap_path, det["filter"], det["fields"])
        if not lines and det["name"].lower() in detected_protos:
            if DEBUG:
                st.info(f"{det['name']} detected but filter returned nothing – trying decode-as on common ports")
            for port in [5000, 5001, 5002, 6000, 10000, 20000]:
                decode_str = f"tcp.port=={port},{det['filter']}"
                lines, _ = run_tshark(pcap_path, det["filter"], det["fields"], decode_str)
                if lines:
                    if DEBUG:
                        st.success(f"Success with decode-as: {decode_str}")
                    break
        for line in lines:
            parts = line.split('\t')
            ip = None
            for p in parts:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', p):
                    ip = p
                    break
            if not ip:
                continue
            ip_data[ip]["protocols"].append(det["name"])
            ip_data[ip]["packet_count"] += 1
            for i, field in enumerate(det["fields"]):
                if i < len(parts) and parts[i] and field != "ip.src":
                    ip_data[ip]["metadata"][field.replace(".", "_")] = parts[i]
    progress_bar.empty()
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
            with st.expander("ℹ️ Debug Info – How to verify your PCAP locally"):
                st.markdown("""
                **Run these commands on your PCAP:**
                ```bash
                # Show all protocols
                tshark -r your.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn | head -20
                # Check for OT protocols
                tshark -r your.pcap -Y "s7comm or modbus or dnp3 or cip or bacnet"
                # Show used TCP ports
                tshark -r your.pcap -T fields -e tcp.port | sort | uniq -c | sort -rn
