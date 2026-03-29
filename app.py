"""
OT Asset Discovery - Fixed Version with Debug Support
- Verifies OT traffic detection at every step
- Supports decode-as for non-standard ports
- Provides detailed debug output
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

st.set_page_config(page_title="OT Asset Discovery", layout="wide")
st.title("🏭 OT Asset Discovery & Network Topology")

# =============================================================================
# DEBUG MODE - Set to True to see detailed tshark output
# =============================================================================
DEBUG = True

# =============================================================================
# PROTOCOL DEFINITIONS WITH PORT HINTS
# =============================================================================

# Standard OT ports for fallback detection
OT_PORTS = {
    102: "s7comm",
    502: "modbus",
    20000: "dnp3",
    44818: "cip",       # EtherNet/IP
    2222: "cip",        # EtherNet/IP (alternative)
    47808: "bacnet",
    2404: "iec104",
    34964: "profinet",
    4840: "opcua"
}

# Protocol detection with multiple filter attempts
PROTOCOL_DETECTORS = [
    # Standard display filters (works for standard ports)
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
# TSHARK HELPER WITH DEBUG
# =============================================================================

def run_tshark(pcap_path: str, display_filter: str, fields: list, decode_as: str = None) -> tuple:
    """
    Run tshark and return (lines, error_message)
    """
    cmd = ["tshark", "-r", pcap_path]
    
    # Add decode-as if specified (for non-standard ports)
    if decode_as:
        cmd.extend(["-d", decode_as])
    
    if display_filter:
        cmd.extend(["-Y", display_filter])
    
    cmd.extend(["-T", "fields"])
    for f in fields:
        cmd.extend(["-e", f])
    
    # Add quiet mode unless debugging
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

def detect_ot_traffic(pcap_path: str) -> dict:
    """
    First pass: detect what OT protocols exist in the PCAP
    Returns dict of protocol -> packet_count
    """
    detected = {}
    
    # Method 1: Check frame.protocols for OT protocol strings
    cmd = ["tshark", "-r", pcap_path, "-T", "fields", "-e", "frame.protocols"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    
    ot_keywords = ['s7comm', 'modbus', 'dnp3', 'cip', 'bacnet', 'profinet', 'iec104', 'opcua', 'pn_dcp']
    
    for line in result.stdout.split('\n'):
        line_lower = line.lower()
        for keyword in ot_keywords:
            if keyword in line_lower:
                detected[keyword] = detected.get(keyword, 0) + 1
    
    # Method 2: Check for traffic on known OT ports
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

def extract_assets_with_fallback(pcap_path: str) -> dict:
    """
    Extract assets using multiple methods, with fallback detection
    """
    ip_data = defaultdict(lambda: {
        "protocols": [],
        "metadata": {},
        "packet_count": 0
    })
    
    # First, detect what's actually in the PCAP
    with st.spinner("Detecting OT protocols in PCAP..."):
        detected_protos = detect_ot_traffic(pcap_path)
    
    if DEBUG:
        st.write("📊 **Detected protocols in PCAP:**")
        for proto, count in detected_protos.items():
            st.write(f"- {proto}: {count} packets")
    
    # Try each detector
    progress_bar = st.progress(0)
    
    for idx, detector in enumerate(PROTOCOL_DETECTORS):
        progress_bar.progress((idx + 1) / len(PROTOCOL_DETECTORS), 
                            f"Trying {detector['name']}...")
        
        # Try without decode-as first
        lines, error = run_tshark(pcap_path, detector["filter"], detector["fields"])
        
        # If no results and we have port info, try decode-as
        if not lines and detector["name"] in detected_protos:
            if DEBUG:
                st.info(f"Protocol {detector['name']} detected but filter returned no results - trying decode-as")
            
            # Try to decode common non-standard ports
            for port in [5000, 5001, 5002, 6000, 10000, 20000]:
                decode_str = f"tcp.port=={port},{detector['filter']}"
                lines, error = run_tshark(pcap_path, detector["filter"], detector["fields"], decode_str)
                if lines:
                    if DEBUG:
                        st.success(f"Success with decode-as: {decode_str}")
                    break
        
        for line in lines:
            parts = line.split('\t')
            # Find IP address
            ip = None
            for p in parts:
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', p):
                    ip = p
                    break
            
            if not ip:
                continue
            
            ip_data[ip]["protocols"].append(detector["name"])
            ip_data[ip]["packet_count"] += 1
            
            # Store metadata from fields
            for i, field in enumerate(detector["fields"]):
                if i < len(parts) and parts[i] and field != "ip.src":
                    ip_data[ip]["metadata"][field.replace(".", "_")] = parts[i]
    
    progress_bar.empty()
    
    return ip_data

def get_vendor_from_metadata(metadata: dict) -> str:
    """Extract vendor from metadata fields"""
    vendor_ids = {
        "002a": "Siemens", "001b": "Rockwell", "005a": "Schneider",
        "001c": "ABB", "006f": "Phoenix Contact", "003c": "Mitsubishi",
        "003d": "Omron", "0062": "GE", "0061": "Emerson"
    }
    
    if "cip_vendor_id" in metadata:
        return vendor_ids.get(metadata["cip_vendor_id"], "Unknown")
    if "vendor_id" in metadata:
        return vendor_ids.get(metadata["vendor_id"], "Unknown")
    if "cpu_type" in metadata:
        if "Siemens" in metadata["cpu_type"] or "S7" in metadata["cpu_type"]:
            return "Siemens"
    if "product_name" in metadata:
        prod = metadata["product_name"].lower()
        if "rockwell" in prod or "controllogix" in prod:
            return "Rockwell"
        if "siemens" in prod:
            return "Siemens"
    return "Unknown"

def get_model_from_metadata(metadata: dict) -> str:
    """Extract model from metadata"""
    if "product_name" in metadata:
        return metadata["product_name"]
    if "cpu_type" in metadata:
        return metadata["cpu_type"]
    if "station_name" in metadata:
        return metadata["station_name"]
    return "Unknown"

# =============================================================================
# CONVERSATION EXTRACTION
# =============================================================================

def get_conversations(pcap_path: str) -> dict:
    """Extract IP conversations"""
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
# MAIN APP
# =============================================================================

def main():
    uploaded_file = st.file_uploader("📁 Choose a PCAP file", type=["pcap", "pcapng"])
    
    if not uploaded_file:
        st.info("👈 Upload a PCAP file to begin OT asset discovery")
        if DEBUG:
            with st.expander("ℹ️ Debug Info - How to Verify Your PCAP"):
                st.markdown("""
                **To verify your PCAP has OT traffic, run these commands locally:**
                
                ```bash
                # Check all protocols present
                tshark -r your_file.pcap -T fields -e frame.protocols | sort | uniq -c | sort -rn
                
                # Check for specific OT protocols
                tshark -r your_file.pcap -Y "s7comm or modbus or dnp3 or cip or bacnet"
                
                # Check TCP ports used (non-standard ports need decode-as)
                tshark -r your_file.pcap -T fields -e tcp.port | sort | uniq -c | sort -rn

