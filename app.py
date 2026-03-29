"""
OT Asset Discovery from PCAP using tshark
Exhaustive protocol support for industrial control systems
"""

import streamlit as st
import subprocess
import tempfile
import os
import re
import pandas as pd
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional

st.set_page_config(page_title="OT Asset Discovery", layout="wide")
st.title("🏭 OT Asset Discovery from PCAP")
st.markdown("Upload a PCAP file to extract industrial control system (ICS) devices and rich metadata.")

# -----------------------------------------------------------------------------
# EXHAUSTIVE PROTOCOL DEFINITIONS
# -----------------------------------------------------------------------------

# Each protocol: filter, display name, fields to extract (tshark -e), and asset metadata fields
PROTOCOLS = {
    # ========== ICS / OT Protocols ==========
    "modbus": {
        "filter": "modbus",
        "name": "Modbus/TCP",
        "fields": ["ip.src", "ip.dst", "modbus.unit_id", "modbus.func_code"],
        "asset": {"unit_id": "modbus.unit_id"}
    },
    "s7comm": {
        "filter": "s7comm",
        "name": "Siemens S7comm",
        "fields": ["ip.src", "ip.dst", "s7comm.cpu_type", "s7comm.param.func", "s7comm.block_name"],
        "asset": {"cpu_type": "s7comm.cpu_type", "block_name": "s7comm.block_name"}
    },
    "s7commplus": {
        "filter": "s7commplus",
        "name": "Siemens S7commPlus",
        "fields": ["ip.src", "ip.dst"],
        "asset": {}
    },
    "dnp3": {
        "filter": "dnp3",
        "name": "DNP3",
        "fields": ["ip.src", "ip.dst", "dnp3.src", "dnp3.dst", "dnp3.obj"],
        "asset": {"dnp3_src": "dnp3.src", "dnp3_dst": "dnp3.dst"}
    },
    "iec104": {
        "filter": "iec104",
        "name": "IEC 60870-5-104",
        "fields": ["ip.src", "ip.dst", "iec104.asdu_type", "iec104.cot"],
        "asset": {}
    },
    "iec61850_mms": {
        "filter": "mms",
        "name": "IEC 61850 MMS",
        "fields": ["ip.src", "ip.dst", "mms.domain", "mms.variable"],
        "asset": {"domain": "mms.domain"}
    },
    "goose": {
        "filter": "goose",
        "name": "IEC 61850 GOOSE",
        "fields": ["goose.appid", "goose.gocbRef", "goose.dataset"],
        "asset": {"gocbRef": "goose.gocbRef"}
    },
    "profinet": {
        "filter": "pn-io or profinet",
        "name": "PROFINET",
        "fields": ["ip.src", "ip.dst", "pn_dcp.station_name", "pn_dcp.device_id"],
        "asset": {"station_name": "pn_dcp.station_name"}
    },
    "pn_dcp": {
        "filter": "pn_dcp",
        "name": "PROFINET DCP",
        "fields": ["pn_dcp.station_name", "pn_dcp.ip_address", "eth.src"],
        "asset": {"station_name": "pn_dcp.station_name"}
    },
    "enip": {
        "filter": "cip or enip",
        "name": "EtherNet/IP (CIP)",
        "fields": ["ip.src", "ip.dst", "cip.vendor_id", "cip.serial_number", "cip.product_name", "cip.product_revision"],
        "asset": {"vendor_id": "cip.vendor_id", "serial": "cip.serial_number", "product": "cip.product_name", "revision": "cip.product_revision"}
    },
    "bacnet": {
        "filter": "bacnet",
        "name": "BACnet",
        "fields": ["ip.src", "ip.dst", "bacnet.object_name", "bacnet.vendor_id", "bacnet.model_name", "bacnet.firmware_revision"],
        "asset": {"object_name": "bacnet.object_name", "vendor_id": "bacnet.vendor_id", "model": "bacnet.model_name", "firmware": "bacnet.firmware_revision"}
    },
    "opcua": {
        "filter": "opcua",
        "name": "OPC UA",
        "fields": ["ip.src", "ip.dst", "opcua.ServerUris", "opcua.NamespaceArray"],
        "asset": {}
    },
    "hartip": {
        "filter": "hartip",
        "name": "HART-IP",
        "fields": ["ip.src", "ip.dst", "hartip.device_id", "hartip.manufacturer_id"],
        "asset": {"device_id": "hartip.device_id", "manufacturer": "hartip.manufacturer_id"}
    },
    "fins": {
        "filter": "fins",
        "name": "FINS (Omron)",
        "fields": ["ip.src", "ip.dst", "fins.da", "fins.sa"],
        "asset": {}
    },
    "melsec": {
        "filter": "melsec",
        "name": "Melsec (Mitsubishi)",
        "fields": ["ip.src", "ip.dst", "melsec.plc_type", "melsec.station"],
        "asset": {"plc_type": "melsec.plc_type"}
    },
    "mqtt": {
        "filter": "mqtt",
        "name": "MQTT",
        "fields": ["ip.src", "ip.dst", "mqtt.client_id", "mqtt.topic"],
        "asset": {"client_id": "mqtt.client_id"}
    },
    "coap": {
        "filter": "coap",
        "name": "CoAP",
        "fields": ["ip.src", "ip.dst", "coap.opt.uri_path"],
        "asset": {}
    },
    "lontalk": {
        "filter": "lontalk",
        "name": "LonTalk",
        "fields": ["lontalk.nid", "lontalk.domid"],
        "asset": {"neuron_id": "lontalk.nid"}
    },

    # ========== Engineering & Discovery Protocols ==========
    "lldp": {
        "filter": "lldp",
        "name": "LLDP",
        "fields": ["lldp.chassis_id", "lldp.port_id", "lldp.system_name", "lldp.system_description"],
        "asset": {"system_name": "lldp.system_name", "system_desc": "lldp.system_description"}
    },
    "cdp": {
        "filter": "cdp",
        "name": "Cisco CDP",
        "fields": ["cdp.device_id", "cdp.platform", "cdp.ip_address"],
        "asset": {"device_id": "cdp.device_id", "platform": "cdp.platform"}
    },
    "dhcp": {
        "filter": "dhcp",
        "name": "DHCP",
        "fields": ["ip.src", "dhcp.option.hostname", "dhcp.option.vendor_class", "dhcp.option.domain_name"],
        "asset": {"hostname": "dhcp.option.hostname", "vendor_class": "dhcp.option.vendor_class"}
    },
    "dns": {
        "filter": "dns",
        "name": "DNS",
        "fields": ["ip.src", "dns.qry.name", "dns.resp.name"],
        "asset": {"query_name": "dns.qry.name"}
    },
    "nbns": {
        "filter": "nbns",
        "name": "NetBIOS",
        "fields": ["ip.src", "nbns.name", "nbns.name_type"],
        "asset": {"netbios_name": "nbns.name"}
    },
    "ssdp": {
        "filter": "ssdp",
        "name": "SSDP",
        "fields": ["ip.src", "ssdp.device_type", "ssdp.server"],
        "asset": {"device_type": "ssdp.device_type"}
    },

    # ========== IT Protocols (for full asset inventory) ==========
    "snmp": {
        "filter": "snmp",
        "name": "SNMP",
        "fields": ["ip.src", "ip.dst", "snmp.name", "snmp.sysDescr", "snmp.sysObjectID", "snmp.sysLocation"],
        "asset": {"snmp_name": "snmp.name", "sysDescr": "snmp.sysDescr", "sysLocation": "snmp.sysLocation"}
    },
    "http": {
        "filter": "http",
        "name": "HTTP",
        "fields": ["ip.src", "http.user_agent", "http.server", "http.host"],
        "asset": {"user_agent": "http.user_agent", "server": "http.server", "http_host": "http.host"}
    },
    "tls": {
        "filter": "tls.handshake",
        "name": "TLS/SSL",
        "fields": ["ip.src", "tls.handshake.extensions_server_name", "tls.handshake.cipher_suites"],
        "asset": {"sni": "tls.handshake.extensions_server_name"}
    },
    "ssh": {
        "filter": "ssh",
        "name": "SSH",
        "fields": ["ip.src", "ssh.server.version"],
        "asset": {"ssh_version": "ssh.server.version"}
    },
    "telnet": {
        "filter": "telnet",
        "name": "Telnet",
        "fields": ["ip.src", "telnet.subnegotiation"],
        "asset": {}
    },
    "smb": {
        "filter": "smb or cifs",
        "name": "SMB/CIFS",
        "fields": ["ip.src", "smb.dialect", "smb.server_component", "smb.share"],
        "asset": {}
    },
    "ftp": {
        "filter": "ftp",
        "name": "FTP",
        "fields": ["ip.src", "ftp.request.command", "ftp.response.code"],
        "asset": {}
    },
    "ntp": {
        "filter": "ntp",
        "name": "NTP",
        "fields": ["ip.src", "ntp.ref_id", "ntp.stratum"],
        "asset": {}
    }
}

# Helper to run tshark and return a list of tab-separated lines
@st.cache_data(ttl=3600)
def run_tshark(pcap_path: str, display_filter: str, fields: List[str]) -> List[str]:
    """Execute tshark and return stdout lines."""
    if not display_filter:
        display_filter = ""
    cmd = ["tshark", "-r", pcap_path]
    if display_filter:
        cmd.extend(["-Y", display_filter])
    cmd.extend(["-T", "fields"])
    for f in fields:
        cmd.extend(["-e", f])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0 and result.stderr:
            # Some filters may not match any packets – that's fine
            pass
        return result.stdout.strip().splitlines() if result.stdout else []
    except Exception as e:
        st.warning(f"Error running tshark with filter '{display_filter}': {e}")
        return []

def extract_mac_addresses(pcap_path: str, ip_to_mac: Dict[str, str]):
    """Extract MAC addresses from ARP or Ethernet headers."""
    # Try to get MAC from ARP packets
    arp_lines = run_tshark(pcap_path, "arp", ["arp.src.proto_ipv4", "arp.src.hw_mac"])
    for line in arp_lines:
        parts = line.split('\t')
        if len(parts) >= 2:
            ip, mac = parts[0], parts[1]
            if ip and mac and ip not in ip_to_mac:
                ip_to_mac[ip] = mac
    # Also try from any Ethernet frame (ip.src + eth.src)
    eth_lines = run_tshark(pcap_path, "", ["ip.src", "eth.src"])
    for line in eth_lines:
        parts = line.split('\t')
        if len(parts) >= 2:
            ip, mac = parts[0], parts[1]
            if ip and mac and ip not in ip_to_mac:
                ip_to_mac[ip] = mac

def extract_hostnames(pcap_path: str) -> Dict[str, str]:
    """Extract hostnames from DHCP, DNS, NetBIOS, LLDP, etc."""
    hostnames = {}
    # DHCP hostname option
    dhcp_hosts = run_tshark(pcap_path, "dhcp", ["ip.src", "dhcp.option.hostname"])
    for line in dhcp_hosts:
        parts = line.split('\t')
        if len(parts) >= 2 and parts[1]:
            hostnames[parts[0]] = parts[1]
    # DNS PTR / A records
    dns_hosts = run_tshark(pcap_path, "dns", ["dns.resp.name", "ip.dst"])
    for line in dns_hosts:
        parts = line.split('\t')
        if len(parts) >= 2 and parts[0] and parts[1]:
            hostnames[parts[1]] = parts[0]
    # NetBIOS
    nbns_hosts = run_tshark(pcap_path, "nbns", ["ip.src", "nbns.name"])
    for line in nbns_hosts:
        parts = line.split('\t')
        if len(parts) >= 2 and parts[1]:
            hostnames[parts[0]] = parts[1]
    return hostnames

def main():
    uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])

    if not uploaded_file:
        st.info("👈 Upload a PCAP file to start analysis")
        return

    # Save uploaded file to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        pcap_path = tmp.name

    st.info(f"📡 Analyzing {uploaded_file.name} with tshark... This may take a moment for large files.")

    # Data structures
    assets = {}          # ip -> dict of attributes
    ip_to_mac = {}
    ip_to_hostname = {}
    ip_to_protocols = defaultdict(set)
    ip_to_metadata = defaultdict(dict)  # extra fields like vendor, model, firmware, serial

    try:
        # Step 1: Extract from all protocols
        progress_bar = st.progress(0)
        total_protos = len(PROTOCOLS)
        for idx, (proto_key, proto_info) in enumerate(PROTOCOLS.items()):
            progress_bar.progress((idx + 1) / total_protos, text=f"Analyzing {proto_info['name']}...")
            fields = proto_info["fields"]
            if not fields:
                continue
            lines = run_tshark(pcap_path, proto_info["filter"], fields)
            for line in lines:
                parts = line.split('\t')
                # Find IP addresses in the fields (assume first two fields might be ip.src and ip.dst)
                ips = []
                for p in parts:
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', p):
                        ips.append(p)
                if not ips:
                    continue
                for ip in ips:
                    ip_to_protocols[ip].add(proto_info["name"])
                    # Extract asset-specific metadata if available
                    asset_fields = proto_info.get("asset", {})
                    for attr_name, tshark_field in asset_fields.items():
                        try:
                            field_idx = fields.index(tshark_field)
                            if field_idx < len(parts) and parts[field_idx]:
                                ip_to_metadata[ip][attr_name] = parts[field_idx]
                        except ValueError:
                            continue
        progress_bar.empty()

        # Step 2: Extract MAC addresses
        extract_mac_addresses(pcap_path, ip_to_mac)

        # Step 3: Extract hostnames
        ip_to_hostname = extract_hostnames(pcap_path)

        # Step 4: Build assets dictionary
        all_ips = set(ip_to_protocols.keys()) | set(ip_to_mac.keys()) | set(ip_to_hostname.keys())
        for ip in all_ips:
            assets[ip] = {
                "IP Address": ip,
                "MAC Address": ip_to_mac.get(ip, "Unknown"),
                "Hostname": ip_to_hostname.get(ip, ""),
                "Detected Protocols": ", ".join(sorted(ip_to_protocols.get(ip, []))),
                "Protocol Count": len(ip_to_protocols.get(ip, [])),
                "Vendor/Model": ip_to_metadata.get(ip, {}).get("vendor_id", "") or ip_to_metadata.get(ip, {}).get("model", ""),
                "Firmware/Serial": ip_to_metadata.get(ip, {}).get("firmware", "") or ip_to_metadata.get(ip, {}).get("serial", ""),
                "Additional Info": ", ".join(f"{k}:{v}" for k, v in ip_to_metadata.get(ip, {}).items())
            }

        if not assets:
            st.warning("⚠️ No assets discovered. The PCAP may contain no OT/IT traffic, or tshark filters found nothing.")
        else:
            # Display results
            df = pd.DataFrame(list(assets.values()))
            st.subheader("📊 Discovered Assets")
            st.dataframe(df, use_container_width=True)

            # Download button
            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("⬇️ Download Asset List (CSV)", csv, "ot_assets.csv", "text/csv")

            # Summary stats
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Assets", len(assets))
            all_protos = set()
            for prot_set in ip_to_protocols.values():
                all_protos.update(prot_set)
            col2.metric("Protocols Detected", len(all_protos))
            col3.metric("With MAC Address", sum(1 for a in assets.values() if a["MAC Address"] != "Unknown"))

            st.subheader("📡 Protocol Distribution")
            proto_counts = defaultdict(int)
            for prot_set in ip_to_protocols.values():
                for p in prot_set:
                    proto_counts[p] += 1
            proto_df = pd.DataFrame(proto_counts.items(), columns=["Protocol", "Asset Count"]).sort_values("Asset Count", ascending=False)
            st.bar_chart(proto_df.set_index("Protocol"))

    except subprocess.CalledProcessError as e:
        st.error(f"Tshark command failed: {e.stderr}")
    except Exception as e:
        st.error(f"Unexpected error: {e}")
    finally:
        # Cleanup temporary file
        os.unlink(pcap_path)

if __name__ == "__main__":
    # Check tshark availability
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        st.error("❌ tshark is not installed or not in PATH. Ensure `packages.txt` contains 'tshark' and redeploy.")
        st.stop()
    main()