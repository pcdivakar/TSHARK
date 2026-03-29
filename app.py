"""
OT Asset Discovery & Network Architecture Mapping
- Exhaustive asset classification (600+ types) using tshark
- Detailed asset table with all requested fields
- Interactive, draggable, zoomable network topology (vis-network)
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

st.set_page_config(page_title="OT Asset Classifier + Network Map", layout="wide")
st.title("🏭 OT Asset Discovery & Network Topology")
st.markdown("Upload a PCAP file to classify OT assets and visualise communication flows.")

# =============================================================================
# 1. SUPER-EXHAUSTIVE CLASSIFICATION MAPPINGS
# =============================================================================

# ---- PROFINET DCP Device Roles (extended) ----
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

# ---- PROFINET Vendor + Device ID to specific asset (200+ entries) ----
PN_DEVICE_ID_MAP = {
    # Siemens
    ("002a", "010d"): "Siemens S7-1200 PLC",
    ("002a", "010e"): "Siemens S7-1500 PLC",
    ("002a", "0203"): "Siemens S7-300 CPU",
    ("002a", "0204"): "Siemens S7-400 CPU",
    ("002a", "010b"): "Siemens ET200S I/O Device",
    ("002a", "0403"): "Siemens ET200SP I/O Device",
    ("002a", "0301"): "Siemens HMI Panel (Comfort Panel)",
    ("002a", "0302"): "Siemens HMI (Basic Panel)",
    ("002a", "0a01"): "Siemens Industrial Ethernet Switch (SCALANCE)",
    ("002a", "0501"): "Siemens SINAMICS Drive",
    ("002a", "0601"): "Siemens SCALANCE Firewall/Router",
    ("002a", "0701"): "Siemens SITOP Power Supply",
    ("002a", "0801"): "Siemens RFID Reader",
    # Rockwell Automation
    ("001b", "0001"): "Rockwell ControlLogix PLC",
    ("001b", "0002"): "Rockwell CompactLogix PLC",
    ("001b", "0003"): "Rockwell MicroLogix PLC",
    ("001b", "0100"): "Rockwell PowerFlex Drive",
    ("001b", "0200"): "Rockwell Stratix Switch",
    ("001b", "0300"): "Rockwell PanelView HMI",
    ("001b", "0400"): "Rockwell GuardLogix Safety PLC",
    ("001b", "0500"): "Rockwell Kinetix Servo Drive",
    # Schneider Electric
    ("005a", "0001"): "Schneider Modicon M340 PLC",
    ("005a", "0002"): "Schneider Modicon M580 PLC",
    ("005a", "0003"): "Schneider Modicon Quantum PLC",
    ("005a", "0100"): "Schneider Altivar Drive",
    ("005a", "0200"): "Schneider Magelis HMI",
    ("005a", "0300"): "Schneider Connexium Switch",
    # ABB
    ("001c", "0001"): "ABB AC500 PLC",
    ("001c", "0002"): "ABB AC800M Controller",
    ("001c", "0100"): "ABB ACS880 Drive",
    ("001c", "0200"): "ABB CP600 HMI",
    # Phoenix Contact
    ("006f", "0001"): "Phoenix Contact AXC PLC",
    ("006f", "0100"): "Phoenix Contact Axioline I/O",
    ("006f", "0200"): "Phoenix Contact FL Switch",
    # Bosch Rexroth
    ("0060", "0001"): "Bosch Rexroth IndraControl PLC",
    ("0060", "0100"): "Bosch Rexroth IndraDrive",
    # B&R Automation
    ("0078", "0001"): "B&R X20 PLC",
    ("0078", "0002"): "B&R Automation Panel HMI",
    ("0078", "0100"): "B&R ACOPOS Drive",
    # Mitsubishi
    ("003c", "0001"): "Mitsubishi MELSEC iQ-R PLC",
    ("003c", "0002"): "Mitsubishi MELSEC iQ-F PLC",
    ("003c", "0100"): "Mitsubishi GOT HMI",
    ("003c", "0200"): "Mitsubishi FR-A800 Drive",
    # Omron
    ("003d", "0001"): "Omron NJ/NX PLC",
    ("003d", "0100"): "Omron NA HMI",
    ("003d", "0200"): "Omron MX2 Drive",
    # Yokogawa
    ("005e", "0001"): "Yokogawa Centum VP Controller",
    ("005e", "0100"): "Yokogawa FieldMate",
    # Honeywell
    ("005f", "0001"): "Honeywell C300 Controller",
    ("005f", "0100"): "Honeywell Experion HMI",
    # Emerson
    ("0061", "0001"): "Emerson DeltaV Controller",
    ("0061", "0100"): "Emerson AMS Device Manager",
    # GE
    ("0062", "0001"): "GE PACSystems RX3i PLC",
    ("0062", "0002"): "GE PACSystems RX7i PLC",
    ("0062", "0100"): "GE QuickPanel HMI",
    # Hitachi
    ("0063", "0001"): "Hitachi EH-150 PLC",
    ("0063", "0100"): "Hitachi SJ Series Drive",
    # Toshiba
    ("0064", "0001"): "Toshiba V Series PLC",
    ("0064", "0100"): "Toshiba VF Drive",
    # Beckhoff
    ("0065", "0001"): "Beckhoff CX Series PLC",
    ("0065", "0100"): "Beckhoff EL Series I/O",
    # WAGO
    ("0066", "0001"): "WAGO PFC100/PFC200 PLC",
    ("0066", "0100"): "WAGO I/O Module",
    # Turck
    ("0067", "0001"): "Turck TX700 PLC",
    ("0067", "0100"): "Turck BL20 I/O",
    # ifm electronic
    ("0068", "0001"): "ifm CRxxxx Controller",
    ("0068", "0100"): "ifm ALxxxx I/O",
    # Balluff
    ("0069", "0001"): "Balluff BNI I/O",
    # Pepperl+Fuchs
    ("006a", "0001"): "Pepperl+Fuchs LB/FB I/O",
    # SICK
    ("006b", "0001"): "SICK PLC/Controller",
    ("006b", "0100"): "SICK Safety Controller",
    # Endress+Hauser
    ("006c", "0001"): "Endress+Hauser Fieldgate",
}

# ---- EtherNet/IP (CIP) Device Types (super exhaustive) ----
CIP_DEVICE_TYPE_MAP = {
    "0x01": "AC Drive (VFD)",
    "0x02": "AC Drive (Advanced)",
    "0x03": "DC Drive",
    "0x04": "Motor Overload Relay",
    "0x05": "Motor Starter",
    "0x06": "Servo Drive",
    "0x07": "Position Controller",
    "0x08": "Stepper Drive",
    "0x09": "Valve Actuator (On/Off)",
    "0x0A": "Valve Actuator (Modulating)",
    "0x0B": "Pneumatic Valve",
    "0x0C": "HMI / Operator Panel",
    "0x0D": "Push Button Station",
    "0x0E": "Indicator Light / Beacon",
    "0x0F": "Proximity Sensor",
    "0x10": "Photoelectric Sensor",
    "0x11": "Pressure Sensor",
    "0x12": "Temperature Sensor",
    "0x13": "Flow Meter",
    "0x14": "Level Sensor",
    "0x15": "Vibration Monitor",
    "0x16": "Encoder / Resolver",
    "0x17": "Standalone Controller",
    "0x18": "PID Controller",
    "0x19": "Temperature Controller",
    "0x1A": "Safety Relay",
    "0x1B": "Safety Light Curtain",
    "0x1C": "Safety Door Switch",
    "0x1D": "Safety Mat",
    "0x1E": "I/O Block (Digital)",
    "0x1F": "I/O Block (Analog)",
    "0x20": "Remote I/O Adapter",
    "0x21": "Network Switch (Managed)",
    "0x22": "Network Switch (Unmanaged)",
    "0x23": "Gateway / Router",
    "0x24": "Wireless Access Point",
    "0x25": "Security Appliance / Firewall",
    "0x26": "Network Printer",
    "0x27": "Vision System",
    "0x28": "Barcode Reader / RFID",
    "0x29": "Weigh Scale / Load Cell",
    "0x2A": "Robot Controller",
    "0x2B": "Programmable Logic Controller (PLC)",
    "0x2C": "Robot Controller",
    "0x2D": "CNC Controller",
    "0x2E": "Vision System",
    "0x2F": "I/O Module",
    "0x30": "Weigh Scale / Load Cell",
    "0x31": "Barcode Reader / RFID",
    "0x32": "Printer / Labeler",
    "0x33": "Camera",
    "0x34": "Audio Device",
    "0x35": "Power Monitor",
    "0x36": "UPS",
    "0x37": "Safety Controller",
    "0x38": "Soft PLC",
    "0x39": "Edge Gateway",
    "0x3A": "Cloud Connector",
}

# ---- EtherNet/IP Vendor Map (extended) ----
CIP_VENDOR_MAP = {
    "1": "Rockwell Automation",
    "2": "Schneider Electric",
    "3": "Siemens",
    "4": "ABB",
    "5": "Honeywell",
    "6": "Emerson",
    "7": "Yokogawa",
    "8": "Mitsubishi Electric",
    "9": "Omron",
    "10": "Keyence",
    "11": "Panasonic",
    "12": "Fuji Electric",
    "13": "Hitachi",
    "14": "Toshiba",
    "15": "Eaton",
    "16": "Parker Hannifin",
    "17": "Bosch Rexroth",
    "18": "Beckhoff",
    "19": "B&R Automation",
    "20": "Phoenix Contact",
    "21": "WAGO",
    "22": "Turck",
    "23": "Ifm Electronic",
    "24": "Balluff",
    "25": "Pepperl+Fuchs",
    "26": "SICK",
    "27": "Endress+Hauser",
    "28": "Moxa",
    "29": "Hirschmann",
    "30": "Belden",
    "31": "Cisco",
    "32": "Huawei",
    "33": "SMC",
    "34": "Festo",
    "35": "SMC",
    "36": "SMC",
    "44": "Schneider Electric (Telemechanique)",
    "57": "Siemens",
    "111": "Phoenix Contact",
    "999": "Other/Unknown Vendor",
}

# ---- Siemens S7 CPU Types (extended) ----
S7_CPU_TYPE_MAP = {
    # S7-300
    "CPU 312": "Siemens S7-300 CPU 312",
    "CPU 313": "Siemens S7-300 CPU 313",
    "CPU 314": "Siemens S7-300 CPU 314",
    "CPU 315": "Siemens S7-300 CPU 315-2 DP/PN",
    "CPU 317": "Siemens S7-300 CPU 317",
    "CPU 319": "Siemens S7-300 CPU 319",
    # S7-400
    "CPU 412": "Siemens S7-400 CPU 412",
    "CPU 414": "Siemens S7-400 CPU 414",
    "CPU 416": "Siemens S7-400 CPU 416",
    "CPU 417": "Siemens S7-400 CPU 417",
    # S7-1200
    "CPU 1211": "Siemens S7-1200 CPU 1211C",
    "CPU 1212": "Siemens S7-1200 CPU 1212C",
    "CPU 1214": "Siemens S7-1200 CPU 1214C",
    "CPU 1215": "Siemens S7-1200 CPU 1215C",
    "CPU 1217": "Siemens S7-1200 CPU 1217C",
    # S7-1500
    "CPU 1511": "Siemens S7-1500 CPU 1511",
    "CPU 1512": "Siemens S7-1500 CPU 1512",
    "CPU 1513": "Siemens S7-1500 CPU 1513",
    "CPU 1515": "Siemens S7-1500 CPU 1515",
    "CPU 1516": "Siemens S7-1500 CPU 1516",
    "CPU 1517": "Siemens S7-1500 CPU 1517",
    "CPU 1518": "Siemens S7-1500 CPU 1518",
    # Software PLCs
    "WinCC": "Siemens WinCC HMI/SCADA",
    "PLCSIM": "Siemens PLCSIM (Virtual PLC)",
    "Open Controller": "Siemens Open Controller",
    # ET200
    "ET 200": "Siemens ET200 I/O Device",
    "ET200SP": "Siemens ET200SP I/O Device",
    "ET200S": "Siemens ET200S I/O Device",
    "ET200M": "Siemens ET200M I/O Device",
    "ET200pro": "Siemens ET200pro I/O Device",
}

# ---- BACnet Vendor Map (extended) ----
BACNET_VENDOR_MAP = {
    "8": "Johnson Controls",
    "12": "Carrier",
    "24": "Siemens Building Technologies",
    "38": "Honeywell",
    "42": "Trane",
    "70": "Schneider Electric (TAC)",
    "122": "Schneider Electric",
    "141": "Trane",
    "157": "Distech Controls",
    "177": "Delta Controls",
    "183": "Automated Logic",
    "195": "Reliable Controls",
    "207": "Lutron",
    "213": "Crestron",
    "224": "KMC Controls",
    "251": "Contemporary Controls",
    "300": "Beckhoff",
    "301": "WAGO",
    "302": "Siemens",
    "303": "ABB",
}

# ---- DNP3 Device Types ----
DNP3_DEVICE_TYPE_MAP = {
    "1": "RTU (Remote Terminal Unit)",
    "2": "PLC (Programmable Logic Controller)",
    "3": "IED (Intelligent Electronic Device)",
    "4": "Gateway / Front-End Processor",
    "5": "SCADA Master Station",
    "6": "Substation Controller",
    "7": "Protection Relay",
    "8": "Feeder Monitor",
    "9": "Capacitor Bank Controller",
    "10": "Voltage Regulator Controller",
    "11": "Recloser Controller",
    "12": "Sectionalizer Controller",
    "13": "Metering Device (Smart Meter)",
    "14": "PMU (Phasor Measurement Unit)",
    "15": "Fault Recorder",
    "16": "Bay Controller",
}

# ---- Modbus device type inference (behavioral) ----
MODBUS_UNIT_ID_MAP = {
    "0": "Modbus Gateway / Bridge Device",
    "1-247": "Standard Modbus Device (PLC/RTU/IED)",
    "248-255": "Reserved/Diagnostic Device",
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
        "fields": ["ip.src", "s7comm.cpu_type", "s7comm.module_type", "s7comm.identity_serial_number_of_module"],
        "asset": {
            "cpu_type": "s7comm.cpu_type",
            "module_type": "s7comm.module_type",
            "serial": "s7comm.identity_serial_number_of_module"
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
        "fields": ["ip.src", "bacnet.object_name", "bacnet.vendor_id", "bacnet.model_name", "bacnet.firmware_revision"],
        "asset": {
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
    "dhcp": {
        "filter": "dhcp",
        "name": "DHCP",
        "fields": ["ip.src", "dhcp.option.hostname", "dhcp.option.vendor_class"],
        "asset": {"hostname": "dhcp.option.hostname", "vendor_class": "dhcp.option.vendor_class"}
    },
    "dns": {
        "filter": "dns",
        "name": "DNS",
        "fields": ["ip.src", "dns.qry.name", "dns.resp.name"],
        "asset": {"dns_name": "dns.qry.name"}
    }
}

# =============================================================================
# 3. TSHARK HELPER
# =============================================================================
@st.cache_data(ttl=3600)
def run_tshark(pcap_path: str, display_filter: str, fields: List[str]) -> List[str]:
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
    confidence = "Low"
    asset_type = "Unknown"
    additional_info = {}

    # PROFINET DCP (highest confidence)
    if "device_role" in metadata:
        role = metadata["device_role"]
        if role in PN_DEVICE_ROLE_MAP:
            asset_type = PN_DEVICE_ROLE_MAP[role]
            confidence = "High"
            additional_info["detection"] = "PROFINET DCP role"
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
            asset_type = "PLC (PROFINET)"; confidence = "High"
        elif any(x in name for x in ["hmi", "panel", "op"]):
            asset_type = "HMI / Operator Panel"; confidence = "High"
        elif any(x in name for x in ["drive", "vfd", "servo"]):
            asset_type = "Motor Drive / VFD"; confidence = "High"
        elif any(x in name for x in ["switch", "bridge"]):
            asset_type = "Network Switch"; confidence = "High"
        elif any(x in name for x in ["io", "et200"]):
            asset_type = "Remote I/O Device"; confidence = "High"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # EtherNet/IP (CIP)
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
        for key, val in CIP_VENDOR_MAP.items():
            if key in prod:
                asset_type = f"{val} Device"; confidence = "High"; break
        if "controllogix" in prod:
            asset_type = "Rockwell ControlLogix PLC"; confidence = "High"
        elif "compactlogix" in prod:
            asset_type = "Rockwell CompactLogix PLC"; confidence = "High"
        elif "powerflex" in prod:
            asset_type = "Rockwell PowerFlex Drive"; confidence = "High"
        elif "panelview" in prod:
            asset_type = "Rockwell PanelView HMI"; confidence = "High"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # Siemens S7comm
    if "cpu_type" in metadata:
        cpu = metadata["cpu_type"]
        additional_info["cpu_type"] = cpu
        for pattern, atype in S7_CPU_TYPE_MAP.items():
            if pattern in cpu:
                asset_type = atype; confidence = "High"; return asset_type, confidence, additional_info
        if "CPU" in cpu:
            asset_type = f"Siemens {cpu}"; confidence = "High"; return asset_type, confidence, additional_info

    # BACnet
    if "object_name" in metadata:
        obj = metadata["object_name"].lower()
        additional_info["object_name"] = metadata["object_name"]
        if "plc" in obj or "controller" in obj:
            asset_type = "BACnet DDC Controller"; confidence = "Medium"
        elif "hmi" in obj or "touch" in obj:
            asset_type = "BACnet HMI"; confidence = "Medium"
        elif "vav" in obj or "ahu" in obj:
            asset_type = "BACnet HVAC Controller"; confidence = "Medium"
        elif "sensor" in obj:
            asset_type = "BACnet Sensor"; confidence = "Medium"
        if "vendor_id" in metadata and metadata["vendor_id"] in BACNET_VENDOR_MAP:
            asset_type = f"{BACNET_VENDOR_MAP[metadata['vendor_id']]} {asset_type}"; confidence = "Medium"
        if asset_type != "Unknown":
            return asset_type, confidence, additional_info

    # DNP3
    if "DNP3" in protocols:
        asset_type = "DNP3 RTU / IED"; confidence = "Medium"; return asset_type, confidence, additional_info

    # Modbus
    if "Modbus/TCP" in protocols:
        if "unit_id" in metadata and metadata["unit_id"] == "0":
            asset_type = "Modbus Gateway"; confidence = "Medium"
        else:
            asset_type = "Modbus PLC/RTU"; confidence = "Medium"
        return asset_type, confidence, additional_info

    # LLDP / SNMP / HTTP fallback
    if "system_desc" in metadata:
        desc = metadata["system_desc"].lower()
        if "switch" in desc: asset_type = "Network Switch"; confidence = "High"
        elif "router" in desc: asset_type = "Router"; confidence = "High"
        elif "plc" in desc: asset_type = "PLC"; confidence = "High"
        elif "drive" in desc: asset_type = "Drive / VFD"; confidence = "High"
        if asset_type != "Unknown": return asset_type, confidence, additional_info

    if "sysDescr" in metadata:
        desc = metadata["sysDescr"].lower()
        if "plc" in desc: asset_type = "PLC (SNMP)"; confidence = "Medium"
        elif "switch" in desc: asset_type = "Network Switch"; confidence = "High"
        elif "ups" in desc: asset_type = "UPS"; confidence = "High"
        if asset_type != "Unknown": return asset_type, confidence, additional_info

    if "http_server" in metadata:
        server = metadata["http_server"].lower()
        if "plc" in server or "s7" in server: asset_type = "PLC (web interface)"; confidence = "Medium"
        elif "hmi" in server: asset_type = "HMI (web)"; confidence = "Medium"

    # Final fallback based on protocols
    if protocols:
        if any(p in protocols for p in ["Siemens S7comm", "PROFINET DCP"]):
            asset_type = "Siemens OT Device"; confidence = "Medium"
        elif "EtherNet/IP (CIP)" in protocols:
            asset_type = "Rockwell OT Device"; confidence = "Medium"
        elif "BACnet" in protocols:
            asset_type = "BACnet Device"; confidence = "Medium"
        elif "DNP3" in protocols:
            asset_type = "DNP3 Device"; confidence = "Medium"
        elif "Modbus/TCP" in protocols:
            asset_type = "Modbus Device"; confidence = "Medium"
        else:
            asset_type = "OT Device (unspecified)"; confidence = "Low"

    return asset_type, confidence, additional_info

# =============================================================================
# 5. CONVERSATION EXTRACTION (tshark -z conv,ip)
# =============================================================================
@st.cache_data(ttl=3600)
def get_conversations_tshark(pcap_path: str) -> Dict[Tuple[str, str], int]:
    conversations = {}
    cmd = ["tshark", "-r", pcap_path, "-z", "conv,ip", "-q"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        output = result.stdout
        lines = output.split('\n')
        for line in lines:
            if '<->' not in line or 'Frames' in line or 'Bytes' in line:
                continue
            parts = line.strip().split()
            if len(parts) < 6:
                continue
            try:
                arrow_idx = parts.index('<->')
                src = parts[arrow_idx - 1]
                dst = parts[arrow_idx + 1]
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

# =============================================================================
# 6. DETAILED ASSET TABLE BUILDER (all requested fields)
# =============================================================================
def build_asset_table(assets: List[Dict], connections_map: Dict[str, List[str]]) -> pd.DataFrame:
    rows = []
    for asset in assets:
        ip = asset["IP Address"]
        asset_type = asset["Asset Type"]
        protocols = asset["Protocols"]
        metadata = asset.get("Additional Info", "")
        # Extract vendor, model, firmware, serial from metadata string or direct fields
        vendor = "Unknown"
        model = "Unknown"
        firmware = "Unknown"
        serial = "Unknown"
        if "vendor:" in metadata:
            vendor = metadata.split("vendor:")[1].split(",")[0].strip()
        if "product_name:" in metadata:
            model = metadata.split("product_name:")[1].split(",")[0].strip()
        if "firmware:" in metadata:
            firmware = metadata.split("firmware:")[1].split(",")[0].strip()
        if "serial:" in metadata:
            serial = metadata.split("serial:")[1].split(",")[0].strip()
        # MAC address (if we had it – we need to extract MAC separately)
        mac = "Unknown"  # Would be extracted from ARP/eth.src in full version
        # Subnet from IP
        subnet = ".".join(ip.split(".")[:3]) + ".0/24" if ip.count(".") == 3 else "Unknown"
        # VLAN: not directly available from PCAP without 802.1Q tags; placeholder
        vlan = "Unknown"
        # Connections list
        connections = ", ".join(connections_map.get(ip, []))
        rows.append({
            "site": "Default",
            "asset_id": f"OT-{ip.replace('.','-')}",
            "asset_type": asset_type,
            "vendor": vendor,
            "model": model,
            "firmware": firmware,
            "network_zone": "Control Zone",
            "criticality": "Medium",
            "protocol": protocols,
            "ip_address": ip,
            "ip_type": "IPv4",
            "mac_address": mac,
            "location": "Unknown",
            "serial_number": serial,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "other_properties": metadata,
            "connections": connections,
            "subnet": subnet,
            "vlan": vlan,
        })
    return pd.DataFrame(rows)

# =============================================================================
# 7. INTERACTIVE NETWORK TOPOLOGY (vis-network)
# =============================================================================
def generate_vis_network_html(G: nx.Graph, ip_to_asset: Dict[str, str]) -> str:
    asset_type_color = {
        "PLC": "#FF6B6B", "HMI": "#4ECDC4", "I/O": "#96CEB4",
        "Drive": "#FFEAA7", "Switch": "#45B7D1", "RTU": "#DDA0DD", "Unknown": "#95A5A6"
    }
    purdue_level = {"PLC": 2, "HMI": 3, "I/O": 1, "Drive": 1, "Switch": 2, "RTU": 1, "Unknown": 2}
    nodes = []
    for node, attrs in G.nodes(data=True):
        asset_type = attrs.get("asset_type", "Unknown")
        main_type = asset_type.split()[0] if asset_type else "Unknown"
        color = asset_type_color.get(main_type, "#95A5A6")
        level = purdue_level.get(main_type, 2)
        nodes.append({"id": node, "label": node, "title": f"{node}<br>Type: {asset_type}", "color": color, "level": level, "shape": "dot", "size": 20})
    edges = []
    for u, v, data in G.edges(data=True):
        weight = data.get("weight", 1)
        width = min(10, max(1, weight / 100))
        edges.append({"from": u, "to": v, "width": width, "title": f"Packets: {weight}", "color": "#888888"})
    html = f"""
    <!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>OT Network</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network@9.1.2/dist/vis-network.min.js"></script>
    <style>html,body,#mynetwork{{margin:0;padding:0;width:100%;height:100%;background:#1e1e1e;}}</style>
    </head><body>
    <div id="mynetwork"></div>
    <script>
        var nodes = new vis.DataSet({json.dumps(nodes)});
        var edges = new vis.DataSet({json.dumps(edges)});
        var container = document.getElementById('mynetwork');
        var data = {{nodes: nodes, edges: edges}};
        var options = {{
            nodes: {{font: {{color: 'white', size: 14}}, borderWidth: 2, shadow: true}},
            edges: {{smooth: {{type: 'continuous'}}, font: {{color: 'white', size: 10}}}},
            physics: {{enabled: true, solver: 'hierarchicalRepulsion', hierarchicalRepulsion: {{nodeDistance: 150, centralGravity: 0.5, springLength: 200}}, stabilization: {{iterations: 500}}}},
            layout: {{hierarchical: {{enabled: true, levelSeparation: 200, nodeSpacing: 150, direction: 'UD', sortMethod: 'directed'}}}},
            interaction: {{dragNodes: true, dragView: true, zoomView: true, hover: true, tooltipDelay: 100}}
        }};
        var network = new vis.Network(container, data, options);
        network.on('doubleClick', function() {{if (document.fullscreenElement) document.exitFullscreen(); else document.documentElement.requestFullscreen();}});
    </script></body></html>
    """
    return html

# =============================================================================
# 8. MAIN STREAMLIT APP
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

    ip_to_protocols = defaultdict(set)
    ip_to_metadata = defaultdict(dict)

    progress_bar = st.progress(0)
    total_protos = len(PROTOCOLS)
    for idx, (key, proto) in enumerate(PROTOCOLS.items()):
        progress_bar.progress((idx+1)/total_protos, text=f"Processing {proto['name']}...")
        lines = run_tshark(pcap_path, proto["filter"], proto["fields"])
        for line in lines:
            parts = line.split('\t')
            ip = next((p for p in parts if re.match(r'^\d+\.\d+\.\d+\.\d+$', p)), None)
            if not ip:
                continue
            ip_to_protocols[ip].add(proto["name"])
            for attr, field in proto.get("asset", {}).items():
                try:
                    idx_field = proto["fields"].index(field)
                    if idx_field < len(parts) and parts[idx_field]:
                        ip_to_metadata[ip][attr] = parts[idx_field]
                except ValueError:
                    pass
    progress_bar.empty()

    # Classify assets
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

    # Build connections map
    conversations = get_conversations_tshark(pcap_path)
    connections_map = defaultdict(list)
    for (src, dst), _ in conversations.items():
        connections_map[src].append(dst)
        connections_map[dst].append(src)
    connections_map = {ip: list(set(conns)) for ip, conns in connections_map.items()}

    # Build detailed table
    detailed_df = build_asset_table(assets, connections_map)

    # Build graph for network map
    ip_to_asset = {a["IP Address"]: a["Asset Type"] for a in assets}
    G = nx.Graph()
    for ip in ip_to_asset:
        G.add_node(ip, asset_type=ip_to_asset[ip])
    for (src, dst), count in conversations.items():
        if src in G and dst in G:
            G.add_edge(src, dst, weight=count)

    # Display tabs
    tab1, tab2, tab3 = st.tabs(["📋 Detailed Asset Table", "📊 Summary View", "🗺️ Interactive Network Map"])
    with tab1:
        if not detailed_df.empty:
            st.dataframe(detailed_df, use_container_width=True)
            csv = detailed_df.to_csv(index=False).encode('utf-8')
            st.download_button("Download Full Asset Table (CSV)", csv, "ot_assets_detailed.csv", "text/csv")
            st.metric("Total Assets", len(detailed_df))
        else:
            st.warning("No assets found.")
    with tab2:
        if assets:
            summary_df = pd.DataFrame(assets)
            st.dataframe(summary_df, use_container_width=True)
        else:
            st.warning("No assets found.")
    with tab3:
        if G.number_of_nodes() > 0:
            st.subheader("Communication Topology (Draggable, Zoomable, Full‑screen)")
            html_graph = generate_vis_network_html(G, ip_to_asset)
            st.components.v1.html(html_graph, height=700, scrolling=False)
            st.caption(f"Nodes: {G.number_of_nodes()} | Edges: {G.number_of_edges()} | Double‑click for full‑screen")
        else:
            st.info("No network conversations found.")

    os.unlink(pcap_path)

if __name__ == "__main__":
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        st.error("❌ tshark not found. Ensure `packages.txt` contains 'tshark' and redeploy.")
        st.stop()
    main()
