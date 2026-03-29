"""
OT Asset Discovery & Network Architecture Mapping from PCAP
Generates interactive network topology graphs based on traffic patterns
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

# ============================================================================
# NETWORK ARCHITECTURE MAPPING FUNCTIONS
# ============================================================================

@st.cache_data(ttl=3600)
def extract_conversations(pcap_path: str, layer: str = "ip") -> List[Dict]:
    """
    Extract conversation statistics from PCAP using tshark.
    
    Args:
        pcap_path: Path to PCAP file
        layer: 'ip' for Layer 3, 'eth' for Layer 2, 'tcp'/'udp' for transport
    
    Returns:
        List of conversation dictionaries with src, dst, packets, bytes
    """
    # Map layer to tshark conversation type
    conv_types = {
        "ip": "conv,ip",
        "eth": "conv,eth", 
        "tcp": "conv,tcp",
        "udp": "conv,udp"
    }
    
    conv_type = conv_types.get(layer, "conv,ip")
    
    try:
        # Run tshark to get conversation statistics
        cmd = ["tshark", "-r", pcap_path, "-z", conv_type, "-q"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        
        conversations = []
        
        # Parse the tshark output
        lines = result.stdout.split('\n')
        in_table = False
        
        for line in lines:
            # Look for the conversation table
            if '<->' in line and ('Bytes' not in line and 'Frames' not in line):
                parts = line.split()
                if len(parts) >= 6:
                    # Parse format: "IP1 <-> IP2    frames1 bytes1    frames2 bytes2    total_frames total_bytes"
                    # This is simplified; actual format varies
                    conversation = parse_conversation_line(line, layer)
                    if conversation:
                        conversations.append(conversation)
        
        return conversations
        
    except Exception as e:
        st.warning(f"Error extracting conversations: {e}")
        return []


def parse_conversation_line(line: str, layer: str) -> Optional[Dict]:
    """Parse a single line from tshark conversation output."""
    # Pattern matches: "192.168.1.1 <-> 192.168.1.2"
    pattern = r'(\S+)\s*<->\s*(\S+)'
    match = re.search(pattern, line)
    
    if not match:
        return None
    
    src = match.group(1)
    dst = match.group(2)
    
    # Extract numbers (frames and bytes) - simplified parsing
    numbers = re.findall(r'(\d+(?:\.\d+)?)\s*(KB|MB|GB|B)?', line)
    
    return {
        "source": src,
        "destination": dst,
        "packets": extract_packet_count(line),
        "bytes": extract_byte_count(line),
        "layer": layer
    }


def extract_packet_count(line: str) -> int:
    """Extract packet count from conversation line."""
    # Find total frames near the end of line
    matches = re.findall(r'(\d+)\s+(?:KB|MB|GB|B)?', line)
    if len(matches) >= 3:
        return int(matches[-2])  # Total frames is second last
    return 1


def extract_byte_count(line: str) -> int:
    """Extract byte count from conversation line."""
    matches = re.findall(r'(\d+(?:\.\d+)?)\s*(KB|MB|GB|B)', line)
    if matches:
        value, unit = matches[-1]
        value = float(value)
        if unit == 'KB':
            return int(value * 1024)
        elif unit == 'MB':
            return int(value * 1024 * 1024)
        elif unit == 'GB':
            return int(value * 1024 * 1024 * 1024)
        return int(value)
    return 0


def extract_protocol_conversations(pcap_path: str, protocol_filter: str) -> List[Tuple[str, str]]:
    """
    Extract source-destination pairs for a specific OT protocol.
    
    Args:
        pcap_path: Path to PCAP file
        protocol_filter: tshark display filter (e.g., "modbus", "s7comm")
    
    Returns:
        List of (src_ip, dst_ip) tuples
    """
    cmd = ["tshark", "-r", pcap_path, "-Y", protocol_filter, "-T", "fields", 
           "-e", "ip.src", "-e", "ip.dst"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        conversations = []
        
        for line in result.stdout.strip().split('\n'):
            if line and '\t' in line:
                parts = line.split('\t')
                if len(parts) >= 2 and parts[0] and parts[1]:
                    conversations.append((parts[0], parts[1]))
        
        return conversations
        
    except Exception as e:
        st.warning(f"Error extracting {protocol_filter} conversations: {e}")
        return []


def build_network_graph(ip_to_asset_type: Dict[str, str], 
                        conversations: List[Dict],
                        protocol_conversations: Dict[str, List[Tuple[str, str]]]) -> nx.Graph:
    """
    Build a NetworkX graph from asset data and conversation flows.
    
    Args:
        ip_to_asset_type: Mapping from IP to classified asset type
        conversations: List of conversation dictionaries
        protocol_conversations: Dict mapping protocol names to conversation lists
    
    Returns:
        NetworkX Graph with nodes and edges
    """
    G = nx.Graph()
    
    # Add nodes with attributes
    for ip, asset_type in ip_to_asset_type.items():
        G.add_node(ip, 
                   asset_type=asset_type,
                   label=f"{ip}\n{asset_type[:20]}")
    
    # Add edges from general conversations
    for conv in conversations:
        src = conv.get("source")
        dst = conv.get("destination")
        if src and dst and src in G and dst in G:
            G.add_edge(src, dst, 
                       weight=conv.get("packets", 1),
                       bytes=conv.get("bytes", 0),
                       protocols=[])
    
    # Add protocol-specific edge attributes
    for protocol, conv_list in protocol_conversations.items():
        for src, dst in conv_list:
            if src in G and dst in G:
                if G.has_edge(src, dst):
                    # Add protocol to existing edge
                    protocols = G[src][dst].get("protocols", [])
                    if protocol not in protocols:
                        protocols.append(protocol)
                    G[src][dst]["protocols"] = protocols
                else:
                    # Create edge with this protocol
                    G.add_edge(src, dst, weight=1, protocols=[protocol], bytes=0)
    
    return G


def create_plotly_network_graph(G: nx.Graph) -> go.Figure:
    """
    Create an interactive Plotly network visualization.
    
    Args:
        G: NetworkX graph with node and edge attributes
    
    Returns:
        Plotly figure object
    """
    # Node positions using spring layout
    pos = nx.spring_layout(G, k=1.5, iterations=50, seed=42)
    
    # Extract node positions
    node_x = []
    node_y = []
    node_text = []
    node_colors = []
    
    # Color mapping for asset types
    color_map = {
        "PLC": "#FF6B6B",
        "HMI": "#4ECDC4", 
        "RTU": "#45B7D1",
        "I/O Device": "#96CEB4",
        "Network Switch": "#FFEAA7",
        "Engineering WS": "#DDA0DD",
        "Unknown": "#95A5A6"
    }
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        asset_type = G.nodes[node].get("asset_type", "Unknown")
        # Simplify asset type for display
        simple_type = asset_type.split()[0] if asset_type else "Unknown"
        color = color_map.get(simple_type, "#95A5A6")
        node_colors.append(color)
        
        node_text.append(f"{node}<br>Type: {asset_type}")
    
    # Create edge traces
    edge_x = []
    edge_y = []
    edge_widths = []
    
    for edge in G.edges(data=True):
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
        # Edge width based on weight (packet count)
        weight = edge[2].get("weight", 1)
        # Normalize weight to width between 1 and 8
        width = min(8, max(1, weight / 100))
        edge_widths.append(width)
    
    # Create figure
    fig = go.Figure()
    
    # Add edges
    fig.add_trace(go.Scatter(
        x=edge_x, y=edge_y,
        mode='lines',
        line=dict(width=1, color='#888'),
        hoverinfo='none',
        showlegend=False
    ))
    
    # Add nodes
    fig.add_trace(go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        marker=dict(
            size=20,
            color=node_colors,
            line=dict(width=2, color='white')
        ),
        text=[G.nodes[n].get("label", n)[:15] for n in G.nodes()],
        textposition="bottom center",
        textfont=dict(size=10),
        hovertext=node_text,
        hoverinfo='text',
        showlegend=False
    ))
    
    # Update layout
    fig.update_layout(
        title="OT Network Architecture Map",
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20, l=5, r=5, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        height=600,
        plot_bgcolor='#1e1e1e',
        paper_bgcolor='#1e1e1e',
        font=dict(color='white')
    )
    
    return fig


def create_force_directed_html(G: nx.Graph) -> str:
    """
    Create an interactive force-directed graph using PyVis-style HTML.
    This requires plotcap or manual HTML generation.
    """
    # Alternative: Use plotcap library for automatic visualization
    # plotcap -f capture.pcap --layer3
    # Returns HTML string
    
    import json
    
    # Prepare data for D3.js force graph
    nodes = []
    for node in G.nodes():
        nodes.append({
            "id": node,
            "label": node,
            "group": G.nodes[node].get("asset_type", "Unknown")
        })
    
    edges = []
    for edge in G.edges(data=True):
        edges.append({
            "from": edge[0],
            "to": edge[1],
            "value": edge[2].get("weight", 1)
        })
    
    # Generate HTML with embedded D3.js
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>OT Network Map</title>
        <style>
            body {{ margin: 0; padding: 0; font-family: Arial, sans-serif; }}
            #graph {{ width: 100%; height: 600px; }}
        </style>
        <script src="https://d3js.org/d3.v7.min.js"></script>
    </head>
    <body>
        <div id="graph"></div>
        <script>
            const nodesData = {json.dumps(nodes)};
            const edgesData = {json.dumps(edges)};
            
            // D3 force simulation code would go here
            // This is a placeholder - full D3 implementation requires more code
            document.getElementById('graph').innerHTML = 
                '<div style="padding:20px">Network Graph with ' + 
                nodesData.length + ' nodes and ' + edgesData.length + ' edges</div>';
        </script>
    </body>
    </html>
    """
    
    return html_template


# ============================================================================
# MAIN STREAMLIT APP (Extend your existing app)
# ============================================================================

def main():
    st.set_page_config(page_title="OT Asset Discovery & Network Map", layout="wide")
    st.title("🏭 OT Asset Discovery & Network Architecture Mapping")
    st.markdown("Upload a PCAP file to discover OT assets and visualize network topology.")
    
    uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
    
    if not uploaded_file:
        st.info("👈 Upload a PCAP file to start analysis")
        return
    
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        pcap_path = tmp.name
    
    st.info(f"📡 Analyzing {uploaded_file.name}...")
    
    # Create tabs for different views
    tab1, tab2, tab3 = st.tabs(["📊 Asset List", "🗺️ Network Map", "📈 Traffic Analysis"])
    
    # ========== TAB 1: Asset List (from previous code) ==========
    with tab1:
        # Your existing asset discovery code here
        # (Refer to previous response for complete asset classification)
        st.subheader("Discovered OT Assets")
        # ... asset classification code ...
    
    # ========== TAB 2: Network Map ==========
    with tab2:
        st.subheader("OT Network Architecture Map")
        
        # Extract conversations
        with st.spinner("Extracting network conversations..."):
            conversations = extract_conversations(pcap_path, "ip")
            
            # Extract protocol-specific conversations
            protocol_conversations = {}
            for proto in ["modbus", "s7comm", "dnp3", "cip", "bacnet"]:
                convs = extract_protocol_conversations(pcap_path, proto)
                if convs:
                    protocol_conversations[proto] = convs
        
        # Build mock asset types for demonstration
        # In production, use your asset classification results
        all_ips = set()
        for conv in conversations:
            all_ips.add(conv.get("source"))
            all_ips.add(conv.get("destination"))
        
        # Assign asset types (replace with actual classification)
        ip_to_asset = {}
        for idx, ip in enumerate(all_ips):
            # Simplified assignment - use your classification results
            if idx % 4 == 0:
                ip_to_asset[ip] = "PLC (Siemens S7-1200)"
            elif idx % 4 == 1:
                ip_to_asset[ip] = "HMI / SCADA"
            elif idx % 4 == 2:
                ip_to_asset[ip] = "I/O Device"
            else:
                ip_to_asset[ip] = "Network Switch"
        
        # Build graph
        G = build_network_graph(ip_to_asset, conversations, protocol_conversations)
        
        if G.number_of_nodes() > 0:
            # Create interactive Plotly graph
            fig = create_plotly_network_graph(G)
            st.plotly_chart(fig, use_container_width=True)
            
            # Display statistics
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Assets", G.number_of_nodes())
            col2.metric("Communication Links", G.number_of_edges())
            col3.metric("Protocols Detected", len(protocol_conversations))
            
            # Display edge list
            with st.expander("📋 Detailed Communication Matrix"):
                edge_data = []
                for edge in G.edges(data=True):
                    edge_data.append({
                        "Source": edge[0],
                        "Destination": edge[1],
                        "Protocols": ", ".join(edge[2].get("protocols", ["Unknown"])),
                        "Traffic Volume": f"{edge[2].get('bytes', 0):,} bytes"
                    })
                st.dataframe(pd.DataFrame(edge_data), use_container_width=True)
        else:
            st.warning("No network conversations found in the PCAP file.")
    
    # ========== TAB 3: Traffic Analysis ==========
    with tab3:
        st.subheader("Protocol Traffic Distribution")
        
        # Count packets per protocol
        protocol_counts = {}
        for proto in ["modbus", "s7comm", "dnp3", "cip", "bacnet", "http", "snmp"]:
            cmd = ["tshark", "-r", pcap_path, "-Y", proto, "-T", "fields", "-e", "frame.number"]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                count = len(result.stdout.strip().splitlines())
                if count > 0:
                    protocol_counts[proto] = count
            except:
                pass
        
        if protocol_counts:
            # Create bar chart
            fig = go.Figure(data=[
                go.Bar(x=list(protocol_counts.keys()), 
                       y=list(protocol_counts.values()),
                       marker_color='#4ECDC4')
            ])
            fig.update_layout(
                title="Packet Count by Protocol",
                xaxis_title="Protocol",
                yaxis_title="Packet Count",
                height=400,
                plot_bgcolor='#1e1e1e',
                paper_bgcolor='#1e1e1e'
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No OT protocol traffic detected.")
    
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
