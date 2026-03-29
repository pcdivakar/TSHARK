# OT Asset Discovery from PCAP

A Streamlit application that extracts industrial control system (ICS) assets from PCAP files using `tshark`.

## Features
- Supports 35+ OT and IT protocols (Modbus, S7, DNP3, BACnet, PROFINET, EtherNet/IP, OPC UA, etc.)
- Extracts rich metadata: vendor IDs, model names, firmware versions, serial numbers, hostnames, MAC addresses
- Deployable on Streamlit Cloud or any Linux server with tshark

## Deployment on Streamlit Cloud
1. Fork this repository
2. Go to [Streamlit Cloud](https://streamlit.io/cloud)
3. Click "New app", select your repo, branch, and `app.py`
4. Deploy – Streamlit will automatically read `packages.txt` and install tshark

## Local Testing
```bash
sudo apt update && sudo apt install tshark -y
pip install -r requirements.txt
streamlit run app.py