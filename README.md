# PacketVoyager: Advanced Traffic Analysis System

## Short Description
A professional-grade Network Traffic Analysis & Forensic System with a real-time Web Dashboard.

## Brief Description
PacketVoyager is a robust network inspection tool that bridges the gap between simple scripts and full forensic suites like Wireshark. It captures live network traffic, extracts deep metadata from non-encrypted HTTP packets, and visualizes everything in a sleek, real-time dashboard. 

**Key Features:**
- **Real-time Web UI**: Monitor traffic, statistics, and protocol distribution via a modern dashboard.
- **Wireshark Integration**: Automatically saves all captured traffic to `capture_history.pcap`.
- **Deep Packet Inspection**: Extracts User-Agents, Hosts, Paths, and Raw Payloads.
- **Traffic Statistics**: Visualizes bandwidth usage and protocol breakdowns.
- **High Performance**: Uses an asynchronous event-driven engine for optimal packet processing.

## Tools Used
- **Scapy**: Core engine for packet manipulation and parsing.
- **Flask & Socket.io**: Web backbone for real-time data streaming.
- **HTML5/TailwindCSS**: Premium UI design with glassmorphism.
- **Wireshark**: Recommended for analyzing the exported `.pcap` files.


## How to Implement
1.  **Setup**: Install Python and the `scapy` library. Ensure Npcap (Windows) or libpcap (Linux) is installed.
2.  **Coding**:
    - **Easy Run**: Double-click `run.bat` (Run as Administrator) to start sniffing on the default interface.
    - **Manual**:
        - Import `scapy.all`.
        - Use `sniff()` function with a callback (`prn`) to process packets.
        - Apply a BPF filter `tcp port 80` to isolate HTTP traffic.
3.  **Parsing**: inside the callback, check for `Raw` layers or HTTP-specific layers to extract headers.
4.  **Logging**: Write the extracted details to a file.

## Tips
- **Promiscuous Mode**: Ensure your network adapter supports promiscuous mode. On Wi-Fi, this might be restricted by the hardware or driver.
- **Permissions**: Sniffing requires administrative (root/Administrator) privileges.
- **Filtering**: Use BPF filters (Berkley Packet Filter) effectively to reduce the load and focus on relevant traffic.
