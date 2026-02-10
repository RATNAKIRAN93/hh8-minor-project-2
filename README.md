# Packet Voyager: Intelligence-Driven Traffic Analyzer

An advanced, real-time network packet sniffer and behavioral analysis dashboard. Packet Voyager goes beyond raw data capture, providing deep insights into service identification and micro-anomaly detection.

## 🚀 Key Features

### 🛡️ Behavioral Threat Engine
- **Heuristic Risk Assessment**: Automatically flags traffic as SAFE, WARN, or CRITICAL based on behavioral patterns.
- **ARP Poisoning Detection**: Real-time monitoring of the ARP table to detect Man-in-the-Middle attacks.
- **Port Scan Intelligence**: Detects and flags scanning behavior when a single source probes high-density service nodes.
- **Credential Scanner**: Scans unencrypted HTTP traffic for visible sensitive keywords like `login`, `pass`, or `token`.

### 🌐 Service Intelligence (DPI-Lite)
- **Deep Service Correlation**: Identifies well-known platforms (Google Cloud, Meta AI, OpenAI, Netflix, etc.) by correlating DNS queries and TLS SNI handshakes.
- **Protocol Distribution**: Live visual density chart showing the ratio of HTTP, HTTPS, DNS, TCP, and UDP traffic.

### 🖥️ Dashboard & UX
- **Glassmorphic UI**: High-end modern dashboard with real-time "Network Pulse" throughput charts.
- **Signal Stream Dissector**: A high-speed packet stream with adaptive filtering (e.g., type "CRITICAL" to see only threats).
- **Forensic Hub**: An inspection sidebar for deep-diving into raw packet payloads and internal risk signatures.

---

## 🛠️ Technical Setup

### Prerequisites
- **Python 3.8+**
- **Npcap (Windows)** or **libpcap (Linux/macOS)**: Required for raw packet capture.
- **Admin Privileges**: Must be run in a session with Administrator/Root rights to access network hardware.

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/RATNAKIRAN93/hh8-minor-project-2.git
   cd hh8-minor-project-2
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Execution
1. Right-click your terminal (cmd/Powershell) and select **"Run as Administrator"**.
2. Start the server:
   ```bash
   python app.py
   ```
3. Open your browser to **[http://127.0.0.1:5001](http://127.0.0.1:5001)**.

---

## 📜 Project Structure
- `app.py`: Flask-SocketIO server and API gateway.
- `sniffer_engine.py`: Core Scapy-based capture engine and risk analysis logic.
- `templates/index.html`: Fully custom dashboard with Chart.js and Tailwind CSS.
- `requirements.txt`: Project dependencies (scapy, flask, flask-socketio).

---

**Disclaimer**: This tool is for educational and network diagnostic purposes only. Ensure you have explicit permission before capturing traffic on any network.
