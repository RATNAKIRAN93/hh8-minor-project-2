from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO
from sniffer_engine import PacketSnifferEngine
import threading
import sys
import os

app = Flask(__name__)
# Use async_mode='threading' for better compatibility with Scapy on Windows
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

sniffer = None
sniffer_thread = None

@app.route('/download_pcap')
def download_pcap():
    pcap_path = os.path.join(os.getcwd(), "capture_history.pcap")
    if os.path.exists(pcap_path):
        return send_file(pcap_path, as_attachment=True)
    return "PCAP file not found", 404

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print('[+] Client connected')

@socketio.on('start_sniffing')
def handle_start(data):
    print(f"\n[SOCKET] START_SNIFFING REQUESTED: {data}", flush=True)
    global sniffer
    if sniffer and sniffer.is_sniffing:
        print("[SOCKET] Sniffer already active. Ignoring.", flush=True)
        return
    
    interface_id = data.get('interface')
    print(f"[SOCKET] Initializing engine on: {interface_id}", flush=True)
    sniffer = PacketSnifferEngine(interface=interface_id, socket_io=socketio)
    sniffer.start()

@socketio.on('stop_sniffing')
def handle_stop():
    global sniffer
    if sniffer:
        sniffer.stop()
    socketio.emit('status', {'status': 'stopped'})

@socketio.on('get_status')
def handle_get_status():
    global sniffer
    status = 'running' if (sniffer and sniffer.is_sniffing) else 'stopped'
    print(f"[DEBUG] Client requested status. Current: {status}", flush=True)
    socketio.emit('status', {'status': status})

@app.route('/interfaces')
def get_interfaces():
    try:
        from scapy.all import IFACES
        active = []
        for iface_id in IFACES:
            iface = IFACES[iface_id]
            # Prioritize interfaces with IPs and recognizable names
            if hasattr(iface, 'ip') and iface.ip and iface.ip != '0.0.0.0' and iface.ip != '127.0.0.1':
                active.append({
                    'name': f"{iface.name} [{iface.description[:40]}]",
                    'id': iface_id # This will be \Device\NPF_{...}
                })
        
        if not active:
            # Fallback to anything in IFACES
            active = [{'name': v.name, 'id': k} for k, v in IFACES.items()]
            
        return jsonify(active)
    except Exception as e:
        print(f"Error fetching interfaces: {e}")
        return jsonify([{'name': "Default (Auto)", 'id': "Default"}])

@app.route('/simulate_packet')
def simulate_packet():
    # Test method to verify UI is receiving events
    dummy = {
        "id": 999999,
        "timestamp": "TEST_TIME",
        "src": "SIMULATED_SRC",
        "dst": "SIMULATED_DST",
        "protocol": "TEST-PROTO",
        "length": 128,
        "info": "This is a simulated packet to verify UI connectivity.",
        "service": "Voyager Simulator",
        "risk": "WARN",
        "risk_desc": "Developer Test Signal"
    }
    socketio.emit('new_packet', dummy)
    return "OK"

if __name__ == '__main__':
    print("\n" + "="*50)
    print("   PACKET VOYAGER - ADVANCED TRAFFIC ANALYZER")
    print("="*50)
    print("[*] Dashboard available at: http://127.0.0.1:5001")
    print("[!] Ensure you are running as Administrator")
    print("="*50 + "\n")
    
    socketio.run(app, debug=False, log_output=True, port=5001, allow_unsafe_werkzeug=True)
