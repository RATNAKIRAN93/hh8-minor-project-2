import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
import threading
import time
import json
import logging
import warnings
from datetime import datetime

# Suppress scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")

# Try to load TLS layers
try:
    scapy.load_layer("tls")
    if not hasattr(scapy, "TLS"):
        from scapy.layers.tls.all import TLS
        scapy.bind_layers(scapy.TCP, TLS, dport=443)
except:
    pass

class PacketSnifferEngine:
    def __init__(self, interface=None, socket_io=None):
        self.interface = interface
        self.sio = socket_io
        self.is_sniffing = False
        self.packet_count = 0
        self.start_time = None
        self.stats = {
            "packet_count": 0,
            "protocols": {"HTTP": 0, "HTTPS": 0, "DNS": 0, "TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0},
            "total_bytes": 0,
            "top_ips": {},
            "top_dst_ips": {},
            "unique_hosts": 0,
            "bps": 0,
            "pps": 0,
            "history": [] 
        }
        self.pcap_file = "capture_history.pcap"
        self._last_stats_time = time.time()
        self._last_byte_count = 0
        self._last_packet_count = 0
        self.unique_srcs = set()
        self.unique_dsts = set()
        
        # Security/Anomaly Tracking
        self.connection_counts = {} # src -> set of (dst, dport)
        self.arp_table = {} # ip -> mac
        self.anomalies = []
        
        # Batching
        self.packet_batch = []
        self._last_batch_time = time.time()

    def detect_service(self, info):
        """Identifies the service/platform based on SNI or DNS."""
        info = info.lower()
        if any(x in info for x in ['google', 'gstatic', 'youtube', 'googlevideo']): return 'Google Cloud'
        if any(x in info for x in ['facebook', 'fbcdn', 'instagram', 'whatsapp']): return 'Meta AI/Social'
        if any(x in info for x in ['netflix', 'nflxvideo']): return 'Netflix CDN'
        if any(x in info for x in ['amazon', 'aws', 'cloudfront']): return 'AWS/CloudFront'
        if any(x in info for x in ['microsoft', 'azure', 'windowsupdate', 'office']): return 'Microsoft Azure'
        if any(x in info for x in ['apple', 'icloud', 'itunes']): return 'Apple Services'
        if any(x in info for x in ['spotify']): return 'Spotify Music'
        if any(x in info for x in ['discord']): return 'Discord Hub'
        if any(x in info for x in ['telegram']): return 'Telegram Sec'
        if any(x in info for x in ['openai', 'chatgpt']): return 'OpenAI/GPT'
        if any(x in info for x in ['github']): return 'GitHub/Git'
        return 'Standard Traffic'

    def get_tls_sni(self, packet):
        """Extracts Server Name Indication from TLS Client Hello."""
        try:
            if packet.haslayer(scapy.TCP) and packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                # Simple heuristic for TLS Client Hello SNI extraction
                if b"\x16\x03" in payload: # Handshake + Version
                    # Look for host-like strings in the payload
                    import re
                    match = re.search(rb'[a-z0-9.-]+\.[a-z]{2,}', payload.lower())
                    if match: return match.group(0).decode(errors='ignore')
        except: pass
        return None

    def update_stats(self, packet):
        """Updates internal metrics for the dashboard."""
        self.stats["packet_count"] += 1
        self.stats["total_bytes"] += len(packet)
        
        # Protocol Count
        if packet.haslayer(HTTPRequest): self.stats["protocols"]["HTTP"] += 1
        elif packet.haslayer(scapy.DNS): self.stats["protocols"]["DNS"] += 1
        elif packet.haslayer(scapy.TCP):
            if packet.haslayer(scapy.Raw) and b"\x16\x03" in packet[scapy.Raw].load:
                self.stats["protocols"]["HTTPS"] += 1
            else: self.stats["protocols"]["TCP"] += 1
        elif packet.haslayer(scapy.UDP): self.stats["protocols"]["UDP"] += 1
        elif packet.haslayer(scapy.ICMP): self.stats["protocols"]["ICMP"] += 1
        else: self.stats["protocols"]["Other"] += 1
        
        # IP Stats
        if packet.haslayer(scapy.IP):
            src, dst = packet[scapy.IP].src, packet[scapy.IP].dst
            self.unique_srcs.add(src)
            self.unique_dsts.add(dst)
            self.stats["top_ips"][src] = self.stats["top_ips"].get(src, 0) + 1
            self.stats["top_dst_ips"][dst] = self.stats["top_dst_ips"].get(dst, 0) + 1
            self.stats["unique_hosts"] = len(self.unique_srcs | self.unique_dsts)

        # Throughput Calculations every 1s
        now = time.time()
        if now - self._last_stats_time > 1.0:
            elapsed = now - self._last_stats_time
            self.stats["pps"] = int((self.stats["packet_count"] - self._last_packet_count) / elapsed)
            self.stats["bps"] = int((self.stats["total_bytes"] - self._last_byte_count) * 8 / elapsed)
            
            # History for chart
            self.stats["history"].append({"t": datetime.now().strftime("%H:%M:%S"), "bps": self.stats["bps"]})
            if len(self.stats["history"]) > 20: self.stats["history"].pop(0)
            
            self._last_stats_time = now
            self._last_byte_count = self.stats["total_bytes"]
            self._last_packet_count = self.stats["packet_count"]

    def analyze_risk(self, packet, protocol, info):
        """Calculates a simple risk score/level."""
        risk = "SAFE"
        risk_desc = "Nominal"
        
        # 1. Cleartext HTTP
        if protocol == "HTTP": 
            risk = "WARN"
            risk_desc = "Unencrypted Protocol"
            if any(x in info.lower() for x in ["login", "pass", "auth", "token", "cookie"]):
                risk = "CRITICAL"
                risk_desc = "Credential Exposure"
        
        # 2. Suspicious Ports
        if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
            port = packet[scapy.TCP].dport if packet.haslayer(scapy.TCP) else packet[scapy.UDP].dport
            sus_ports = {21: "FTP", 23: "Telnet", 445: "SMB/Exploit?", 3389: "RDP"}
            if port in sus_ports:
                risk = "WARN"
                risk_desc = f"Legacy/Vulnerable Port ({sus_ports[port]})"

        # 3. Behavioral: Port Scanning Detection
        if packet.haslayer(scapy.IP):
            src = packet[scapy.IP].src
            dst = packet[scapy.IP].dst
            if packet.haslayer(scapy.TCP):
                dport = packet[scapy.TCP].dport
                if src not in self.connection_counts: self.connection_counts[src] = set()
                self.connection_counts[src].add((dst, dport))
                
                if len(self.connection_counts[src]) > 50:
                    risk = "CRITICAL"
                    risk_desc = "Potential Port Scanning"

        # 4. ARP Spoofing Detection
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2: # is-at (reply)
            ip = packet[scapy.ARP].psrc
            mac = packet[scapy.ARP].hwsrc
            if ip in self.arp_table and self.arp_table[ip] != mac:
                risk = "CRITICAL"
                risk_desc = "ARP Poisoning Detected"
            self.arp_table[ip] = mac
                
        return risk, risk_desc

    def process_packet(self, packet):
        self.packet_count += 1
        self.update_stats(packet)
        
        # Save to PCAP
        try:
            scapy.wrpcap(self.pcap_file, packet, append=True)
        except:
            pass
            
        packet_info = {
            "id": self.packet_count,
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src": packet[scapy.IP].src if packet.haslayer(scapy.IP) else (packet[scapy.Ether].src if packet.haslayer(scapy.Ether) else "Unknown"),
            "dst": packet[scapy.IP].dst if packet.haslayer(scapy.IP) else (packet[scapy.Ether].dst if packet.haslayer(scapy.Ether) else "Unknown"),
            "protocol": "Other",
            "length": len(packet),
            "info": "",
            "service": "Unknown",
            "risk": "SAFE",
            "risk_desc": "Nominal"
        }

        # Protocol Identification
        if packet.haslayer(HTTPRequest):
            packet_info["protocol"] = "HTTP"
            try:
                host = packet[HTTPRequest].Host.decode(errors='ignore')
                path = packet[HTTPRequest].Path.decode(errors='ignore')
                packet_info["info"] = f"GET {host}{path}"
            except: packet_info["info"] = "HTTP Request"
        elif packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
            packet_info["protocol"] = "DNS"
            try:
                query = packet[scapy.DNSQR].qname.decode(errors='ignore')
                packet_info["info"] = f"Query: {query}"
            except: packet_info["info"] = "DNS Query"
        elif packet.haslayer(scapy.TCP):
            sni = self.get_tls_sni(packet)
            if sni:
                packet_info["protocol"] = "HTTPS (TLS)"
                packet_info["info"] = f"SNI: {sni}"
            else:
                packet_info["protocol"] = "TCP"
                packet_info["info"] = f"Port: {packet[scapy.TCP].sport} -> {packet[scapy.TCP].dport}"
        elif packet.haslayer(scapy.UDP):
            packet_info["protocol"] = "UDP"
            packet_info["info"] = f"Port: {packet[scapy.UDP].sport} -> {packet[scapy.UDP].dport}"
        elif packet.haslayer(scapy.ICMP):
            packet_info["protocol"] = "ICMP"
            packet_info["info"] = f"Type: {packet[scapy.ICMP].type} Code: {packet[scapy.ICMP].code}"
        elif packet.haslayer(scapy.ARP):
            packet_info["protocol"] = "ARP"
            op = "Request" if packet[scapy.ARP].op == 1 else "Reply"
            packet_info["info"] = f"ARP {op} {packet[scapy.ARP].psrc} -> {packet[scapy.ARP].pdst}"

        # Enhanced Detection Logic
        packet_info['service'] = self.detect_service(packet_info['info'])
        packet_info['risk'], packet_info['risk_desc'] = self.analyze_risk(packet, packet_info['protocol'], packet_info['info'])

        # IMMEDIATE EMISSION (No batching for stability check)
        if self.sio:
            self.sio.emit('new_packet', packet_info)
            # Only emit stats every 1 second to avoid overload
            if time.time() - self._last_stats_time > 1.0:
                self.sio.emit('update_stats', self.stats)

    def start(self):
        if self.is_sniffing: return
        self.is_sniffing = True
        self.start_time = time.time()
        self.packet_count = 0
        
        print("[DEBUG] PacketSnifferEngine.start() called", flush=True)
        if self.sio: self.sio.emit('log', {'message': "SYSTEM: Preparing Capture Engine..."})

        # 1. Smart Interface Detection for Windows
        from scapy.all import IFACES, conf
        if not self.interface or self.interface == "Default":
            try:
                selected_iface = None
                for iface_id in IFACES:
                    iface = IFACES[iface_id]
                    if hasattr(iface, 'ip') and iface.ip and iface.ip != '0.0.0.0' and iface.ip != '127.0.0.1':
                        selected_iface = iface
                        break
                if selected_iface:
                    self.interface = selected_iface
                    if self.sio: self.sio.emit('log', {'message': f"AUTO: Using {selected_iface.description}"})
                else:
                    self.interface = conf.iface
                    if self.sio: self.sio.emit('log', {'message': f"WARN: No active IP. Using default adapter."})
            except Exception as e:
                print(f"[ERROR] Detection failed: {e}", flush=True)
        elif isinstance(self.interface, str):
            if self.interface in IFACES:
                self.interface = IFACES[self.interface]

        # 2. Status Threads
        def status_monitor():
            h_count = 0
            while self.is_sniffing:
                h_count += 1
                msg = f"STATUS: Engine Operational (Uptime: {h_count*10}s | Packets: {self.packet_count})"
                if self.sio: self.sio.emit('log', {'message': msg})
                print(f"[DEBUG] {msg}", flush=True)
                
                # Simulation Injector: Every 20s if no real traffic, send a dummy
                if h_count % 2 == 0:
                    try:
                        dummy_pkt = scapy.IP(src="127.0.0.1", dst="1.1.1.1")/scapy.TCP(sport=1234, dport=80)
                        self.process_packet(dummy_pkt)
                        if self.sio: self.sio.emit('log', {'message': "DEBUG: Simulation packet injected into stream."})
                    except Exception as ex:
                        print(f"[DEBUG] Simulation inject failed: {ex}")
                
                time.sleep(10)
        
        threading.Thread(target=status_monitor, daemon=True).start()

        # 3. Main Sniff Task
        def sniff_task():
            try:
                iface_id = getattr(self.interface, 'name', str(self.interface))
                iface_desc = getattr(self.interface, 'description', str(self.interface))
                
                print(f"[DEBUG] STARTING SNIFF ON: {iface_id} ({iface_desc})", flush=True)
                if self.sio: 
                    self.sio.emit('log', {'message': f"STARTING ON: {iface_desc}"})
                    self.sio.emit('status', {'status': 'running'})
                
                # Persistent loop for Windows stability
                while self.is_sniffing:
                    try:
                        scapy.sniff(
                            iface=self.interface,
                            store=False,
                            prn=self.process_packet,
                            stop_filter=lambda x: not self.is_sniffing
                        )
                    except Exception as sniff_err:
                        print(f"[DEBUG] Sniff Loop Exception: {sniff_err}", flush=True)
                        if self.is_sniffing: time.sleep(2)
                
                print("[DEBUG] Scapy sniff task finished", flush=True)
                if self.sio: self.sio.emit('log', {'message': "STOPPED: Capture process ended."})

            except Exception as e:
                err_msg = f"ERROR: Capture Exception - {str(e)}"
                print(f"[CRITICAL] {err_msg}", flush=True)
                if self.sio:
                    self.sio.emit('error', {'message': err_msg})
                    self.sio.emit('log', {'message': err_msg})
                    self.sio.emit('status', {'status': 'stopped'})
                self.is_sniffing = False

        threading.Thread(target=sniff_task, daemon=True).start()

    def stop(self):
        self.is_sniffing = False
        print("[*] Engine stopping...")
