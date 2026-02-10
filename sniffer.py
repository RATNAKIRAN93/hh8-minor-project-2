
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
import argparse
from colorama import init, Fore, Style
import logging
import sys

# Initialize colorama
init()

def get_arguments():
    parser = argparse.ArgumentParser(description="Packet Sniffer for HTTP Traffic")
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to sniff on")
    parser.add_argument("-l", "--list", dest="list_interfaces", action="store_true", help="List available interfaces")
    parser.add_argument("-o", "--output", dest="output", help="Output file to log captured packets", default="captured_traffic.txt")
    options = parser.parse_args()
    return options

def setup_logger(output_file):
    logger = logging.getLogger("TrafficLogger")
    logger.setLevel(logging.INFO)
    
    # File handler
    fh = logging.FileHandler(output_file)
    fh.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    
    return logger

def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        # Extract HTTP details
        http_layer = packet[HTTPRequest]
        url = http_layer.Host.decode() + http_layer.Path.decode()
        method = http_layer.Method.decode()
        
        # Extract User-Agent & Referer if present
        user_agent = http_layer.User_Agent.decode() if http_layer.User_Agent else "Unknown"
        referer = http_layer.Referer.decode() if http_layer.Referer else "None"

        # Extract IP details
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
        else:
            src_ip = packet[scapy.IPv6].src if packet.haslayer(scapy.IPv6) else "Unknown"
            dst_ip = packet[scapy.IPv6].dst if packet.haslayer(scapy.IPv6) else "Unknown"
            
        log_message = f"[+] {src_ip} -> {dst_ip} | {method} {url}"
        details = f"    User-Agent: {user_agent}\n    Referer: {referer}"
        
        print(f"{Fore.GREEN}{log_message}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{details}{Style.RESET_ALL}")
        
        log_entry = f"{log_message}\n{details}"

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            print(f"{Fore.YELLOW}    Data: {load}{Style.RESET_ALL}")
            log_entry += f"\n    Data: {load}"
            
        logger.info(log_entry)

def sniff(interface):
    print(f"{Fore.CYAN}[*] Starting Sniffer...{Style.RESET_ALL}")
    if interface:
        print(f"{Fore.CYAN}[*] Interface: {interface}{Style.RESET_ALL}")
        scapy.sniff(iface=interface, store=False, prn=process_packet, filter="tcp port 80")
    else:
        print(f"{Fore.CYAN}[*] Interface: Default (All){Style.RESET_ALL}")
        # On Windows, sniff() without iface might not list all interfaces correctly depending on Npcap
        # But we'll try default first or let scapy decide.
        scapy.sniff(store=False, prn=process_packet, filter="tcp port 80")

if __name__ == "__main__":
    options = get_arguments()
    
    if options.list_interfaces:
        print(f"{Fore.CYAN}[*] Available Interfaces:{Style.RESET_ALL}")
        scapy.show_interfaces()
        sys.exit(0)
        
    logger = setup_logger(options.output)
    
    try:
        sniff(options.interface)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Stopping Sniffer.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
