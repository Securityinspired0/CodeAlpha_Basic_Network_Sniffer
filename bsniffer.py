import sys
from scapy.all import sniff, IP, TCP, UDP, ARP
from datetime import datetime

class PacketSniffer:
    def __init__(self, interface, verbose=False):
        self.interface = interface
        self.verbose = verbose
        self.logfile_name = f"sniffer_{interface}_log.txt"

    
    def handle_packet(self, packet):
        if IP in packet:
            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[IP].sport if TCP in packet else "N/A"
            dst_port = packet[IP].dport if TCP in packet else "N/A"
            with open(self.logfile_name, 'a') as log:
                if packet.haslayer(TCP):
                    log.write(f"[{timestamp}] TCP Connection - Source: {src_ip}:{src_port} --> Destination: {dst_ip}:{dst_port}\n")
                elif packet.haslayer(UDP):
                    log.write(f"[{timestamp}] UDP Connection - Source: {src_ip}:{src_port} --> Destination: {dst_ip}:{dst_port}\n")
                else:
                    log.write(f"Unknown Protocol - Source: {src_ip} --> Destination: {dst_ip}\n")
        else:
            print("Non-IP Packet")

    def start_sniffing(self):
        try:
            if self.verbose:
                sniff(iface=self.interface, prn=self.handle_packet, store=0, verbose=self.verbose)
            else:
                sniff(iface=self.interface, prn=self.handle_packet, store=0)
        except KeyboardInterrupt:
            sys.exit(0)

def run_sniffer():
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: Python sniffer.py <interface>")  
        sys.exit(1)

    interface = sys.argv[1]
    verbose = len(sys.argv) == 3 and sys.argv[2].lower == "verbose"

    sniffer = PacketSniffer(interface, verbose)
    sniffer.start_sniffing()


if __name__ == "__main__":
    run_sniffer()