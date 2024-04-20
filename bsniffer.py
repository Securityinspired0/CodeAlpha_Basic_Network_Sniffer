# Importing the necessary modules
import sys # For system related functions
from scapy.all import sniff, IP, TCP, UDP, ARP # For packet sniffing and parsing
from datetime import datetime # For timestamping packets

# Define a class for the packet sniffer
class PacketSniffer:
    """Initialize the sniffer with provided interface and verbosity settings"""
    def __init__(self, interface, verbose=False):
        self.interface = interface # Interface to sniff on
        self.verbose = verbose # Whether to print verbose output
        self.logfile_name = f"sniffer_{interface}_log.txt" # Name of log file to write to

    # Method to handle each sniffed packet
    def handle_packet(self, packet):
        if IP in packet: # Check if the packet is an IP packet
            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S') # Get packet timestamp
            src_ip = packet[IP].src # Source IP address
            dst_ip = packet[IP].dst # Destination IP address
            src_port = packet[IP].sport if TCP in packet else "N/A" # Source Port (if TCP)
            dst_port = packet[IP].dport if TCP in packet else "N/A" # Destination Port (if TCP)
            with open(self.logfile_name, 'a') as log: # Open logfile in append mode
                if packet.haslayer(TCP): # Check if packet is TCP  
                    log.write(f"[{timestamp}] TCP Connection - Source: {src_ip}:{src_port} --> Destination: {dst_ip}:{dst_port}\n") # Log TCP Connection
                elif packet.haslayer(UDP): # Checi if packet is UDP
                    log.write(f"[{timestamp}] UDP Connection - Source: {src_ip}:{src_port} --> Destination: {dst_ip}:{dst_port}\n") # Log UDP Connection
                else: # If neither TCP or UDP treat as unknown protocol
                    log.write(f"Unknown Protocol - Source: {src_ip} --> Destination: {dst_ip}\n") # Log unknown protocol
        else: # If not an IP packet
            print("Non-IP Packet") # Print message

    # Method to start packet sniffing
    def start_sniffing(self):
        try:
            if self.verbose: # If verbose mode is enabled
                sniff(iface=self.interface, prn=self.handle_packet, store=0, verbose=self.verbose) # Start sniffing with verbose output
            else: # If verbose mode is disabled
                sniff(iface=self.interface, prn=self.handle_packet, store=0) # Start sniffing without verbose output
        except KeyboardInterrupt: # Handle keyboard interrupt (Ctrl+C)
            sys.exit(0) # Exit gracefully

# Function to run the sniffer
def run_sniffer():
    if len(sys.argv) < 2 or len(sys.argv) > 3: # Check if the correct number of argument is provided
        print("Usage: Python bsniffer.py <interface>")  # Print usage information
        sys.exit(1) # Exit with error code

    interface = sys.argv[1] # Get interface from command line argument
    verbose = len(sys.argv) == 3 and sys.argv[2].lower == "verbose" # Check if verbose mode is enabled

    sniffer = PacketSniffer(interface, verbose) # Create PacketSniffer instance
    sniffer.start_sniffing() # Start packet sniffing

# Entry point of the script
if __name__ == "__main__":
    run_sniffer() # Call run_sniffer function