# Basic Packet Sniffer

# Overview

This is a basic packet sniffer script written in Python using the Scapy library. It captures network packet traversing a specified network interface and log information about them, such as source and destination IP addresses ports and protocol type.


# Features 

* Captures packets on a specified network interface.
* Log packet details including timestapms, source and destination IP addresses, ports and protocol type.
* Support Both TCP and UDP protocols
* Provides an option for verbose mode.

# Usage 

1. Ensure you have Python installed on your system.
2. Install the Scapy library by running 'pip install scapy'
3. Run the script with the following command "python bsniffer.py <interface> [verbose]" replace 'interface' with the name of the network interface you want to sniff on(e.g., eth0). Optionally, include the word verbose as the second argument to enable verbose mode for real-time packet information.
4. The script will start capturing packets on the specified interface and log them to a file named sniffer_<interface>_log.txt.

# EXAMPLE 

To sniff packets on the eth0 interface in verbose mode:
 python bsniffer.py eth0 verbose


