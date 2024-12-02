#!/bin/python3

'''
An intrusion detection system is a security mechanism designed to monitor network
traffic, detect potential malicious activities and alert administrators when
such activities are detected. the main goal is to identify  unauthorised access
or abnormal behaviour within a network or system
key functions;
detection, alerting,logging<recording details of suspicious events 
for further analysis or forensic investigation
threats detected by ids are
port scanning, dos,malware,sql injection, xss, unauthorised access
'''
import scapy.all as scapy  #all scapy library for packet manipulation
import logging
from scapy.layers.inet import IP, ICMP, TCP  #These are layers from scapy used to analyze specific parts of network packets

# Setup logging for alerts
logging.basicConfig(filename="ids_log.txt", level=logging.INFO)
'''this configures the logging mechanism.All alerts will be
 written  to file ids_log.txt
'''
# Function to capture and analyze packets
def packet_callback(packet): #the function is called for every packet captured by scapy.sniff()
    # Log information about each packet
    if packet.haslayer(IP):
        ip_src = packet[IP].src  #Extracts the source IP address of the packet
        ip_dst = packet[IP].dst  #destination ip 
        protocol = packet[IP].proto   #protocol; tcp,udo,icmp

        # Check for ICMP (Ping) packets - Common for DoS detection
	# icmp is used for ping request
        if packet.haslayer(ICMP):
            logging.info(f"ICMP Packet Detected: {ip_src} -> {ip_dst}")
            print(f"ICMP Packet Detected: {ip_src} -> {ip_dst}")

        # Check for TCP packets and port scanning attempts
        if packet.haslayer(TCP):
            tcp_flags = packet[TCP].flags
            if tcp_flags == 0x02:  # SYN flag, common in port scanning, correspons with syn flag used for port scanning
                logging.info(f"Port Scan Attempt: {ip_src} -> {ip_dst}")
                print(f"Port Scan Attempt: {ip_src} -> {ip_dst}")
		# if the syn packet is detected, it logs the event as a port scan attempt
    # Check for any suspicious high-frequency traffic (DoS-like behavior)
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        packet_count = len(scapy.sniff(filter=f"src host {ip_src}", count=100))  # Check if source IP is flooding
        if packet_count > 100:
            logging.warning(f"Possible DoS Attack from {ip_src}")
            print(f"Possible DoS Attack from {ip_src}")
		#scapy.sniff is used to sniff packets from the same source ip to count the number of packets

# Start sniffing packets
def start_sniffing():
    print("IDS Started... Listening for suspicious activities...")
    scapy.sniff(prn=packet_callback, store=False)
	#callback will be called for each captured packet
	#store=false means we don't store the packets in memory, only to analyse
if __name__ == "__main__":
    start_sniffing()
#ensures that start_sniffing function runs when the script is executed
'''advantages are
real-time detection,customizabe,cost effective
'''
