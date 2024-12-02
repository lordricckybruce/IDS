#!/bin/python3
 '''
******Using Pyshark
Buidling  an ids without using scapy makes it more powerful because 
libraries like Pyshark are optimized for high speed
---Efficiency
---Compatability
---Advanced Features and detection is advanced, flexibility is moderate

******Using scapy:
only packet capture --- moderate level
ease of use -- easy 
and detection capabilities are just basic
flexibility is high
****Using raw sockets:
pacture capture at a high perfomance
ease of use is difficult
detection capabilities is ok/moderate
flexibility is high like scapy
'''

#Using Pyshark
import pyshark
#a python wrapper , for capturing and analyzing packets in a higher level
def packet_callback(packet): #defined the function to handle each captured packets during live capture
    try:
        if 'IP' in packet:  #checks for captured packets in the ip layer
            ip_src = packet.ip.src   #Extract source and destinantion of ip
            ip_dst = packet.ip.dst
            print(f"Packet: {ip_src} -> {ip_dst}")
            
        if 'ICMP' in packet:   #checks if the packets contains the icmp layer 
            print(f"ICMP Packet: {packet.ip.src} -> {packet.ip.dst}") #logs icmp packets separately
            
        if 'TCP' in packet: #checks if packet contains tcp layer
            tcp_flags = packet.tcp.flags  #extracts tcp flags
            if tcp_flags == '0x02':  # SYN flag 
                print(f"Port Scan Detected: {packet.ip.src} -> {packet.ip.dst}")   #logs when a possible port scan is detected
    except AttributeError:  #handles errors
        pass  # Some packets might lack certain layers,  prevents program from crashing

def start_sniffing(interface):  #defines the function to begin packet sniffing
    print(f"Starting IDS on {interface}...")
    capture = pyshark.LiveCapture(interface=interface) #sets up a live packet capture on the specified interface
    capture.apply_on_packets(packet_callback) #applies the packet_callback function to each captured packet

if __name__ == "__main__":
    start_sniffing('eth0')  # Replace 'eth0' with your network interface
#ensures code run
#start_sniffing on the eth0 interface




#2 Using Raw sockets

import socket #for networks connection
import struct  #helps unpack binary 

def parse_packet(packet):  #defines the function to parse a captured packet
    # Unpack Ethernet frame
    eth_length = 14  #ethernet header length (14bytes)
    eth_header = packet[:eth_length]  #extract the ethernet header from the packet
    eth = struct.unpack('!6s6sH', eth_header) #unpacks the ethernet frame header
    eth_protocol = socket.ntohs(eth[2]) #converts the protocol field to a readable format
    
    # Parse IP packets
    if eth_protocol == 8:  # IP Protocol -- checks if packet is an ip packet
        ip_header = packet[eth_length:20 + eth_length] #extract the ip header
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)  #unpacks the ip header fields
        ip_src = socket.inet_ntoa(iph[8]) # converts the source ip address to humn readable form
        ip_dst = socket.inet_ntoa(iph[9]) 
        print(f"IP Packet: {ip_src} -> {ip_dst}") #logs the source and destination ip address

def start_sniffing():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #creates a raw socket to capture all packets
	#AF_PACKET caputres ethernet frames, SOCK_RAW -- allows access to raw packets, socket_ntohs --- captures all protocols(ipv4,arp)
    print("Listening for packets...")
    while True:
        raw_packet = conn.recvfrom(65565)[0]
        parse_packet(raw_packet)

if __name__ == "__main__":
    start_sniffing()


