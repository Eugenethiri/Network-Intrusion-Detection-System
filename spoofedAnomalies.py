#!/usr/bin/env python3

from scapy.all import IP, TCP, UDP, ICMP, send

"""id,src_ip,dst_ip,protocol,src_port,dst_port,length,flags,ttl,anomaly_type
1,192.168.1.10,192.168.1.20,TCP,1234,80,1500,SYN,64,No Anomaly
2,192.168.1.15,192.168.1.25,UDP,4444,1337,5000,0,255,Unusual Port Number
3,10.0.0.1,192.168.1.30,ICMP,0,0,56,0,1,Unusual TTL
4,192.168.1.50,192.168.1.60,TCP,5555,80,1500,SYN|FIN,64,Invalid Flag Combination
5,8.8.8.8,192.168.1.70,TCP,80,80,4000,RST,128,No Anomaly
6,172.16.0.1,192.168.1.80,UDP,53,53,200,0,30,Reserved IP Range
7,192.168.1.90,192.168.1.100,TCP,4444,80,1500,SYN,64,Known Malicious Port
8,192.168.1.110,8.8.8.8,TCP,3333,80,2500,PSH|ACK,255,Suspicious TTL
9,192.168.1.120,192.168.1.130,TCP,22,80,1500,URG|PSH,50,Suspicious Flags
10,192.168.1.140,192.168.1.150,UDP,137,138,4500,0,64,Unusually Large Packet
"""


# Define packets based on the above provided dataset
packets = [
    {"id": 1, "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20", "protocol": "TCP", "src_port": 1234, "dst_port": 80, "length": 1500, "flags": "S", "ttl": 64, "anomaly_type": "No Anomaly"},
    {"id": 2, "src_ip": "192.168.1.15", "dst_ip": "192.168.1.25", "protocol": "UDP", "src_port": 4444, "dst_port": 1337, "length": 5000, "flags": "0", "ttl": 255, "anomaly_type": "Unusual Port Number"},
    {"id": 3, "src_ip": "10.0.0.1", "dst_ip": "192.168.1.30", "protocol": "ICMP", "src_port": 0, "dst_port": 0, "length": 56, "flags": "0", "ttl": 1, "anomaly_type": "Unusual TTL"},
    {"id": 4, "src_ip": "192.168.1.50", "dst_ip": "192.168.1.60", "protocol": "TCP", "src_port": 5555, "dst_port": 80, "length": 1500, "flags": "SF", "ttl": 64, "anomaly_type": "Invalid Flag Combination"},
    {"id": 5, "src_ip": "8.8.8.8", "dst_ip": "192.168.1.70", "protocol": "TCP", "src_port": 80, "dst_port": 80, "length": 4000, "flags": "R", "ttl": 128, "anomaly_type": "No Anomaly"},
    {"id": 6, "src_ip": "172.16.0.1", "dst_ip": "192.168.1.80", "protocol": "UDP", "src_port": 53, "dst_port": 53, "length": 200, "flags": "0", "ttl": 30, "anomaly_type": "Reserved IP Range"},
    {"id": 7, "src_ip": "192.168.1.90", "dst_ip": "192.168.1.100", "protocol": "TCP", "src_port": 4444, "dst_port": 80, "length": 1500, "flags": "S", "ttl": 64, "anomaly_type": "Known Malicious Port"},
    {"id": 8, "src_ip": "192.168.1.110", "dst_ip": "8.8.8.8", "protocol": "TCP", "src_port": 3333, "dst_port": 80, "length": 2500, "flags": "PA", "ttl": 255, "anomaly_type": "Suspicious TTL"},
    {"id": 9, "src_ip": "192.168.1.120", "dst_ip": "192.168.1.130", "protocol": "TCP", "src_port": 22, "dst_port": 80, "length": 1500, "flags": "UP", "ttl": 50, "anomaly_type": "Suspicious Flags"},
    {"id": 10, "src_ip": "192.168.1.140", "dst_ip": "192.168.1.150", "protocol": "UDP", "src_port": 137, "dst_port": 138, "length": 4500, "flags": "0", "ttl": 64, "anomaly_type": "Unusually Large Packet"},
]

# Function to create and send spoofed packets
def create_and_send_packet(packet):
    ip_layer = IP(src=packet["src_ip"], dst=packet["dst_ip"], ttl=packet["ttl"])
    
    if packet["protocol"] == "TCP":
        # Handle flags for TCP (Scapy uses string representation for flags)
        flags = packet["flags"]
        tcp_layer = TCP(sport=packet["src_port"], dport=packet["dst_port"], flags=flags)
        pkt = ip_layer / tcp_layer
    elif packet["protocol"] == "UDP":
        udp_layer = UDP(sport=packet["src_port"], dport=packet["dst_port"])
        pkt = ip_layer / udp_layer
    elif packet["protocol"] == "ICMP":
        icmp_layer = ICMP()
        pkt = ip_layer / icmp_layer
    
    send(pkt)
    print(f"Sent packet: {packet['anomaly_type']}")

# Send all packets
for packet in packets:
    create_and_send_packet(packet)

