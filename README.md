# Network-intrusion-detection-system
simple network intrusion detection system offering real time mobile alerts

# Overview
An Optimized Network Intrusion Detection System (NIDS) made specifically for small networks. Leveraging Python to sniff and analyze network traffic, focusing on the metadata of packets to identify potential threats. The system offers real-time monitoring through a dashboard and sends mobile notifications for detected intrusions. In turn providing an affordable and accessible security solution for small networks with limited resources.
The main reason for this repo is to better understand about packets, its structure, sniffing the packets, generation/spoofing of packets,and distinguishing between anomaly and safe packets in implementing the IDS

# Features
- Intrusion detection : Detection algorithm made from python analyzing captured metadata in packets
- Network Overview : Insight on the traffic sent and received in the network
- Alert notification : Real time alert notifications to the network admin or user

# System requirements
- Operating system : linux based os
- Python : Version 3
- Libraries : sqlite3(2.4.5), Tkinter, scapy
- NB: this was done on kali testing of the script and all the dependcacies needed for this were already preinstalled

# Installation 
- Import required libaries
- install pushover app and create account aswell as a key for mobile notification
- clone repository or copy script and run it
