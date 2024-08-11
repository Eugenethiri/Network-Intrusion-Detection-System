#!/usr/bin/env python3

import sqlite3
import threading
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
import http.client
import urllib

# Logo

logo = r"""
 

                                                                                                      
  .--,-``-.                                                                                           
 /   /     '.        ,-.             ,--,                              ,---,    ,---,      .--.--.    
/ ../        ;   ,--/ /|           ,--.'|     ,--,                  ,`--.' |  .'  .' `\   /  /    '.  
\ ``\  .`-    ',--. :/ |           |  | :   ,--.'|                  |   :  :,---.'     \ |  :  /`. /  
 \___\/   \   ::  : ' /            :  : '   |  |,                   :   |  '|   |  .`\  |;  |  |--`   
      \   :   ||  '  /    ,--.--.  |  ' |   `--'_                   |   :  |:   : |  '  ||  :  ;_     
      /  /   / '  |  :   /       \ '  | |   ,' ,'|                  '   '  ;|   ' '  ;  : \  \    `.  
      \  \   \ |  |   \ .--.  .-. ||  | :   '  | |                  |   |  |'   | ;  .  |  `----.   \ 
  ___ /   :   |'  : |. \ \__\/: . .'  : |__ |  | :                  '   :  ;|   | :  |  '  __ \  \  | 
 /   /\   /   :|  | ' \ \," .--.; ||  | '.'|'  : |__                |   |  |'   | :  |  '  __ \  \  | 
/ ,,/  ',-    .'  : |--'/  /  ,.  |;  :    ;|  | '.'|               '   :  ||   : | /  ;  /  /`--'  / 
\ ''\        ; ;  |,'  ;  :   .'   \  ,   / ;  :    ;               ;   |.' ;   :  .'      `--'---'   
 \   \     .'  '--'    |  ,     .-./---`-'  |  ,   /                '---'   |   ,.'                   
  `--`-,,-'             `--`---'             ---`-'                         '---'                     
                                                                                                      


"""

def display_logo():
    print(logo)

# Alert notification via Pushover app
def send_pushover_notification(token, user_key, message):
    conn = http.client.HTTPSConnection("api.pushover.net:443")
    conn.request("POST", "/1/messages.json",
        urllib.parse.urlencode({
            "token": token,  # API KEY TOKEN
            "user": user_key,  # USER KEY TOKEN
            "message": message,
        }), { "Content-type": "application/x-www-form-urlencoded" })
    conn.getresponse()


# Sniffer + database (packets.db)
class PacketCapture:
    def __init__(self, db_name='packets.db', interface='wlan0'):
        self.conn = sqlite3.connect(db_name, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.interface = interface
        self.create_table()
        self.running = True

        # Replace these with your actual Pushover API credentials
        self.pushover_token = "xxxxxxxxxxxxxx" #input key
        self.pushover_user_key = "xxxxxxxxxxxx" #input key

    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                length INTEGER,
                flags TEXT,
                ttl INTEGER,
                payload BLOB,
                anomaly TEXT,
                description TEXT
            )
        ''')
        self.conn.commit()
        
    # IDS engine
    def analyze_packet(self, src_ip, dst_ip, protocol, src_port, dst_port, length, flags, ttl):
        anomaly = "No Anomaly"
        description = ""
        
        # Predetermined unusual ports
        unusual_ports = {4444, 1337}
        if src_port in unusual_ports or dst_port in unusual_ports:
            anomaly = "Anomaly"
            description = "Unusual Port Number"
            
        # DDOS TTL
        if ttl == 1:
            anomaly = "Anomaly"
            description = "Unusual TTL"
            
        # TCP SYN attack
        if protocol == 'TCP' and ('S' in flags and 'F' in flags):
            anomaly = "Anomaly"
            description = "Invalid Flag Combination"
            
        if protocol == 'TCP' and ('U' in flags and 'P' in flags):
            anomaly = "Anomaly"
            description = "Invalid Flag Combination"
            
        # Predetermined blacklisting IPs
        reserved_ip_ranges = ["172.16.", "192.0.2.", "198.51.100.", "203.0.113."]
        if any(src_ip.startswith(range) for range in reserved_ip_ranges) or any(dst_ip.startswith(range) for range in reserved_ip_ranges):
            anomaly = "Anomaly"
            description = "Reserved IP Range"
            
        # Metasploit known port or known malicious port (Blaster worm vuln)
        known_malicious_ports = {4444}
        if src_port in known_malicious_ports or dst_port in known_malicious_ports:
            anomaly = "Anomaly"
            description = "Known Malicious Port"

        LARGE_PACKET_THRESHOLD = 4000
        if length > LARGE_PACKET_THRESHOLD:
            anomaly = "Anomaly"
            description = "Unusually Large Packet"

        return anomaly, description
        
    # Extract packet metadata
    def process_packet(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol_number = packet[IP].proto
                length = len(packet)
                ttl = packet[IP].ttl
                flags = ""
                payload = b''  # Default empty payload

                # Initialize ports to None in case not used
                src_port = None
                dst_port = None

                if protocol_number == 1:
                    protocol = 'ICMP'
                    payload = bytes(packet[ICMP].payload)
                elif protocol_number == 6:
                    protocol = 'TCP'
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    payload = bytes(packet[TCP].payload)
                    flags = packet[TCP].flags
                elif protocol_number == 17:
                    protocol = 'UDP'
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    payload = bytes(packet[UDP].payload)
                else:
                    protocol = f'OTHER ({protocol_number})'

                anomaly, description = self.analyze_packet(src_ip, dst_ip, protocol, src_port, dst_port, length, str(flags), ttl)

                # Insert packet data into the database
                self.cursor.execute('''
                    INSERT INTO packets (src_ip, dst_ip, protocol, length, flags, ttl, payload, anomaly, description)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (src_ip, dst_ip, protocol, length, str(flags), ttl, payload, anomaly, description))
                self.conn.commit()

                # Print packet information to the terminal
                print(f'Packet captured: src_ip={src_ip}, dst_ip={dst_ip}, protocol={protocol}, length={length}, flags={flags}, ttl={ttl}, anomaly={anomaly}, description={description}')

                # Send a notification if an anomaly is detected
                if anomaly == "Anomaly":
                    send_pushover_notification(self.pushover_token, self.pushover_user_key, f"Intrusion detected! Source IP: {src_ip}, Description: {description}")

        except Exception as e:
            print(f'Unexpected error: {e}')

    def capture_packets(self):
        sniff(iface=self.interface, prn=self.process_packet, stop_filter=lambda p: not self.running)

    def stop_capture(self):
        self.running = False

# Display dashboard
class PacketDashboard(tk.Tk):
    def __init__(self, packet_capture):
        super().__init__()
        self.packet_capture = packet_capture
        self.title('Packet Capture Dashboard')
        self.geometry('800x400')

        self.tree = ttk.Treeview(self, columns=('src_ip', 'dst_ip', 'protocol', 'length', 'anomaly', 'description'), show='headings')
        self.tree.heading('src_ip', text='Source IP')
        self.tree.heading('dst_ip', text='Destination IP')
        self.tree.heading('protocol', text='Protocol')
        self.tree.heading('length', text='Length')
        self.tree.heading('anomaly', text='Anomaly')
        self.tree.heading('description', text='Description')
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.refresh_button = tk.Button(self, text="Refresh", command=self.refresh_data)
        self.refresh_button.pack(pady=10)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.refresh_data()

    def refresh_data(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.packet_capture.cursor.execute('SELECT src_ip, dst_ip, protocol, length, anomaly, description FROM packets ORDER BY id DESC')
        rows = self.packet_capture.cursor.fetchall()
        for row in rows:
            self.tree.insert("", tk.END, values=row)
        self.after(5000, self.refresh_data)

    def on_closing(self):
        self.packet_capture.stop_capture()
        self.destroy()

# Main function
def main():
    display_logo()
    packet_capture = PacketCapture()
    
    capture_thread = threading.Thread(target=packet_capture.capture_packets)
    capture_thread.start()
    
    dashboard = PacketDashboard(packet_capture)
    dashboard.mainloop()
    
    packet_capture.stop_capture()
    capture_thread.join()

if __name__ == "__main__":
    main()

