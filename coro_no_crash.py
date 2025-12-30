from scapy.all import sniff, TCP, IP

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):                                            # Ensures the packet has the layers we need.
        payload = str(packet[TCP].payload).lower()                                              # Extracts and decodes the payload safely.
        
        # check for keywords
        if 'user' in payload or 'pass' in payload:
            print(f"\n[!] Alert: Potential Credentials Detected!")
            print(f"[*] Source: {packet[IP].src} -> Destination: {packet[IP].dst}")
            print(f"[*] Raw Data: {payload}")

def main():
    print("[*] Starting sniffer on email ports...")
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', prn=packet_callback, store=0)   # store=0 ensures we don't run out of RAM during long captures.

if __name__ == '__main__':
    main()
