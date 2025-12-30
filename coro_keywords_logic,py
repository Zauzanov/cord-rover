from scapy.all import sniff, TCP, IP

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):                                            # Ensures the packet has the layers we need.
        payload = str(packet[TCP].payload).lower()                                              # Extracts and decodes the payload safely.
        
        # List of interesting SMTP keywords
        keywords = ['user', 'pass', 'mail from', 'rcpt to']
        
        if any(key in payload for key in keywords):
            print(f"\n[!] SMTP Traffic Detected on {packet[IP].dst}")
            # Clean up the output to remove the b' ' bytes notation
            clean_payload = str(packet[TCP].payload).strip()
            print(f"[*] Data: {clean_payload}")

def main():
    print("[*] Starting sniffer on email ports...")
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', prn=packet_callback, store=0)   # store=0 ensures we don't run out of RAM during long captures.

if __name__ == '__main__':
    main()
