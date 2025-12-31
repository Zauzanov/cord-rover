from scapy.all import sniff, TCP, IP                                                # sniff interacts with the NIC to capture raw data.

def packet_callback(packet):                                                        # This func is executed every time a packet passes the filter.  
    if packet.haslayer(TCP) and packet.haslayer(IP):                                # Ensures the script doesn't crash: if a packet is an ARP or ICMP packet, it will not have a TCP layer.  
        raw_payload = packet[TCP].payload                                           # Extractes the data, digging into the 'data' portin of the TCP segment.
        payload_str = bytes(raw_payload).decode('utf-8', 
                                                errors='ignore').lower()            # Converts bytes into strings safely. Also I use `errors="ignore"` to prevent crashes on non-text data.
        

        # DEBUG mode prints every packet's first few chars 
        # to prove we are hearing the traffic
        if len(payload_str) > 0:                                                    # Filters zero data packets(ACK or SYN handshakes), ignoring those empty management packets to save processing time. 
             print(f"[DEBUG] Received data: {payload_str.strip()}")

        # Signagute-based detection
        if 'user' in payload_str or 'pass' in payload_str:                          # It looks for the specific patterns used by SMPT, POP3 and IMAP whe a user tries to auth. 
            print(f"\n[!] ALERT: Credentials found!")
            print(f"[*] Destination: {packet[IP].dst}")                             # Extracts the metadata, pulling the dest IP-address from the L3(IP) header, telling us which server the user is sending creds to.
            print(f"[*] Payload: {payload_str.strip()}")

def main(): 
    print("[*] Starting sniffer on email ports...")
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143', 
          prn=packet_callback, store=0)                                             # Looks for SMPT/POP3/IMAP ports only; 
                                                                                    # Using prn, I link the sniffer to my func;  
                                                                                    # store=0 ensures we don't run out of RAM during long captures, bc by default Scapy keeps every packet in RAM. 

if __name__ == '__main__':
    main()
