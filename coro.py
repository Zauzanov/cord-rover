from scapy.all import sniff                                     # Places the NIC into promiscuous mode, allowing it capture all traffic, not just intended for your machine. 


def packet_callback(packet):                                    # Firstly, we define a callback function, which is gonna accept every single intercepted packet.
    print(packet.show())                                        # Prints the entire packet structure.
'''
The packet variable is a Scapy object containing every layer of the captured data(L2-L4). 
'''

def main():
    sniff(prn=packet_callback, count=1)                         # Every time it sees a packet, it hands it over to packet_callback. 

if __name__ == '__main__':
    main()
