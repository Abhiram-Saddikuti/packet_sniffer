from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, IP
from scapy.layers.inet6 import IPv6

handshakes = {}

def packet_callback(packet):

    if packet.haslayer(TCP):

        if packet.haslayer(IP) :
            src = packet[IP].src
            dest = packet[IP].dst

        elif packet.haslayer(IPv6) :
            src = packet[IPv6].src
            dest = packet[IPv6].dst
        else :
            return

        connection = (src, dest, packet[TCP].dport)

        flags = packet[TCP].flags


        if flags == 'S' :
            print(src, "->", dest, "SYN")
            handshakes[connection] = "SYN"
            print("SYN STORED")


        elif flags == 'SA' :
            print(src, "->", dest, "SYN ACK")
            reverse_connection = (dest, src, packet[TCP].sport)
            if reverse_connection in handshakes :
                handshakes[reverse_connection] = "SYN ACK"
            print("SYN ACK STORED")


        elif flags == 'A' :
            print(src, "->", dest, "ACK")
            connection = (src, dest, packet[TCP].dport)
            if connection in handshakes : 
                if handshakes[connection] == "SYN ACK" :
                    print("\n====================")
                    print("TCP HANDSHAKE COMPLETE")
                    print("====================")

                    print("Client:", src)
                    print("Server:", dest)

                    del handshakes[connection]


        print(handshakes)
sniff(prn=packet_callback, store=False)