from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.inet6 import IPv6


def packet_callback(packet):

    if packet.haslayer(TCP):

        print("\n====================")
        print("     TCP Packet")
        print("====================")

        if packet.haslayer(IP):

            print("IP Version      : IPv4")
            print("Source IP       :", packet[IP].src)
            print("Destination IP  :", packet[IP].dst)

        elif packet.haslayer(IPv6):

            print("IP Version      : IPv6")
            print("Source IP       :", packet[IPv6].src)
            print("Destination IP  :", packet[IPv6].dst)

        print("Source Port     :", packet[TCP].sport)
        print("Destination Port:", packet[TCP].dport)
        print("Packet Length   :", len(packet), "bytes")



    elif packet.haslayer(UDP):

        print("\n====================")
        print("     UDP Packet")
        print("====================")

        if packet.haslayer(IP):

            print("IP Version      : IPv4")
            print("Source IP       :", packet[IP].src)
            print("Destination IP  :", packet[IP].dst)

        elif packet.haslayer(IPv6):

            print("IP Version      : IPv6")
            print("Source IP       :", packet[IPv6].src)
            print("Destination IP  :", packet[IPv6].dst)

        print("Source Port     :", packet[UDP].sport)
        print("Destination Port:", packet[UDP].dport)
        print("Packet Length   :", len(packet), "bytes")



sniff(prn=packet_callback, store=False)