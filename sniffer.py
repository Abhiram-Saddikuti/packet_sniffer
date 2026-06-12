from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNSQR


packet_no = 1

def get_service(port):

    services = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS"
    }

    return services.get(port, "Unknown")

def packet_callback(packet):
    global packet_no

    if packet.haslayer(DNSQR):

        print("\n====================")
        print("      DNS QUERY")
        print("====================")

        print(
             "Domain:",
             packet[DNSQR].qname.decode()
        )

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

        print("Source Port     :", packet[TCP].sport,
              f"({get_service(packet[TCP].sport)})")
        print("Destination Port:", packet[TCP].dport,
              f"({get_service(packet[TCP].dport)})")
        print("Packet Length   :", len(packet), "bytes")
        print(f"Packet No. : {packet_no}")
        packet_no += 1



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

        print("Source Port     :", packet[UDP].sport,
              f"({get_service(packet[UDP].sport)})")
        print("Destination Port:", packet[UDP].dport,
              f"({get_service(packet[UDP].dport)})")
        print("Packet Length   :", len(packet), "bytes")
        print(f"Packet No. : {packet_no}")
        packet_no += 1



sniff(prn=packet_callback, store=False)