from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS

BOLD = "\033[1m"
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

handshakes = {}
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

    if packet.haslayer(DNS):
        print(f"\nPacket No. : {packet_no}")
        packet_no += 1

        print("\n====================")
        if packet[DNS].qr == 0 :
            print(f"{BOLD}DNS QUERY{RESET}")
        if packet[DNS].qr == 1 :
            print(f"{BOLD}DNS RESPONSE{RESET}")
        print("====================")


    if packet.haslayer(TCP):
        print(f"\nPacket No. : {packet_no}")
        packet_no += 1

        print("\n====================")
        print(f"     {BOLD}TCP Packet{RESET}")
        print("====================")

        if packet.haslayer(IP):

            print("IP Version      : IPv4")
            print("Source IP       :", packet[IP].src)
            print("Destination IP  :", packet[IP].dst)

            src_ip = packet[IP].src
            dest_ip = packet[IP].dst

        elif packet.haslayer(IPv6):

            print("IP Version      : IPv6")
            print("Source IP       :", packet[IPv6].src)
            print("Destination IP  :", packet[IPv6].dst)

            src_ip = packet[IPv6].src
            dest_ip = packet[IPv6].dst

        print("Source Port     :", packet[TCP].sport,
              f"({get_service(packet[TCP].sport)})")
        print("Destination Port:", packet[TCP].dport,
              f"({get_service(packet[TCP].dport)})")
        print("Packet Length   :", len(packet), "bytes")


        flags = packet[TCP].flags
        connection = (src_ip, dest_ip, packet[TCP].dport)
        if flags == 'S' :
            handshakes[connection] = "SYN"
            print("[HANDSHAKE] SYN STORED")
        elif flags == "SA" :
            reverse_connection = (dest_ip, src_ip, packet[TCP].sport)
            if reverse_connection in handshakes :
                handshakes[reverse_connection] = "SYN ACK"
                print("[HANDSHAKE] SYN ACK STORED")
        elif flags == "A" :
            if connection in handshakes : 
                if handshakes[connection] == "SYN ACK" :
                    print(f"\n{GREEN}[HANDSHAKE] COMPLETE{RESET}")
                    print("Client : ",src_ip)
                    print("Server : ",dest_ip)
                    del handshakes[connection]



    elif packet.haslayer(UDP):
        print(f"\nPacket No. : {packet_no}")
        packet_no += 1

        print("\n====================")
        print(f"     {BOLD}UDP Packet{RESET}")
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



sniff(prn=packet_callback, store=False)