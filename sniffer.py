from scapy.sendrecv import sniff #for sniffing all packets
from scapy.layers.inet import TCP, IP, UDP #for accessing layers (TCP, IP, UDP)
from scapy.layers.inet6 import IPv6 #for accessing IPv6 layer
from scapy.layers.dns import DNS #for accessing DNS queries

BOLD = "\033[1m"  #changing output text colour
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"

alerted_ips = set() #threat IPs for port scanning
scan_tracker = {} #stores ports open for IPs
handshakes = {} #stores S,SA,A packets for HANDSHAKES
packet_no = 1 #packet counter

def get_service(port): #gets ports service name by number

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

def packet_callback(packet): #reads packets
    global packet_no

    if packet.haslayer(DNS): #DNS packets
        print(f"\nPacket No. : {packet_no}")
        packet_no += 1

        print("\n====================")
        if packet[DNS].qr == 0 : #query
            print(f"{BOLD}DNS QUERY{RESET}")
        if packet[DNS].qr == 1 : #response
            print(f"{BOLD}DNS RESPONSE{RESET}")
        print("====================")


    if packet.haslayer(TCP): #TCP packets
        print(f"\nPacket No. : {packet_no}")
        packet_no += 1

        print("\n====================")
        print(f"     {BOLD}TCP Packet{RESET}")
        print("====================")

        if packet.haslayer(IP): #IPv4 packets

            print("IP Version      : IPv4")
            print("Source IP       :", packet[IP].src)
            print("Destination IP  :", packet[IP].dst)

            src_ip = packet[IP].src #source IP as IPv4
            dest_ip = packet[IP].dst #dest IP as IPv4

        elif packet.haslayer(IPv6): #IPv6 packets

            print("IP Version      : IPv6")
            print("Source IP       :", packet[IPv6].src)
            print("Destination IP  :", packet[IPv6].dst)

            src_ip = packet[IPv6].src #source IP as IPv6
            dest_ip = packet[IPv6].dst #dest IP as IPv6

        print("Source Port     :", packet[TCP].sport, #port number
              f"({get_service(packet[TCP].sport)})") #port name
        print("Destination Port:", packet[TCP].dport,
              f"({get_service(packet[TCP].dport)})")
        print("Packet Length   :", len(packet), "bytes") #packet length


        flags = packet[TCP].flags #SYN, SYN ACK, ACK
        connection = (src_ip, dest_ip, packet[TCP].dport) #TCP connection stored as 'connection'
        if flags == 'S' : #SYN packets
            handshakes[connection] = "SYN"
            print("[HANDSHAKE] SYN STORED")

            if src_ip not in scan_tracker : #tracks ports searched in 'scan_tracker'
                scan_tracker[src_ip] = set()
            scan_tracker[src_ip].add(packet[TCP].dport)
            print(f"{YELLOW}[SCAN TRACKER]{RESET}", src_ip, "->", scan_tracker[src_ip])

            if (len(scan_tracker[src_ip]) >= 2 #threshold for PORT SCAN
                and src_ip not in alerted_ips
                ):
                print(f"{RED}[ALERT] POSSIBLE PORT SCAN DETECTED{RESET}")
                print("Source IP :",src_ip)
                print("Ports : ",sorted(scan_tracker[src_ip]))
                alerted_ips.add(src_ip)


        elif flags == "SA" : #SYN ACK packets
            reverse_connection = (dest_ip, src_ip, packet[TCP].sport) #logs reverse connection
            if reverse_connection in handshakes : #checks for SYN log (if yes, replaced)
                handshakes[reverse_connection] = "SYN ACK"
                print("[HANDSHAKE] SYN ACK STORED")


        elif flags == "A" : #ACK packets
            if connection in handshakes :  
                if handshakes[connection] == "SYN ACK" : #checks for SYN ACK log (if yes, HANDSHAKE complete)
                    print(f"\n{GREEN}[HANDSHAKE] COMPLETE{RESET}")
                    print("Client : ",src_ip)
                    print("Server : ",dest_ip)
                    del handshakes[connection] #deletes the current connection IPs


    elif packet.haslayer(UDP): #UDP packets
        print(f"\nPacket No. : {packet_no}")
        packet_no += 1

        print("\n====================")
        print(f"     {BOLD}UDP Packet{RESET}")
        print("====================")

        if packet.haslayer(IP): #IPv4 layer

            print("IP Version      : IPv4")
            print("Source IP       :", packet[IP].src)
            print("Destination IP  :", packet[IP].dst)

        elif packet.haslayer(IPv6): #IPv6 layer

            print("IP Version      : IPv6")
            print("Source IP       :", packet[IPv6].src)
            print("Destination IP  :", packet[IPv6].dst)

        print("Source Port     :", packet[UDP].sport, #port number
              f"({get_service(packet[UDP].sport)})") #port name
        print("Destination Port:", packet[UDP].dport,
              f"({get_service(packet[UDP].dport)})")
        print("Packet Length   :", len(packet), "bytes") #packet length


sniff(prn=packet_callback, store=False) #starts sniffing packets until terminated