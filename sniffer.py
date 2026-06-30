from scapy.sendrecv import sniff #for sniffing all packets
from scapy.layers.inet import TCP, IP, UDP #for accessing layers (TCP, IP, UDP)
from scapy.layers.inet6 import IPv6 #for accessing IPv6 layer
from scapy.layers.dns import DNS, DNSRR #for accessing DNS queries
from scapy.layers.l2 import ARP #for accessing ARP layer
from scapy.packet import Raw #for HTTP analysis
from datetime import datetime #for timestamps

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
arp_table = {} #stores IP-MAC ARP mappings
dns_table ={} #stores DNS responses (domain-address mappings)
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

def print_banner() :
    print(f"""{CYAN}
==========================================
             Packet Sniffer
==========================================
{RESET}""")


def handle_http(packet) :
    payload = packet[Raw].load.decode(errors="ignore")
    lines = payload.split("\r\n")
    if payload.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")) :
        print(f"\n{MAGENTA}===================={RESET}")
        print(f"{MAGENTA}    HTTP REQUEST{RESET}")
        print(f"{MAGENTA}===================={RESET}")

        print("Request : ", lines[0])
        for line in lines : 
            if line.startswith("Host:"):
                print(line)
            elif line.startswith("User-Agent:"):
                print(line)
            elif line.startswith("Accept:"):
                print(line)
    
    elif payload.startswith("HTTP/") :
        print(f"\n{MAGENTA}===================={RESET}")
        print(f"{MAGENTA}   HTTP RESPONSE{RESET}")
        print(f"{MAGENTA}===================={RESET}")

        print("Status : ", lines[0])
        for line in lines :
            if line.startswith("Server:"):
                print(line)
            if line.startswith("Content-Type:"):
                print(line)
            if line.startswith("Content-Length:"):
                print(line)



#UDP Block
def handle_udp(packet) :
    global packet_no
    print(f"\n{YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{RESET}")
    print(f"\nPacket No. : {packet_no}")
    packet_no += 1

    print(f"\n{GREEN}===================={RESET}")
    print(f"     {GREEN}UDP Packet{RESET}")
    print(f"{GREEN}===================={RESET}")

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


def get_dns_record_type(record_type) :
    types = {
        1:"A",
        28:"AAAA",
        5:"CNAME"

    }
    return types.get(record_type, str(record_type))

#DNS Block
def handle_dns(packet) :
    global packet_no
    print(f"\n{YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{RESET}")
    print(f"\nPacket No. : {packet_no}")
    packet_no += 1

    print(f"\n{BLUE}===================={RESET}")
    if packet[DNS].qr == 0 : #query
        print(f"{BLUE}     DNS QUERY{RESET}")
    if packet[DNS].qr == 1 : #response
        print(f"{BLUE}     DNS RESPONSE{RESET}")
    print(f"{BLUE}===================={RESET}")

    if packet[DNS].qr ==1 :
        if packet.haslayer(DNSRR) :
            record_type = get_dns_record_type(packet[DNSRR].type)
            domain = packet[DNSRR].rrname.decode()
            ip = str(packet[DNSRR].rdata)
            key = (domain, record_type)

            if key not in dns_table :
                dns_table[key] = ip
                print(f"\n{GREEN}[DNS] Added Domain{RESET}")
                print(f"Domain      : {domain}")
                print(f"Record Type : {record_type}")
                print(f"IP Address  : {ip}")
            
            else :
                if dns_table[key] == ip :
                    print(f"\n{GREEN}[DNS] Domain Verified{RESET}")
                    print(f"Domain      : {domain}")
                    print(f"Record Type : {record_type}")
                    print(f"IP Address  : {ip}")
                else : 
                    print(f"\n{YELLOW}[DNS] Possible DNS Poisoning Detected{RESET}")
                    print(f"Domain : {key}")
                    print(f"Original IP : {dns_table[key]}")
                    print(f"New IP : {ip}")


    

#ARP Block
def handle_arp(packet) :
    global packet_no
    print(f"\n{YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{RESET}")
    print(f"\nPacket No. : {packet_no}")
    packet_no += 1

    if packet[ARP].op == 2 : #Only looks at ARP replys
        print(f"\n{CYAN}===================={RESET}")
        print(f"{CYAN}     ARP Reply{RESET}")
        print(f"{CYAN}===================={RESET}")

        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc
        print("IP Address : ", ip)
        print("MAC Address : ", mac)

        if ip not in arp_table : #first time seeing IP
            arp_table[ip] = mac
            print(f"{GREEN}[ARP]{RESET} New Device Learned")
            print(f"{ip} --> {mac}")
            print(f"Known Devices : {len(arp_table)}")

        else : #IP already present
            if arp_table[ip] != mac : #different MAC add.
                print(f"\n{RED}[ALERT] POSSIBLE ARP SPOOFING{RESET}")
                print("IP Address : ", ip)
                print("Original MAC : ", arp_table[ip])
                print("New MAC : ", mac)
            else : #same MAC add.
                print(f"{GREEN}[ARP]{RESET} Verified")
                print(f"IP Address  : {ip}")
                print(f"MAC Address : {mac}")

#TCP Block
def handle_tcp(packet) :
    global packet_no
    print(f"\n{YELLOW}[{datetime.now().strftime('%H:%M:%S')}]{RESET}")
    print(f"\nPacket No. : {packet_no}")
    packet_no += 1

    print(f"\n{MAGENTA}===================={RESET}")
    print(f"{MAGENTA}     TCP Packet{RESET}")
    print(f"{MAGENTA}===================={RESET}")

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

        if (len(scan_tracker[src_ip]) >= 5 #threshold for PORT SCAN
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

    if packet.haslayer(Raw) :
        handle_http(packet)



def packet_callback(packet): #reads packets
    global packet_no

    if packet.haslayer(DNS): #DNS packets
        handle_dns(packet)

    elif packet.haslayer(ARP): #ARP packets
        handle_arp(packet)

    elif packet.haslayer(TCP): #TCP packets
        handle_tcp(packet)

    elif packet.haslayer(UDP): #UDP packets
        handle_udp(packet)

print_banner()
sniff(prn=packet_callback, store=False) #starts sniffing packets until terminated