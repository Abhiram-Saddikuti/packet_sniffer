from scapy.sendrecv import sniff
from scapy.layers.inet import TCP, IP, UDP, ICMP
from scapy.layers.inet6 import IPv6

def packet_callback(packet):

    if packet.haslayer(TCP):
        print("[TCP]", packet.summary())

    elif packet.haslayer(UDP):
        print("[UDP]", packet.summary())

    elif packet.haslayer(ICMP):
        print("[ICMP]", packet.summary())

sniff(prn=packet_callback, store=False)