import scapy.all as scapy


def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"IP packet: {src_ip} --> {dst_ip} Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            print(f"TCP Packet: {src_ip}:{src_port} --> {dst_ip}:{dst_port}")

        elif packet.haslayer(scapy.UDP):
            src_port = packet[scapy.UDP].sport
            dst_port = packet[scapy.UDP].dport
            print(f"UDP Packet:{src_ip}:{src_port} --> {dst_ip}:{dst_port}")

        elif packet.haslayer(scapy.ICMP):
            icmp_type = packet(scapy.ICMP).type
            icmp_code = packet[scapy.ICMP].code
            print(f"ICMP Packet: {src_ip} --> {dst_ip} Type: {icmp_type} Code: {icmp_code}")
