"""Small Scapy-based IPv4 packet inspection exercise."""

import argparse

import scapy.all as scapy


def process_packet(packet):
    """Print useful metadata for supported IPv4 packets."""
    if not packet.haslayer(scapy.IP):
        return

    ip = packet[scapy.IP]
    print(f"IP packet: {ip.src} --> {ip.dst} Protocol: {ip.proto}")

    if packet.haslayer(scapy.TCP):
        tcp = packet[scapy.TCP]
        print(f"TCP packet: {ip.src}:{tcp.sport} --> {ip.dst}:{tcp.dport}")
    elif packet.haslayer(scapy.UDP):
        udp = packet[scapy.UDP]
        print(f"UDP packet: {ip.src}:{udp.sport} --> {ip.dst}:{udp.dport}")
    elif packet.haslayer(scapy.ICMP):
        icmp = packet[scapy.ICMP]
        print(
            f"ICMP packet: {ip.src} --> {ip.dst} "
            f"Type: {icmp.type} Code: {icmp.code}"
        )


def sniff_packets(interface):
    """Capture packets on an authorized interface until interrupted."""
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("interface", help="network interface to capture on")
    args = parser.parse_args()
    sniff_packets(args.interface)


if __name__ == "__main__":
    main()
