from unittest.mock import patch

import scapy.all as scapy

from network_sniffer import process_packet, sniff_packets


def test_process_tcp_packet(capsys):
    packet = scapy.IP(src="192.0.2.10", dst="198.51.100.20") / scapy.TCP(sport=1234, dport=443)

    process_packet(packet)

    output = capsys.readouterr().out
    assert "192.0.2.10 --> 198.51.100.20" in output
    assert "TCP packet" in output
    assert ":1234 -->" in output
    assert ":443" in output


def test_process_udp_packet(capsys):
    packet = scapy.IP(src="192.0.2.10", dst="198.51.100.20") / scapy.UDP(sport=5353, dport=53)

    process_packet(packet)

    output = capsys.readouterr().out
    assert "UDP packet" in output
    assert ":5353 -->" in output
    assert ":53" in output


def test_process_icmp_packet(capsys):
    packet = scapy.IP(src="192.0.2.10", dst="198.51.100.20") / scapy.ICMP(type=8, code=0)

    process_packet(packet)

    output = capsys.readouterr().out
    assert "ICMP packet" in output
    assert "Type: 8 Code: 0" in output


def test_process_non_ip_packet_is_ignored(capsys):
    process_packet(scapy.Ether() / scapy.ARP(pdst="192.0.2.1"))

    assert capsys.readouterr().out == ""


def test_sniff_packets_configures_scapy_sniff():
    with patch("network_sniffer.scapy.sniff") as sniff:
        sniff_packets("eth0")

    sniff.assert_called_once_with(iface="eth0", store=False, prn=process_packet)
