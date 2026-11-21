"""
Unit Tests for Packet Parsing and Analysis Engine
Tests parsing of synthetic Scapy packets without requiring live network access.
"""

import os
import unittest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

from analyzer import (
    PacketStatistics,
    parse_scapy_packet,
    _parse_tcp_flags,
    _extract_http_summary,
)
from utils import format_hex_ascii_dump, format_mac_address, safe_decode_string


class TestPacketAnalyzer(unittest.TestCase):

    def test_tcp_syn_packet_parsing(self):
        # Build synthetic TCP SYN packet
        pkt = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=54321, dport=80, flags="S", seq=1000)
        parsed = parse_scapy_packet(pkt)

        self.assertEqual(parsed.protocol, "TCP")
        self.assertEqual(parsed.src_ip, "192.168.1.50")
        self.assertEqual(parsed.dst_ip, "93.184.216.34")
        self.assertEqual(parsed.src_port, 54321)
        self.assertEqual(parsed.dst_port, 80)
        self.assertIn("SYN", parsed.tcp_flags)
        self.assertEqual(parsed.src_endpoint, "192.168.1.50:54321")
        self.assertEqual(parsed.dst_endpoint, "93.184.216.34:80")

    def test_tcp_syn_ack_packet(self):
        pkt = IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=54321, flags="SA", seq=5000, ack=1001)
        parsed = parse_scapy_packet(pkt)

        self.assertEqual(parsed.protocol, "TCP")
        self.assertIn("SYN", parsed.tcp_flags)
        self.assertIn("ACK", parsed.tcp_flags)

    def test_icmp_echo_request_parsing(self):
        pkt = IP(src="192.168.1.50", dst="8.8.8.8") / ICMP(type=8, code=0)
        parsed = parse_scapy_packet(pkt)

        self.assertEqual(parsed.protocol, "ICMP")
        self.assertEqual(parsed.src_ip, "192.168.1.50")
        self.assertEqual(parsed.dst_ip, "8.8.8.8")
        self.assertIn("Echo Request", parsed.summary)

    def test_icmp_echo_reply_parsing(self):
        pkt = IP(src="8.8.8.8", dst="192.168.1.50") / ICMP(type=0, code=0)
        parsed = parse_scapy_packet(pkt)

        self.assertEqual(parsed.protocol, "ICMP")
        self.assertIn("Echo Reply", parsed.summary)

    def test_arp_request_parsing(self):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="192.168.1.100", pdst="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:ff")
        parsed = parse_scapy_packet(pkt)

        self.assertEqual(parsed.protocol, "ARP")
        self.assertEqual(parsed.src_ip, "192.168.1.100")
        self.assertEqual(parsed.dst_ip, "192.168.1.1")
        self.assertIn("Who has 192.168.1.1?", parsed.summary)

    def test_dns_query_parsing(self):
        pkt = IP(src="192.168.1.50", dst="1.1.1.1") / UDP(sport=61234, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.com"))
        parsed = parse_scapy_packet(pkt)

        self.assertEqual(parsed.protocol, "DNS")
        self.assertIn("example.com", parsed.summary)
        self.assertEqual(parsed.dst_port, 53)

    def test_http_plaintext_request_parsing(self):
        http_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\n\r\n"
        pkt = IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="PA") / Raw(load=http_data)
        parsed = parse_scapy_packet(pkt)

        self.assertEqual(parsed.protocol, "HTTP")
        self.assertIn("GET /index.html HTTP/1.1", parsed.summary)
        self.assertIn("Host: example.com", parsed.summary)

    def test_packet_statistics_and_csv_export(self):
        stats = PacketStatistics()
        
        pkt1 = IP(src="192.168.1.10", dst="8.8.8.8") / ICMP(type=8)
        pkt2 = IP(src="192.168.1.10", dst="1.1.1.1") / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname="test.org"))
        
        stats.record_packet(parse_scapy_packet(pkt1))
        stats.record_packet(parse_scapy_packet(pkt2))

        self.assertEqual(stats.total_packets, 2)
        self.assertEqual(stats.protocol_counts["ICMP"], 1)
        self.assertEqual(stats.protocol_counts["DNS"], 1)
        self.assertEqual(stats.talker_counts["192.168.1.10"], 2)

        # CSV Export test
        tmp_csv = "temp_test_output.csv"
        try:
            stats.export_to_csv(tmp_csv)
            self.assertTrue(os.path.exists(tmp_csv))
            with open(tmp_csv, "r", encoding="utf-8") as f:
                content = f.read()
                self.assertIn("Timestamp,Protocol", content)
                self.assertIn("ICMP", content)
                self.assertIn("DNS", content)
        finally:
            if os.path.exists(tmp_csv):
                os.remove(tmp_csv)

    def test_utils_formatting(self):
        data = b"Hello, Network Sniffer World! \x00\x01\x02\x03"
        dump = format_hex_ascii_dump(data, max_bytes=64)
        self.assertIn("0000", dump)
        self.assertIn("Hello, Network", dump)

        mac = format_mac_address(b"\x00\x11\x22\x33\x44\x55")
        self.assertEqual(mac, "00:11:22:33:44:55")

        decoded = safe_decode_string(b"Test \xff\xfe")
        self.assertTrue(len(decoded) > 0)


if __name__ == "__main__":
    unittest.main()
