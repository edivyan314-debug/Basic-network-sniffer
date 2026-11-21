"""
Packet Parsing and Statistical Analysis Engine
Part of the Basic Network Sniffer educational toolkit.
"""

from __future__ import annotations

import csv
import datetime
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    HAS_SCAPY_DNS = True
except ImportError:
    HAS_SCAPY_DNS = False

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Mapping common port numbers to standard network service names
COMMON_SERVICES: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP-Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}

# TCP Flag bitmasks and names
TCP_FLAG_NAMES: Dict[str, str] = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

ICMP_TYPES: Dict[int, str] = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded",
    12: "Parameter Problem",
}


@dataclass
class ParsedPacket:
    """Structured representation of an analyzed network packet."""
    timestamp: float
    formatted_time: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    length: int = 0
    tcp_flags: List[str] = field(default_factory=list)
    summary: str = ""
    payload: bytes = b""
    layer_details: Dict[str, Any] = field(default_factory=dict)

    @property
    def src_endpoint(self) -> str:
        if self.src_port is not None:
            return f"{self.src_ip}:{self.src_port}"
        return self.src_ip

    @property
    def dst_endpoint(self) -> str:
        if self.dst_port is not None:
            return f"{self.dst_ip}:{self.dst_port}"
        return self.dst_ip


def _parse_tcp_flags(flags_val: Any) -> List[str]:
    """Extract human-readable flag abbreviations from Scapy TCP flags."""
    str_flags = str(flags_val).strip()
    active_flags: List[str] = []
    for code, name in TCP_FLAG_NAMES.items():
        if code in str_flags:
            active_flags.append(name)
    return active_flags


def _extract_http_summary(payload_bytes: bytes) -> Optional[str]:
    """Inspect payload to see if it represents a plaintext HTTP request or response."""
    if not payload_bytes:
        return None
    
    # Try decoding initial line
    try:
        sample = payload_bytes[:512].decode("latin-1")
    except Exception:
        return None

    first_line = sample.split("\r\n", 1)[0].strip()
    methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ")
    
    if any(first_line.startswith(m) for m in methods):
        # Locate Host header if available
        host = ""
        for line in sample.split("\r\n"):
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        if host:
            return f"HTTP Request: {first_line} [Host: {host}]"
        return f"HTTP Request: {first_line}"
    
    if first_line.startswith("HTTP/1."):
        return f"HTTP Response: {first_line}"
        
    return None


def parse_scapy_packet(pkt: Packet) -> ParsedPacket:
    """
    Deconstruct a Scapy packet into layer metadata and structured packet info.
    """
    packet_time = float(getattr(pkt, "time", time.time()))
    time_str = datetime.datetime.fromtimestamp(packet_time).strftime("%H:%M:%S.%f")[:-3]
    pkt_len = len(pkt)
    
    protocol = "OTHER"
    src_ip = "N/A"
    dst_ip = "N/A"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: List[str] = []
    summary_parts: List[str] = []
    layer_info: Dict[str, Any] = {}
    payload_data = b""

    # Layer 2: ARP check
    if pkt.haslayer(ARP):
        protocol = "ARP"
        arp_layer = pkt[ARP]
        op_code = arp_layer.op
        src_ip = arp_layer.psrc
        dst_ip = arp_layer.pdst
        layer_info["hwsrc"] = arp_layer.hwsrc
        layer_info["hwdst"] = arp_layer.hwdst
        if op_code == 1:
            summary_parts.append(f"Who has {dst_ip}? Tell {src_ip}")
        elif op_code == 2:
            summary_parts.append(f"{src_ip} is at {arp_layer.hwsrc}")
        else:
            summary_parts.append(f"ARP op={op_code}")

    # Layer 3: IPv4
    elif pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        layer_info["ttl"] = ip_layer.ttl
        layer_info["ip_id"] = ip_layer.id
        protocol = "IP"

    # Layer 3: IPv6
    elif pkt.haslayer(IPv6):
        ip6_layer = pkt[IPv6]
        src_ip = ip6_layer.src
        dst_ip = ip6_layer.dst
        layer_info["hlim"] = ip6_layer.hlim
        protocol = "IPv6"

    # Layer 4: ICMP
    if pkt.haslayer(ICMP):
        protocol = "ICMP"
        icmp_layer = pkt[ICMP]
        itype = icmp_layer.type
        icode = icmp_layer.code
        type_desc = ICMP_TYPES.get(itype, f"Type {itype}")
        summary_parts.append(f"{type_desc} (code={icode})")
        layer_info["icmp_type"] = itype
        layer_info["icmp_code"] = icode

    # Layer 4: TCP
    elif pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        protocol = "TCP"
        src_port = int(tcp_layer.sport)
        dst_port = int(tcp_layer.dport)
        tcp_flags = _parse_tcp_flags(tcp_layer.flags)
        layer_info["seq"] = tcp_layer.seq
        layer_info["ack"] = tcp_layer.ack
        layer_info["window"] = tcp_layer.window

    # Layer 4: UDP
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        protocol = "UDP"
        src_port = int(udp_layer.sport)
        dst_port = int(udp_layer.dport)
        layer_info["udp_len"] = udp_layer.len

    # Extract Raw payload if present
    if pkt.haslayer(Raw):
        payload_data = bytes(pkt[Raw].load)

    # Layer 7: DNS Inspection
    if HAS_SCAPY_DNS and pkt.haslayer(DNS):
        dns_layer = pkt[DNS]
        protocol = "DNS"
        qr = dns_layer.qr  # 0 for query, 1 for response
        if qr == 0 and dns_layer.qd:
            # Query
            try:
                qd_item = dns_layer.qd[0] if hasattr(dns_layer.qd, "__getitem__") else dns_layer.qd
                qname = qd_item.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype_id = qd_item.qtype
                qtype_name = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS"}.get(qtype_id, str(qtype_id))
                summary_parts.append(f"Query {qname} [{qtype_name}]")
            except Exception:
                summary_parts.append("DNS Query")
        elif qr == 1:
            # Response
            ancount = dns_layer.ancount
            summary_parts.append(f"Response (Answers: {ancount})")

    # Layer 7: Plaintext HTTP Inspection
    if protocol == "TCP" and payload_data:
        http_info = _extract_http_summary(payload_data)
        if http_info:
            protocol = "HTTP"
            summary_parts.append(http_info)

    # Fallback summary if empty
    final_summary = " | ".join(summary_parts) if summary_parts else f"Length: {pkt_len} bytes"

    return ParsedPacket(
        timestamp=packet_time,
        formatted_time=time_str,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=pkt_len,
        tcp_flags=tcp_flags,
        summary=final_summary,
        payload=payload_data,
        layer_details=layer_info,
    )


class PacketStatistics:
    """Accumulates packet counts and computes session metrics."""

    def __init__(self) -> None:
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.start_time: float = time.time()
        self.end_time: float = self.start_time
        self.protocol_counts: Counter[str] = Counter()
        self.talker_counts: Counter[str] = Counter()
        self.port_counts: Counter[int] = Counter()
        self.records: List[ParsedPacket] = []

    def record_packet(self, pkt: ParsedPacket, store_record: bool = True) -> None:
        """Add an analyzed packet to cumulative statistics."""
        self.total_packets += 1
        self.total_bytes += pkt.length
        self.end_time = pkt.timestamp
        self.protocol_counts[pkt.protocol] += 1

        if pkt.src_ip and pkt.src_ip != "N/A":
            self.talker_counts[pkt.src_ip] += 1
        if pkt.dst_ip and pkt.dst_ip != "N/A":
            self.talker_counts[pkt.dst_ip] += 1

        if pkt.src_port:
            self.port_counts[pkt.src_port] += 1
        if pkt.dst_port:
            self.port_counts[pkt.dst_port] += 1

        if store_record:
            self.records.append(pkt)

    @property
    def duration_seconds(self) -> float:
        return max(0.001, self.end_time - self.start_time)

    def export_to_csv(self, file_path: str) -> None:
        """Save captured records as a CSV spreadsheet."""
        with open(file_path, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp",
                "Protocol",
                "Source_Endpoint",
                "Destination_Endpoint",
                "Length_Bytes",
                "TCP_Flags",
                "Summary"
            ])
            for r in self.records:
                writer.writerow([
                    r.formatted_time,
                    r.protocol,
                    r.src_endpoint,
                    r.dst_endpoint,
                    r.length,
                    " ".join(r.tcp_flags) if r.tcp_flags else "-",
                    r.summary,
                ])

    def display_rich_summary(self, rich_console: Optional[Console] = None) -> None:
        """Render a clean statistical dashboard to the terminal."""
        out = rich_console or Console()

        duration = self.duration_seconds
        pps = self.total_packets / duration
        kb_sec = (self.total_bytes / 1024.0) / duration

        # 1. Overview Table
        overview_table = Table(title="Session Overview", show_header=True, header_style="bold cyan")
        overview_table.add_column("Metric", style="white")
        overview_table.add_column("Value", style="bold green", justify="right")
        overview_table.add_row("Total Packets", f"{self.total_packets:,}")
        overview_table.add_row("Total Data Captured", f"{self.total_bytes / 1024.0:.2f} KB ({self.total_bytes:,} bytes)")
        overview_table.add_row("Capture Duration", f"{duration:.2f} seconds")
        overview_table.add_row("Average Throughput", f"{pps:.1f} packets/sec ({kb_sec:.2f} KB/s)")

        # 2. Protocol Distribution Table
        proto_table = Table(title="Protocol Breakdown", show_header=True, header_style="bold magenta")
        proto_table.add_column("Protocol", style="cyan")
        proto_table.add_column("Packets", style="green", justify="right")
        proto_table.add_column("Percentage", style="yellow", justify="right")

        for proto, count in self.protocol_counts.most_common():
            pct = (count / self.total_packets * 100) if self.total_packets > 0 else 0
            proto_table.add_row(proto, f"{count:,}", f"{pct:.1f}%")

        # 3. Top Talkers (IPs)
        talker_table = Table(title="Top 5 Host Talkers (IP Addresses)", show_header=True, header_style="bold blue")
        talker_table.add_column("IP Address", style="cyan")
        talker_table.add_column("Packets Observed", style="green", justify="right")
        talker_table.add_column("Activity Share", style="yellow", justify="right")

        total_ip_hits = sum(self.talker_counts.values()) or 1
        for ip, count in self.talker_counts.most_common(5):
            pct = (count / total_ip_hits) * 100
            talker_table.add_row(ip, f"{count:,}", f"{pct:.1f}%")

        # 4. Top Ports Table
        port_table = Table(title="Top 5 Transport Ports", show_header=True, header_style="bold yellow")
        port_table.add_column("Port", style="cyan", justify="right")
        port_table.add_column("Service Name", style="magenta")
        port_table.add_column("Occurrences", style="green", justify="right")

        for port, count in self.port_counts.most_common(5):
            service = COMMON_SERVICES.get(port, "Unassigned / Custom")
            port_table.add_row(str(port), service, f"{count:,}")

        # Render all panels
        out.print("\n")
        out.print(overview_table)
        out.print(proto_table)
        out.print(talker_table)
        out.print(port_table)
        out.print("\n")
