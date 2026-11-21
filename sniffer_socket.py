"""
Raw Socket Network Sniffer (Low-Level Demonstration)
Demonstrates manual packet header deconstruction using socket and struct.
Part of the Basic Network Sniffer educational toolkit.
"""

from __future__ import annotations

import argparse
import datetime
import os
import signal
import socket
import struct
import sys
import time
from typing import Dict, List, Optional, Tuple

from utils import (
    console,
    display_startup_banner,
    format_hex_ascii_dump,
    format_mac_address,
    verify_system_privileges,
)

# Protocol IDs in IP Header
IP_PROTOCOLS: Dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def parse_ethernet_header(raw_data: bytes) -> Tuple[str, str, int, bytes]:
    """
    Unpack 14-byte Ethernet II frame header.
    Format string: '!6s6sH' (Big-Endian: 6B dst, 6B src, 2B ethertype)
    """
    dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw_data[:14])
    return (
        format_mac_address(dst_mac),
        format_mac_address(src_mac),
        socket.ntohs(ethertype),
        raw_data[14:],
    )


def parse_ipv4_header(raw_data: bytes) -> Tuple[int, int, int, str, str, bytes]:
    """
    Unpack standard 20-byte IPv4 packet header.
    Format string: '!BBHHHBBH4s4s'
    """
    header_fields = struct.unpack("!BBHHHBBH4s4s", raw_data[:20])
    
    version_ihl = header_fields[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4  # Header length in bytes
    
    ttl = header_fields[5]
    protocol_num = header_fields[6]
    src_ip = socket.inet_ntoa(header_fields[8])
    dst_ip = socket.inet_ntoa(header_fields[9])
    
    # Payload starts after IHL bytes (accounting for optional IP options)
    payload = raw_data[ihl:]
    return version, ihl, protocol_num, src_ip, dst_ip, payload


def parse_tcp_segment(raw_data: bytes) -> Tuple[int, int, int, int, List[str], bytes]:
    """
    Unpack 20-byte TCP header and evaluate flag bitmasks.
    Format string: '!HHLLBBHHH'
    """
    fields = struct.unpack("!HHLLBBHHH", raw_data[:20])
    
    src_port = fields[0]
    dst_port = fields[1]
    seq_num = fields[2]
    ack_num = fields[3]
    offset_reserved = fields[4]
    data_offset = (offset_reserved >> 4) * 4
    flags_byte = fields[5]

    # Decode individual flag bits
    flags: List[str] = []
    if flags_byte & 0x01: flags.append("FIN")
    if flags_byte & 0x02: flags.append("SYN")
    if flags_byte & 0x04: flags.append("RST")
    if flags_byte & 0x08: flags.append("PSH")
    if flags_byte & 0x10: flags.append("ACK")
    if flags_byte & 0x20: flags.append("URG")

    payload = raw_data[data_offset:]
    return src_port, dst_port, seq_num, ack_num, flags, payload


def parse_udp_segment(raw_data: bytes) -> Tuple[int, int, int, bytes]:
    """
    Unpack 8-byte UDP header.
    Format string: '!HHHH'
    """
    src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw_data[:8])
    payload = raw_data[8:]
    return src_port, dst_port, length, payload


def parse_icmp_packet(raw_data: bytes) -> Tuple[int, int, int, bytes]:
    """
    Unpack 4-byte ICMP header.
    Format string: '!BBH'
    """
    icmp_type, code, checksum = struct.unpack("!BBH", raw_data[:4])
    payload = raw_data[4:]
    return icmp_type, code, checksum, payload


def get_default_local_ip() -> str:
    """Find the primary local IPv4 address of the active network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Does not send actual traffic, merely resolves routing table
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def run_raw_socket_sniffer(bind_ip: Optional[str] = None, max_packets: int = 0) -> None:
    """Run the raw-socket packet capture loop."""
    display_startup_banner()

    if not verify_system_privileges():
        if console:
            console.print(
                "[bold red][!] Error: Raw sockets strictly require elevated administrator / root permissions.[/bold red]\n"
                "    Please relaunch this script from an elevated command prompt.\n"
            )
        else:
            print("Error: Elevated administrator/root permissions required.")
        return

    is_windows = os.name == "nt"
    target_ip = bind_ip or get_default_local_ip()
    
    sock: Optional[socket.socket] = None

    try:
        if is_windows:
            # On Windows, raw sockets capture Layer 3 IP packets and require SIO_RCVALL
            if console:
                console.print(f"[bold cyan][*] Windows Mode:[/bold cyan] Binding raw IP socket to [green]{target_ip}[/green]")
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((target_ip, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Enable promiscuous mode
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        else:
            # On Linux / POSIX, AF_PACKET captures raw Layer 2 Ethernet frames
            if console:
                console.print("[bold cyan][*] Linux/POSIX Mode:[/bold cyan] Binding AF_PACKET raw socket (All protocols)")
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        if console:
            console.print("[*] Sniffer running. Press [bold red]Ctrl+C[/bold red] to stop.\n" + "-" * 75)

        captured_count = 0

        while True:
            raw_data, addr = sock.recvfrom(65535)
            timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
            captured_count += 1

            ip_payload: bytes
            src_ip: str
            dst_ip: str
            proto_num: int

            if not is_windows:
                # Dissect Ethernet Frame on Linux
                dst_mac, src_mac, eth_type, ip_bytes = parse_ethernet_header(raw_data)
                if eth_type != 0x0800:
                    # Non-IPv4 (e.g. ARP or IPv6)
                    continue
                version, ihl, proto_num, src_ip, dst_ip, ip_payload = parse_ipv4_header(ip_bytes)
            else:
                # Windows delivers IPv4 packet directly
                version, ihl, proto_num, src_ip, dst_ip, ip_payload = parse_ipv4_header(raw_data)

            proto_name = IP_PROTOCOLS.get(proto_num, f"Proto-{proto_num}")
            
            # Transport Layer dissection
            info_line = ""
            payload_data = b""

            if proto_num == 6:  # TCP
                src_port, dst_port, seq, ack, flags, payload_data = parse_tcp_segment(ip_payload)
                flags_str = f"[{' '.join(flags)}]" if flags else "[]"
                info_line = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  flags={flags_str}  seq={seq}"
            elif proto_num == 17:  # UDP
                src_port, dst_port, length, payload_data = parse_udp_segment(ip_payload)
                info_line = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  len={length}"
            elif proto_num == 1:  # ICMP
                itype, code, chk, payload_data = parse_icmp_packet(ip_payload)
                info_line = f"{src_ip} -> {dst_ip}  type={itype} code={code}"
            else:
                info_line = f"{src_ip} -> {dst_ip}"

            # Output packet to terminal
            if console:
                console.print(f"[dim]{timestamp}[/dim]  [bold yellow]{proto_name:<5}[/bold yellow]  {info_line}")
                if payload_data:
                    preview = format_hex_ascii_dump(payload_data, max_bytes=64)
                    for line in preview.splitlines():
                        console.print(f"       [dim]{line}[/dim]")
            else:
                print(f"{timestamp}  {proto_name:<5}  {info_line}")

            if max_packets > 0 and captured_count >= max_packets:
                break

    except KeyboardInterrupt:
        if console:
            console.print("\n[bold red][!] User initiated stop.[/bold red]")
    except PermissionError:
        if console:
            console.print("\n[bold red][X] Permission denied: Administrator/root privileges required![/bold red]")
        else:
            print("Permission denied: Run as Administrator / root.")
    except Exception as e:
        if console:
            console.print(f"\n[bold red][X] Socket error:[/bold red] {e}")
        else:
            print(f"Socket error: {e}")
    finally:
        if is_windows and sock:
            try:
                # Turn off promiscuous mode
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        if sock:
            sock.close()
        if console:
            console.print("[bold green][✓] Raw socket closed cleanly.[/bold green]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Low-Level Raw Socket Packet Sniffer (socket + struct demonstration)",
    )
    parser.add_argument("--ip", help="Local IPv4 address to bind (Windows mode; defaults to primary host IP)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Stop after N packets (0 = continuous)")
    args = parser.parse_args()

    run_raw_socket_sniffer(bind_ip=args.ip, max_packets=args.count)


if __name__ == "__main__":
    main()

