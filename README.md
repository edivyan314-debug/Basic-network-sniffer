# Basic Network Sniffer & Packet Analyzer (PyNetSniffer)

An educational network analysis tool built with Python 3.10+ and Scapy. Designed for students, security learners, and systems programmers to inspect packet encapsulation, examine protocol headers, and visualize real-time network traffic.

---

## ⚠️ Legal, Ethical & Safety Notice

> **Important:** This tool is strictly intended for **educational research**, **lab training**, and **authorized local diagnostics**.
> 
> Intercepting or capturing communications on networks without prior written consent from the network owner violates national and international laws, including the Computer Fraud and Abuse Act (CFAA), the Electronic Communications Privacy Act (ECPA), and the European GDPR.
> 
> **Always adhere to these rules:**
> 1. Run packet captures **only** on your own personal machine (loopback `127.0.0.1`), your own isolated lab routers, or networks where you have explicit permission.
> 2. Do not attempt to harvest, store, or inspect credentials or private user data.
> 3. An ethical warning banner is shown every time this tool starts up to remind users of these principles.

---

## Key Features

- **Multi-Protocol Dissection:**
  - **Layer 2 (Data Link):** Ethernet II frame headers, hardware MAC addresses, ARP requests/replies.
  - **Layer 3 (Network):** IPv4 & IPv6 headers, TTL / Hop Limits, IP Identification.
  - **Layer 4 (Transport):**
    - **TCP:** Full flag tracking (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`), sequence and acknowledgment numbers, window sizing.
    - **UDP:** Port multiplexing, datagram length.
    - **ICMP:** Type and code inspection (e.g. Echo Request `8`, Echo Reply `0`, Destination Unreachable `3`).
  - **Layer 7 (Application):**
    - **DNS:** Live domain query inspection (`A`, `AAAA`, `CNAME`, `MX`, etc.) and answer counters.
    - **HTTP:** Request line (`GET /path HTTP/1.1`), `Host:` headers, and response status codes for unencrypted traffic.
- **Dual Capture Engines:**
  - **Scapy Engine (`sniffer.py`):** High-level capture, BPF filters, PCAP / CSV export, and rich terminal output.
  - **Raw Socket Engine (`sniffer_socket.py`):** Low-level demonstration using Python's built-in `socket` and `struct` modules to illustrate manual binary header unpacking without external dependencies.
- **Hex & Printable ASCII Payload Preview:** Displays raw packet bytes side-by-side with sanitized ASCII text (first 64 bytes by default, or full payload in verbose mode).
- **Session Analytics Dashboard:** Summarizes total packets, throughput rate, protocol breakdown percentage, top host talkers (IPs), and top active transport ports.
- **Color-Coded Output:** Rich-powered terminal formatting with distinct color schemes per protocol.
- **Flexible Export:** Save captured packets directly to `.pcap` (viewable in Wireshark) or `.csv` spreadsheets.

---

## How Data Flows Through Network Layers

When data travels across a computer network, it passes through layers of the TCP/IP stack. Each layer prepends its own addressing and control metadata—a process called **encapsulation**:

```
+-------------------------------------------------------------+
| Layer 7: Application (e.g. HTTP GET / DNS Query)            |
+-------------------------------------------------------------+
                              ↓
+-------------------------------------------------------------+
| Layer 4: Transport Header [TCP / UDP] + Application Data    |
| (Source Port, Destination Port, Flags, Seq/Ack)             |
+-------------------------------------------------------------+
                              ↓
+-------------------------------------------------------------+
| Layer 3: Network Header [IPv4 / IPv6] + Transport Segment   |
| (Source IP, Destination IP, TTL, Protocol ID)               |
+-------------------------------------------------------------+
                              ↓
+-------------------------------------------------------------+
| Layer 2: Frame Header [Ethernet II] + IP Packet + CRC       |
| (Source MAC, Destination MAC, EtherType: 0x0800 / 0x0806)   |
+-------------------------------------------------------------+
```

When our sniffer captures a packet from the network card, it reverses this chain (**decapsulation**), peeling back the Ethernet frame, reading the IP packet, extracting the TCP segment or UDP datagram, and previewing the payload.

For complete field diagrams and byte-level layouts, refer to [docs/protocols.md](docs/protocols.md).

---

## Installation & Prerequisites

### 1. Python Environment
Ensure Python 3.10 or higher is installed:
```bash
python --version
```

### 2. Driver & Permission Setup

#### Windows
- Scapy requires **Npcap** to access raw network interfaces on Windows.
- Download and install Npcap from: [https://npcap.com/#download](https://npcap.com/#download)
- During the installation wizard, ensure you check:
  - **"Install Npcap in WinPcap API-compatible Mode"**
- Launch your terminal (PowerShell or CMD) using **"Run as Administrator"**.

#### Linux
- Install development packet headers and run with `sudo`:
```bash
sudo apt-get update
sudo apt-get install -y libpcap-dev
```

#### macOS
- Standard BSD packet filter drivers are built-in. Run with elevated privileges:
```bash
sudo python sniffer.py
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

## Command-Line Usage

### Main Scapy Sniffer (`sniffer.py`)

```bash
# Capture 10 packets continuously on default interface
python sniffer.py -c 10

# Capture only HTTP traffic and show verbose layer details
python sniffer.py -f "tcp port 80" -v

# Capture DNS requests and save session records to CSV
python sniffer.py -p dns -o dns_session.csv

# Capture all traffic and save to a Wireshark-compatible PCAP file
python sniffer.py -c 50 -o capture.pcap

# Filter by high-level protocol (tcp, udp, icmp, arp, dns, http)
python sniffer.py -p icmp

# View all detectable network interfaces
python sniffer.py --list-interfaces
```

#### Available CLI Options:
| Argument | Flag | Description |
|---|---|---|
| `--interface` | `-i` | Specific network adapter identifier or name |
| `--count` | `-c` | Maximum number of packets to capture (`0` = run indefinitely) |
| `--filter` | `-f` | Berkeley Packet Filter (BPF) expression (e.g., `'tcp port 443'`) |
| `--protocol` | `-p` | Filter by protocol name: `tcp`, `udp`, `icmp`, `arp`, `dns`, `http` |
| `--output` | `-o` | Export path ending in `.pcap` (Wireshark) or `.csv` |
| `--verbose` | `-v` | Display expanded layer headers and complete payload hex dump |
| `--list-interfaces` | `-l` | Display all available network interfaces and exit |

---

### Low-Level Raw Socket Sniffer (`sniffer_socket.py`)

To study how packets are parsed using binary unpacking (`struct.unpack`) without third-party packet capture libraries:

```bash
# Continuous capture using raw sockets (requires Administrator / root)
python sniffer_socket.py

# Capture 20 packets and bind to a specific local IP (Windows)
python sniffer_socket.py --ip 192.168.1.100 -c 20
```

---

## Hands-On Test Scenarios

Try these three scenarios to see different protocols in action. Run the sniffer in one terminal, then trigger the command in a second terminal:

1. **ICMP (Ping):**
   - Sniffer: `python sniffer.py -f "icmp" -v`
   - Trigger: `ping 8.8.8.8` (or `ping -n 2 8.8.8.8` on Windows)
   - Observation: Notice Echo Request (type 8) and Echo Reply (type 0) without any transport port numbers.

2. **DNS Query:**
   - Sniffer: `python sniffer.py -p dns`
   - Trigger: `nslookup example.com` (or `Resolve-DnsName example.com`)
   - Observation: Watch UDP datagrams targeting port 53 decode the requested hostname `example.com`.

3. **Plaintext HTTP Traffic:**
   - Sniffer: `python sniffer.py -f "tcp port 80" -v`
   - Trigger: `curl -i http://neverssl.com/`
   - Observation: Witness the initial 3-way TCP handshake (`SYN` -> `SYN-ACK` -> `ACK`), followed by the plaintext HTTP `GET` request line and `Host:` header.

Detailed traces and observations are documented in [samples/test_scenarios.md](samples/test_scenarios.md) and [samples/sample_output.txt](samples/sample_output.txt).

---

## Automated Unit Testing

A comprehensive offline test suite validates packet decoding, flag extraction, HTTP/DNS parsing, and statistics calculation using synthetic packets:

```bash
python -m unittest tests/test_analyzer.py
```

---

## Project Structure

```
basic-network-sniffer/
├── sniffer.py            # Primary Scapy-based CLI packet sniffer
├── sniffer_socket.py     # Low-level raw socket demo (socket + struct)
├── analyzer.py           # Protocol parser, packet dataclass, and statistics engine
├── utils.py              # Hex/ASCII dumping, warning banner, privilege checks
├── requirements.txt      # Python dependencies (scapy, rich, colorama)
├── README.md             # Project documentation and user guide
├── .gitignore            # Git exclusion rules
├── LICENSE               # Educational open-source license
├── docs/
│   └── protocols.md      # Detailed header diagrams and OSI/TCP-IP reference
├── samples/
│   ├── sample_output.txt # Terminal capture and statistical dashboard output
│   └── test_scenarios.md # Step-by-step educational testing guide
└── tests/
    └── test_analyzer.py  # Unit test suite for offline validation
```

---

## Future Enhancements

- [ ] **Graphical User Interface (GUI):** A desktop GUI built with PyQt or a web interface via Streamlit.
- [ ] **GeoIP Location Mapping:** Look up geographic origins and autonomous system numbers (ASN) for public remote IP addresses.
- [ ] **Heuristic Anomaly Alerts:** Detection triggers for rapid port scans (SYN floods, NULL scans, or XMAS scans).
- [ ] **TLS SNI Extraction:** Parse Server Name Indication (SNI) records from TLS Client Hello handshakes to identify domains accessed over HTTPS.
