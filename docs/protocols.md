# Network Protocol Header Reference & Packet Flow Guide

This document provides a comprehensive educational reference for the network protocols inspected by the Basic Network Sniffer toolkit.

---

## 1. Network Encapsulation: How Packets Flow

When an application transmits data over a network, the operating system stacks protocols in layers—a process known as **encapsulation**. As data moves down the TCP/IP stack from application to physical wire, each layer attaches its own header:

```
[ Application Data (Payload, e.g., HTTP GET) ]
       ↓
[ Transport Header (TCP/UDP) ] + [ Application Data ]              --> Segment / Datagram
       ↓
[ Network Header (IPv4/IPv6) ] + [ Transport Header ] + [ Data ]    --> Packet
       ↓
[ Frame Header (Ethernet) ] + [ Network Header ] + [ Transport ] + [ Data ] + [ Frame Check ] --> Frame
```

When receiving data, the physical adapter reads the frame and each protocol driver strips its corresponding header (**decapsulation**) before handing the payload to the next layer up.

---

## 2. Ethernet II Frame (Layer 2: Data Link)

Ethernet operates at the local link layer. It addresses network cards on the same local broadcast domain using 48-bit (6-byte) MAC addresses.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Destination MAC Address (Bytes 0-3)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Dest MAC (Bytes 4-5)         |   Source MAC Address (0-1)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Source MAC Address (Bytes 2-5)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          EtherType            |   Payload (46 to 1500 bytes)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
```

- **Destination MAC (6 bytes):** Hardware address of the receiving network interface.
- **Source MAC (6 bytes):** Hardware address of the sending network interface.
- **EtherType (2 bytes):** Identifies the encapsulated Layer 3 protocol:
  - `0x0800`: IPv4 (Internet Protocol v4)
  - `0x0806`: ARP (Address Resolution Protocol)
  - `0x86DD`: IPv6 (Internet Protocol v6)

---

## 3. ARP (Address Resolution Protocol)

ARP resolves Layer 3 IP addresses to Layer 2 physical MAC addresses on local subnets.

- **Hardware Type (2 bytes):** Link layer type (usually `1` for Ethernet).
- **Protocol Type (2 bytes):** Protocol to resolve (usually `0x0800` for IPv4).
- **Hardware & Protocol Size (1 byte each):** MAC length (6) and IPv4 length (4).
- **Opcode (2 bytes):**
  - `1`: ARP Request ("Who has IP X.X.X.X? Tell Y.Y.Y.Y")
  - `2`: ARP Reply ("IP X.X.X.X is at MAC AA:BB:CC:DD:EE:FF")
- **Sender MAC / IP:** The identity of the querier or responder.
- **Target MAC / IP:** Target addresses.

---

## 4. IPv4 Header (Layer 3: Network)

IPv4 provides logical host addressing and route determination across distinct networks.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IP Address                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IP Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Version (4 bits):** Set to `4` for IPv4.
- **IHL (Internet Header Length, 4 bits):** Number of 32-bit words in the header. Minimum value is `5` (20 bytes).
- **Total Length (16 bits):** Complete size of packet (header + payload) in bytes.
- **Time to Live (TTL, 8 bits):** Hop counter decremented by each router to avoid infinite loops. When it hits 0, the packet is discarded and an ICMP Time Exceeded is returned.
- **Protocol (8 bits):** Identifies the transport protocol inside:
  - `1`: ICMP
  - `6`: TCP
  - `17`: UDP
- **Source / Destination IP (32 bits / 4 bytes each):** Logical addresses of sender and recipient.

---

## 5. TCP Header (Layer 4: Transport)

TCP provides reliable, ordered, error-checked delivery of byte streams between applications.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |        Urgent Pointer         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### The TCP Three-Way Handshake
1. **Client -> Server [SYN]:** Initiates connection with initial sequence number $x$.
2. **Server -> Client [SYN, ACK]:** Acknowledges receipt of $x$ (ack=$x+1$) and offers server initial sequence number $y$.
3. **Client -> Server [ACK]:** Acknowledges receipt of $y$ (ack=$y+1$). Connection is now `ESTABLISHED`.

### Important TCP Flags:
- **SYN (Synchronize):** Initializes a connection.
- **ACK (Acknowledgment):** Indicates acknowledgment field is valid.
- **FIN (Finish):** Sender has finished transmitting data; begins graceful teardown.
- **RST (Reset):** Abruptly aborts or refuses a connection.
- **PSH (Push):** Instructs receiver to push buffered data immediately to the application.
- **URG (Urgent):** Indicates urgent pointer field should be evaluated.

---

## 6. UDP Header (Layer 4: Transport)

UDP is a lightweight, connectionless datagram protocol that trades reliability for minimal overhead and low latency.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- Only 8 bytes total overhead.
- Commonly utilized by DNS (port 53), DHCP (ports 67/68), NTP (port 123), and real-time audio/video streaming.

---

## 7. ICMP (Internet Control Message Protocol)

ICMP reports diagnostic conditions and operational errors in network processing.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Identifier          |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **Type 8, Code 0:** Echo Request (used by `ping`).
- **Type 0, Code 0:** Echo Reply (response from target).
- **Type 3:** Destination Unreachable (e.g., Code 1: Host Unreachable, Code 3: Port Unreachable).
- **Type 11:** Time Exceeded (TTL expired in transit; used by `traceroute`).

---

## 8. DNS (Domain Name System: Layer 7)

DNS translates human-readable hostnames (e.g. `example.com`) to machine-routable IP addresses (e.g. `93.184.216.34`).

- Runs primarily over **UDP port 53** for queries.
- Structure contains:
  - **Transaction ID (16 bits):** Matches responses to queries.
  - **Flags (16 bits):** Query/Response flag (QR), Opcode, Authoritative Answer (AA), Truncated (TC), Recursion Desired (RD).
  - **Question Section:** Domain name and query record type:
    - `A` (1): IPv4 address
    - `AAAA` (28): IPv6 address
    - `CNAME` (5): Canonical domain alias
    - `MX` (15): Mail exchange server
  - **Answer Section:** Resource records matching the question.

---

## 9. HTTP (HyperText Transfer Protocol: Layer 7)

Plaintext HTTP/1.1 transmits commands as plain ASCII text over **TCP port 80**.

### Request Format
```http
GET /index.html HTTP/1.1\r\n
Host: example.com\r\n
User-Agent: curl/8.4.0\r\n
Accept: */*\r\n
\r\n
```

### Response Format
```http
HTTP/1.1 200 OK\r\n
Date: Fri, 20 Nov 2026 12:00:00 GMT\r\n
Content-Type: text/html; charset=UTF-8\r\n
Content-Length: 1256\r\n
\r\n
<!doctype html><html>...
```

Because plaintext HTTP carries headers unencrypted, a passive sniffer can read URLs, requested paths, and `Host:` headers directly from the raw payload bytes.
