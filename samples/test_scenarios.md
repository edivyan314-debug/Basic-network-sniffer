# Educational Test Scenarios

This guide details three reproducible hands-on test scenarios designed to observe how real-world network protocols behave at the packet layer.

---

## Scenario 1: ICMP Echo ("Ping")

### Purpose
Observe Layer 3 control messages without any transport-layer ports. Notice how ICMP Echo Request (type 8) and Echo Reply (type 0) match sequence numbers and identifiers.

### Step 1: Start the Sniffer
In your primary terminal (elevated as Administrator / root):
```bash
python sniffer.py -f "icmp" -v
```

### Step 2: Trigger Traffic
In a separate terminal window, ping a known reliable server:
```bash
# Windows
ping -n 2 8.8.8.8

# Linux / macOS
ping -c 2 8.8.8.8
```

### Expected Output
```text
21:48:10.104  ICMP   192.168.1.100 -> 8.8.8.8    len=74   Echo Request (code=0)
       Payload (first 64B):
          0000   08 00 4d 5b 00 01 00 01  61 62 63 64 65 66 67 68  |..M[....abcdefgh|
21:48:10.128  ICMP   8.8.8.8 -> 192.168.1.100    len=74   Echo Reply (code=0)
       Payload (first 64B):
          0000   00 00 55 5b 00 01 00 01  61 62 63 64 65 66 67 68  |..U[....abcdefgh|
```

### What to Learn
1. Notice that `src_port` and `dst_port` are absent because ICMP operates directly on top of IP (Protocol 1), bypassing TCP and UDP.
2. The payload in Windows ping contains default alphabet strings (`abcdefghijklmnopqrstuvw...`) used to test round-trip latency.

---

## Scenario 2: DNS Query & Resolution

### Purpose
Observe UDP datagram exchange over port 53, and see how the queried hostname is decoded directly from the payload.

### Step 1: Start the Sniffer
```bash
python sniffer.py -p dns -v
```

### Step 2: Trigger Traffic
In another terminal, perform a DNS query:
```bash
# Windows PowerShell
Resolve-DnsName -Name example.com -Type A

# Linux / macOS / Windows CMD
nslookup example.com 1.1.1.1
```

### Expected Output
```text
21:48:12.431  DNS    192.168.1.100:54210 -> 1.1.1.1:53   len=68   Query example.com [A]
       Payload (first 64B):
          0000   b3 a1 01 00 00 01 00 00  00 00 00 00 07 65 78 61  |.............exa|
          0010   6d 70 6c 65 03 63 6f 6d  00 00 01 00 01           |mple.com.....|
21:48:12.449  DNS    1.1.1.1:53 -> 192.168.1.100:54210   len=84   Response (Answers: 1)
```

### What to Learn
1. DNS queries send the requested domain labels prefixed by their byte lengths (e.g. `\x07example\x03com\x00`).
2. UDP is connectionless: there is no prior handshake before the query packet is sent.

---

## Scenario 3: Plaintext HTTP Request & Response

### Purpose
Observe the full TCP 3-way handshake (`SYN` -> `SYN-ACK` -> `ACK`), data transfer (`PSH-ACK`), and connection teardown (`FIN-ACK`).

### Step 1: Start the Sniffer
```bash
python sniffer.py -f "tcp port 80" -o http_capture.pcap -v
```

### Step 2: Trigger Traffic
Fetch a website that serves plaintext HTTP:
```bash
# Using curl (all platforms)
curl -i http://neverssl.com/
```

### Expected Output
```text
21:48:15.012  TCP    192.168.1.100:59124 -> 93.184.216.34:80  [SYN] len=64
21:48:15.045  TCP    93.184.216.34:80 -> 192.168.1.100:59124  [SYN ACK] len=60
21:48:15.046  TCP    192.168.1.100:59124 -> 93.184.216.34:80  [ACK] len=52
21:48:15.050  HTTP   192.168.1.100:59124 -> 93.184.216.34:80  [PSH ACK] len=138  HTTP Request: GET / HTTP/1.1 [Host: neverssl.com]
       Payload (first 64B):
          0000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  |GET / HTTP/1.1..|
          0010   48 6f 73 74 3a 20 6e 65  76 65 72 73 73 6c 2e 63  |Host: neverssl.c|
21:48:15.092  HTTP   93.184.216.34:80 -> 192.168.1.100:59124  [PSH ACK] len=450  HTTP Response: HTTP/1.1 200 OK
21:48:15.105  TCP    192.168.1.100:59124 -> 93.184.216.34:80  [FIN ACK] len=52
21:48:15.140  TCP    93.184.216.34:80 -> 192.168.1.100:59124  [FIN ACK] len=52
21:48:15.141  TCP    192.168.1.100:59124 -> 93.184.216.34:80  [ACK] len=52
```

### What to Learn
1. **Three-Way Handshake:** Notice packets 1, 2, and 3 carrying `SYN`, `SYN-ACK`, and `ACK` flags with 0 payload bytes before any data is sent.
2. **Cleartext Payload:** Plaintext HTTP headers (`Host:`, `User-Agent:`) and response status codes (`200 OK`) are completely readable in the ASCII preview. This demonstrates why modern internet traffic relies on HTTPS / TLS encryption to prevent eavesdropping on sensitive credentials.
