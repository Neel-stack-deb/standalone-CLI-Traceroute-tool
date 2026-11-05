# Standalone CLI Traceroute Tool (Go)

A lightweight **ICMP traceroute** implementation for Linux that crafts **raw Echo Request packets**, increments **IP TTL** via `setsockopt`, parses **inbound ICMP Type 11 (Time Exceeded)** and **Type 0 (Echo Reply)** messages without third-party packet libraries, and enriches each hop with **reverse DNS** and **Team Cymru ASN** data.

---

## 1. Project Overview

Traceroute discovers the path packets take to a destination by sending probes with increasing Time-To-Live (TTL). Each router decrements TTL; when TTL reaches zero, the router returns an ICMP **Time Exceeded** message. The final host typically returns an ICMP **Echo Reply** when the probe is an Echo Request that reaches the destination.

This project implements that behavior as a **standalone command-line program** suitable for networking coursework or lab demonstrations. It emphasizes:

- Low-level socket programming (`SOCK_RAW`, `IPPROTO_ICMP`)
- Manual ICMP header construction and **RFC 1071** checksums
- Native parsing of IPv4 + ICMP datagrams
- Practical output enrichment (PTR + ASN/organization)

**Platform:** Linux (IPv4). Raw ICMP requires `CAP_NET_RAW` or root.

---

## 2. Learning Objectives

After studying or running this tool, you should understand:

1. How TTL controls path discovery and why intermediate routers emit ICMP Type 11.
2. How ICMP Echo Request / Reply (Type 8 / Type 0) probes differ from UDP-based traceroute.
3. How to compute Internet checksums (one’s complement sum) over arbitrary byte buffers.
4. Why raw sockets are privileged and how Linux file capabilities reduce reliance on full root.
5. How reverse DNS and Team Cymru’s DNS-based ASN service augment bare IP addresses.

---

## 3. Architecture

```
cmd/traceroute-tool/main.go     CLI flags (-m, -w, -q) and error handling
internal/icmpproto/             ICMP constants, RFC 1071 checksum, echo marshaling, reply matching
internal/rawsock/               Linux SOCK_RAW socket, IP_TTL, send/recv timeouts
internal/trace/                 Traceroute control loop (3 probes/hop by default)
internal/enrich/                PTR lookup + Cymru TXT ASN lookup with timeouts
internal/output/                Aligned terminal table rendering
```

### Control flow

1. Resolve the target hostname to an IPv4 address.
2. Open `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`.
3. For each hop `1 … max`:
   - Set `IP_TTL` to the hop number.
   - Send `q` ICMP Echo Requests (unique sequence numbers).
   - Wait up to `-w` seconds per probe for Type 11 or Type 0 replies matching our identifier/sequence.
   - Record RTT samples; compute **min / avg / max** in milliseconds.
   - Perform PTR and Cymru ASN lookups for the responding router IP.
4. Stop early when an Echo Reply indicates the destination was reached.

---

## 4. Protocol & Packet Details

| Constant | Value | Meaning |
| --- | --- | --- |
| ICMP Echo Request | Type 8 | Outbound probe |
| ICMP Echo Reply | Type 0 | Destination reached |
| ICMP Time Exceeded | Type 11 | TTL expired at intermediate router |

**Checksum (RFC 1071):** Sum 16-bit words in one’s complement; fold carries; bitwise NOT. Implemented in `internal/icmpproto/checksum.go`.

**Matching replies:** For Type 0, identifier and sequence are read at ICMP bytes 4–7. For Type 11, the original IP datagram and first 8 bytes of the original ICMP message are embedded after the 8-byte ICMP header; the embedded Echo Request must match our identifier and sequence.

**RTT:** Measured from immediately before `sendto` until a matching datagram is received.

---

## 5. Network Enrichment

For each responding hop IP:

| Step | Mechanism | Fallback |
| --- | --- | --- |
| Hostname | Reverse DNS (`LookupAddr`) | `-` on timeout/error |
| ASN / ISP | DNS TXT to `<reversed-ipv4>.origin.asn.cymru.com` (Team Cymru) | `-` on timeout/error |

Cymru TXT format (pipe-separated): `ASN | Prefix | CC | Registry | Allocated | AS Name`. The tool displays `AS<number>` and the organization field.

Lookup timeout: **2 seconds** per enrichment phase (independent of probe timeout).

---

## 6. Requirements

- **OS:** Linux (uses `SOCK_RAW`)
- **Go:** 1.22+
- **Privileges:** `CAP_NET_RAW` **or** root (see below)
- **Network:** Outbound ICMP and DNS (for resolution and enrichment)

Optional packages installed by `.cursor/install.sh` for development convenience: `iputils-tracepath`, `traceroute` (not used at runtime by this implementation).

---

## 7. Build & Run

```bash
make build          # produces bin/traceroute-tool
make test           # unit tests (checksum, parsing, enrichment helpers)
```

### Usage

```bash
sudo ./bin/traceroute-tool [-m max-hops] [-w timeout-seconds] [-q probes-per-hop] host
```

| Flag | Default | Description |
| --- | --- | --- |
| `-m` | 30 | Maximum TTL / hop count |
| `-w` | 3.0 | Per-probe timeout (seconds) |
| `-q` | 3 | Probes per hop (standard traceroute style) |

### Example

```bash
sudo ./bin/traceroute-tool -m 15 -w 2 -q 3 google.com
```

### Sample output

```
traceroute to google.com (142.250.185.78), 15 hops max, 3 probes per hop

Hop #  RTT min/avg/max (ms)  IP Address      Hostname / PTR  ASN & ISP
1      * * *                 *               -               -
4      2.977/3.102/3.334     10.1.3.145      -               AS… …
```

Non-responsive probes within a hop appear as `* * *` in the RTT column.

---

## 8. Privileges: `sudo` vs `setcap`

Raw ICMP sockets fail with `EPERM` without capability:

```text
raw ICMP socket permission denied: open SOCK_RAW IPPROTO_ICMP
```

**Option A — run with sudo (simplest for labs):**

```bash
sudo ./bin/traceroute-tool 8.8.8.8
```

**Option B — file capability (no sudo on each run):**

```bash
sudo setcap cap_net_raw+ep ./bin/traceroute-tool
./bin/traceroute-tool 8.8.8.8
```

Verify:

```bash
getcap ./bin/traceroute-tool
# ./bin/traceroute-tool cap_net_raw=ep
```

Remove capability:

```bash
sudo setcap -r ./bin/traceroute-tool
```

---

## 9. Wireshark Capture (Lab Exercise)

1. Start capture on the egress interface (often `eth0` or `any`).
2. Filter: `icmp || (dns && (dns.qname contains "origin.asn.cymru" || dns.flags.response))`
3. Run the tool with a low hop limit: `sudo ./bin/traceroute-tool -m 5 -q 1 example.com`
4. Observe:
   - Outbound Echo Request (Type 8) with increasing IP TTL in the **IP header** (not ICMP).
   - Inbound Type 11 from intermediate routers or Type 0 from the destination.
   - DNS queries for PTR and Cymru TXT after each hop.

Export interesting packets for your report (File → Export Specified Packets).

---

## 10. Testing Strategy

| Layer | Tests |
| --- | --- |
| Checksum | RFC 1071 vector, echo checksum validation |
| Parser | Synthetic IPv4 datagrams for Type 0 and Type 11 |
| Enrichment | Cymru reverse-octet helper |
| Integration | Manual run with `sudo` on a real target |

Cloud VMs often filter ICMP responses; `* * *` hops may reflect environment policy, not necessarily a bug.

---

## 11. Limitations & Future Work

- **IPv4 only** in this version (no ICMPv6 / raw IPv6).
- **Linux-specific** raw socket code (`internal/rawsock/socket_linux.go`).
- Enrichment depends on public DNS (Cymru, resolvers).
- No parallel probing across hops (sequential, classroom-friendly).
- Possible extensions: JSON output, TCP/UDP probe modes, configurable payload size.

---

## 12. References

- RFC 792 — Internet Control Message Protocol
- RFC 1071 — Computing the Internet Checksum
- Team Cymru IP-to-ASN DNS service (`origin.asn.cymru.com`)
- Linux `man 7 raw`, `man 7 icmp`, `capabilities(7)`

---

## 13. Academic Integrity Note

If you submit this project for grading, clearly document:

- What you implemented yourself
- Any collaboration or AI assistance
- Screenshots / Wireshark evidence from **your** test runs

---

## License

See repository license (if present). Intended for educational use in networking courses.
