"""
dns_inspector.py
================
Deep-dive DNS tool — queries A, AAAA, MX, CNAME, TXT, NS records
using raw UDP sockets (port 53), without dnspython or any library.

CN concept: DNS uses UDP port 53. A query is a binary packet with
a header, question section, and (in the response) answer section.

Usage:
    python dns_inspector.py example.com
    python dns_inspector.py --type MX gmail.com
    python dns_inspector.py --type TXT github.com
"""

import socket
import struct
import sys
import argparse
import random

DNS_SERVER = "8.8.8.8"   # Google Public DNS
DNS_PORT   = 53
TIMEOUT    = 5

# Record type codes
QTYPES = {
    "A":     1,
    "NS":    2,
    "CNAME": 5,
    "MX":    15,
    "TXT":   16,
    "AAAA":  28,
}

QTYPE_NAMES = {v: k for k, v in QTYPES.items()}

GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


# ══════════════════════════════════════════════════════════════════
# Build a raw DNS query packet
# ══════════════════════════════════════════════════════════════════

def build_query(domain: str, qtype: int) -> bytes:
    """
    DNS packet structure (RFC 1035):
      Header (12 bytes):
        ID (2) | Flags (2) | QDCOUNT (2) | ANCOUNT (2) | NSCOUNT (2) | ARCOUNT (2)
      Question:
        QNAME (labels) | QTYPE (2) | QCLASS (2)
    """
    txn_id = random.randint(0, 65535)
    flags  = 0x0100          # standard query, recursion desired
    header = struct.pack(">HHHHHH", txn_id, flags, 1, 0, 0, 0)

    # Encode domain as length-prefixed labels: "example.com" → \x07example\x03com\x00
    labels = b""
    for part in domain.split("."):
        encoded = part.encode()
        labels += bytes([len(encoded)]) + encoded
    labels += b"\x00"

    question = labels + struct.pack(">HH", qtype, 1)   # QCLASS=IN
    return header + question, txn_id


# ══════════════════════════════════════════════════════════════════
# Parse response
# ══════════════════════════════════════════════════════════════════

def parse_name(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a DNS name, following compression pointers."""
    labels = []
    visited = set()
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:          # pointer
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if ptr in visited:
                break
            visited.add(ptr)
            name, _ = parse_name(data, ptr)
            labels.append(name)
            offset += 2
            break
        labels.append(data[offset + 1: offset + 1 + length].decode(errors="replace"))
        offset += 1 + length
    return ".".join(labels), offset


def parse_rdata(data: bytes, offset: int, rdlength: int, rtype: int) -> str:
    rdata = data[offset: offset + rdlength]
    if rtype == 1:    # A
        return socket.inet_ntoa(rdata)
    if rtype == 28:   # AAAA
        return socket.inet_ntop(socket.AF_INET6, rdata)
    if rtype in (2, 5):   # NS, CNAME
        name, _ = parse_name(data, offset)
        return name
    if rtype == 15:   # MX
        pref = struct.unpack(">H", rdata[:2])[0]
        name, _ = parse_name(data, offset + 2)
        return f"priority={pref} exchange={name}"
    if rtype == 16:   # TXT
        parts = []
        i = 0
        while i < len(rdata):
            l = rdata[i]; i += 1
            parts.append(rdata[i:i+l].decode(errors="replace"))
            i += l
        return " ".join(parts)
    return rdata.hex()


def parse_response(data: bytes, txn_id: int) -> list[dict]:
    if len(data) < 12:
        raise ValueError("Response too short")

    hdr = struct.unpack(">HHHHHH", data[:12])
    resp_id, flags, qdcount, ancount, nscount, arcount = hdr

    if resp_id != txn_id:
        raise ValueError(f"Transaction ID mismatch: {resp_id} != {txn_id}")

    rcode = flags & 0x000F
    if rcode != 0:
        raise ValueError(f"DNS error RCODE={rcode}")

    offset = 12
    # Skip questions
    for _ in range(qdcount):
        _, offset = parse_name(data, offset)
        offset += 4   # QTYPE + QCLASS

    records = []
    for _ in range(ancount + nscount + arcount):
        if offset >= len(data):
            break
        name, offset = parse_name(data, offset)
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
        offset += 10
        rdata = parse_rdata(data, offset, rdlength, rtype)
        offset += rdlength
        records.append({
            "name":  name,
            "type":  QTYPE_NAMES.get(rtype, str(rtype)),
            "ttl":   ttl,
            "rdata": rdata,
        })
    return records


# ══════════════════════════════════════════════════════════════════
# Main query
# ══════════════════════════════════════════════════════════════════

def dns_query(domain: str, qtype_name: str = "A") -> list[dict]:
    qtype = QTYPES.get(qtype_name.upper(), 1)
    packet, txn_id = build_query(domain, qtype)

    print(f"{DIM}[DNS]{RESET} Sending UDP query to {DNS_SERVER}:{DNS_PORT}")
    print(f"{DIM}[DNS]{RESET} Query: {domain} type={qtype_name}  packet={len(packet)} bytes")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)
    try:
        sock.sendto(packet, (DNS_SERVER, DNS_PORT))
        response, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    print(f"{GREEN}[DNS]{RESET} Response: {len(response)} bytes received")
    return parse_response(response, txn_id)


def main():
    parser = argparse.ArgumentParser(description="DNS Inspector")
    parser.add_argument("domain", help="Domain to query")
    parser.add_argument("--type", default="A",
                        choices=list(QTYPES.keys()),
                        help="Record type (default: A)")
    args = parser.parse_args()

    print(f"\n{BOLD}DNS Inspector{RESET}")
    print(f"{'─'*40}")

    try:
        records = dns_query(args.domain, args.type)
    except Exception as e:
        print(f"\033[31m[ERROR]{RESET} {e}")
        sys.exit(1)

    print(f"\n{BOLD}Results ({len(records)} records):{RESET}")
    for r in records:
        print(f"  {CYAN}{r['type']:6}{RESET}  ttl={r['ttl']:6d}s  {r['rdata']}")

    if not records:
        print("  No records found.")


if __name__ == "__main__":
    main()
