"""
Mini Web Browser
================
Demonstrates: DNS · TCP/IP · SSL/TLS · HTTP · Networking Fundamentals

Concepts covered
----------------
DNS       - socket.getaddrinfo() resolves hostname → IP
TCP/IP    - raw socket.create_connection() builds the TCP stream
SSL/TLS   - ssl.SSLContext wraps the socket for HTTPS (port 443)
HTTP      - hand-crafted GET request, response parser (status, headers, body)
Net Fund  - ports (80/443), keep-alive, redirect following, chunked transfer

Usage
-----
    python browser.py https://example.com
    python browser.py http://httpbin.org/get
    python browser.py --dump-headers https://httpbin.org/headers
"""

import socket
import ssl
import sys
import argparse
from urllib.parse import urlparse, urljoin
from datetime import datetime

# ── ANSI colours (disabled on Windows if needed) ──────────────────────────────
GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

MAX_REDIRECTS = 5
TIMEOUT       = 10          # seconds


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — DNS Resolution
# ══════════════════════════════════════════════════════════════════════════════

def dns_resolve(hostname: str, port: int) -> list[tuple]:
    """
    Uses the OS resolver (which itself queries UDP port 53).
    Returns a list of (family, type, proto, canonname, sockaddr) tuples.

    CN concept: DNS translates human-readable names to IP addresses.
    """
    print(f"{DIM}[DNS]{RESET}  Resolving {BOLD}{hostname}{RESET} …")
    try:
        results = socket.getaddrinfo(hostname, port,
                                     proto=socket.IPPROTO_TCP)
        if not results:
            raise OSError("No addresses found")
        ip = results[0][4][0]
        print(f"{GREEN}[DNS]{RESET}  {hostname} → {ip}")
        return results
    except socket.gaierror as e:
        raise SystemExit(f"{RED}[DNS ERROR]{RESET} {e}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — TCP/IP Connection
# ══════════════════════════════════════════════════════════════════════════════

def tcp_connect(hostname: str, port: int) -> socket.socket:
    """
    Opens a TCP stream socket to (hostname, port).

    CN concept: TCP three-way handshake (SYN → SYN-ACK → ACK) happens here.
    The OS handles the handshake; we just call connect().
    """
    print(f"{DIM}[TCP]{RESET}  Connecting to {hostname}:{port} …")
    try:
        sock = socket.create_connection((hostname, port), timeout=TIMEOUT)
        local  = sock.getsockname()
        remote = sock.getpeername()
        print(f"{GREEN}[TCP]{RESET}  {local[0]}:{local[1]} → {remote[0]}:{remote[1]}")
        return sock
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        raise SystemExit(f"{RED}[TCP ERROR]{RESET} {e}")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — SSL/TLS Handshake (HTTPS only)
# ══════════════════════════════════════════════════════════════════════════════

def tls_wrap(sock: socket.socket, hostname: str) -> ssl.SSLSocket:
    """
    Wraps a plain TCP socket with TLS.

    CN concept:
      - ClientHello / ServerHello exchange negotiates cipher suite
      - Server sends certificate; client verifies against trusted CAs
      - Session keys are derived via key exchange (ECDHE etc.)
      - All subsequent data is encrypted
    """
    print(f"{DIM}[TLS]{RESET}  Starting TLS handshake with {hostname} …")
    ctx = ssl.create_default_context()          # loads system CA bundle
    tls_sock = ctx.wrap_socket(sock, server_hostname=hostname)
    cipher  = tls_sock.cipher()
    version = tls_sock.version()
    cert    = tls_sock.getpeercert()
    subject = dict(x[0] for x in cert.get("subject", []))
    expiry  = cert.get("notAfter", "unknown")
    print(f"{GREEN}[TLS]{RESET}  {version}  cipher={cipher[0]}")
    print(f"{GREEN}[TLS]{RESET}  cert CN={subject.get('commonName','?')}  expires={expiry}")
    return tls_sock


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — HTTP Request
# ══════════════════════════════════════════════════════════════════════════════

def build_request(method: str, path: str, hostname: str,
                  extra_headers: dict = None) -> bytes:
    """
    Builds a raw HTTP/1.1 request.

    CN concept: HTTP is an application-layer text protocol over TCP.
    Request line + headers + blank line = end of headers.
    """
    headers = {
        "Host":            hostname,
        "User-Agent":      "MiniPyBrowser/1.0",
        "Accept":          "text/html,application/json,*/*",
        "Accept-Encoding": "identity",   # avoid gzip so body is human-readable
        "Connection":      "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    lines = [f"{method} {path} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in headers.items()]
    lines += ["", ""]                    # blank line terminates headers
    raw = "\r\n".join(lines)
    print(f"{DIM}[HTTP]{RESET} → {method} {path}")
    return raw.encode()


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — HTTP Response Parser
# ══════════════════════════════════════════════════════════════════════════════

def recv_all(sock) -> bytes:
    """Read until the server closes the connection."""
    chunks = []
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
        except socket.timeout:
            break
    return b"".join(chunks)


def parse_response(raw: bytes) -> dict:
    """
    Splits raw HTTP response into status, headers, body.

    CN concept: HTTP response = status line + headers + blank line + body.
    Chunked transfer encoding reassembles the body.
    """
    sep = b"\r\n\r\n"
    idx = raw.find(sep)
    if idx == -1:
        return {"status": 0, "reason": "Bad response", "headers": {}, "body": raw}

    header_part = raw[:idx].decode(errors="replace")
    body        = raw[idx + 4:]

    lines = header_part.split("\r\n")
    status_line = lines[0]
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) >= 2 else 0
    reason = parts[2] if len(parts) >= 3 else ""

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

    # Reassemble chunked transfer
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = decode_chunked(body)

    return {"status": status, "reason": reason, "headers": headers, "body": body}


def decode_chunked(data: bytes) -> bytes:
    """Reassemble HTTP chunked transfer encoding."""
    result = []
    while data:
        crlf = data.find(b"\r\n")
        if crlf == -1:
            break
        size = int(data[:crlf], 16)
        if size == 0:
            break
        result.append(data[crlf + 2: crlf + 2 + size])
        data = data[crlf + 2 + size + 2:]
    return b"".join(result)


# ══════════════════════════════════════════════════════════════════════════════
# Main fetch — ties all layers together
# ══════════════════════════════════════════════════════════════════════════════

def fetch(url: str, redirects: int = 0) -> dict:
    if redirects > MAX_REDIRECTS:
        raise SystemExit(f"{RED}Too many redirects{RESET}")

    parsed = urlparse(url)
    scheme   = parsed.scheme.lower()
    hostname = parsed.hostname
    port     = parsed.port or (443 if scheme == "https" else 80)
    path     = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}Fetching:{RESET} {url}")
    print(f"{BOLD}{'='*60}{RESET}\n")

    # ── DNS ──────────────────────────────────────────────────────
    dns_resolve(hostname, port)

    # ── TCP ──────────────────────────────────────────────────────
    sock = tcp_connect(hostname, port)

    # ── TLS (HTTPS only) ─────────────────────────────────────────
    if scheme == "https":
        sock = tls_wrap(sock, hostname)
    else:
        print(f"{YELLOW}[TLS]{RESET}  Skipped (HTTP — unencrypted)")

    # ── HTTP ─────────────────────────────────────────────────────
    req = build_request("GET", path, hostname)
    sock.sendall(req)
    raw = recv_all(sock)
    sock.close()

    resp = parse_response(raw)
    status = resp["status"]
    reason = resp["reason"]

    colour = GREEN if 200 <= status < 300 else YELLOW if status < 400 else RED
    print(f"{colour}[HTTP]{RESET} ← {status} {reason}")

    # ── Follow redirects ─────────────────────────────────────────
    if status in (301, 302, 303, 307, 308):
        location = resp["headers"].get("location", "")
        if location:
            if location.startswith("/"):
                location = f"{scheme}://{hostname}{location}"
            print(f"{YELLOW}[HTTP]{RESET}  Redirect → {location}")
            return fetch(location, redirects + 1)

    return resp


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def print_response(resp: dict, dump_headers: bool, max_body: int):
    print(f"\n{BOLD}--- Response Headers ---{RESET}")
    for k, v in resp["headers"].items():
        print(f"  {CYAN}{k}{RESET}: {v}")

    if not dump_headers:
        body_text = resp["body"].decode(errors="replace")
        print(f"\n{BOLD}--- Body (first {max_body} chars) ---{RESET}")
        print(body_text[:max_body])
        if len(body_text) > max_body:
            print(f"\n{DIM}… ({len(body_text) - max_body} more chars){RESET}")


def main():
    parser = argparse.ArgumentParser(description="Mini Web Browser")
    parser.add_argument("url", help="URL to fetch (http:// or https://)")
    parser.add_argument("--dump-headers", action="store_true",
                        help="Show only headers, not body")
    parser.add_argument("--max-body", type=int, default=2000,
                        help="Max body characters to display (default 2000)")
    args = parser.parse_args()

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    t0 = datetime.now()
    resp = fetch(url)
    elapsed = (datetime.now() - t0).total_seconds()

    print_response(resp, args.dump_headers, args.max_body)
    size = len(resp["body"])
    print(f"\n{DIM}Completed in {elapsed:.2f}s  |  body={size} bytes{RESET}\n")


if __name__ == "__main__":
    main()
