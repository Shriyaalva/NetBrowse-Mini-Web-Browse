# Mini Web Browser
### CN Concepts: DNS · TCP/IP · SSL/TLS · HTTP · Networking Fundamentals

A from-scratch browser built with Python's `socket` and `ssl` modules only.
No `requests`, no `httpx`, no `urllib` — pure sockets.

---

## Project Structure

```
mini_browser/
├── browser.py          ← Main browser (fetch any URL)
├── dns_inspector.py    ← Raw UDP DNS queries (A, MX, TXT, CNAME …)
├── tls_inspector.py    ← TLS handshake + certificate analysis
└── README.md
```

---

## Requirements

- Python 3.10+
- No external libraries

---

## How to Run

### 1. Fetch a webpage
```bash
python browser.py https://example.com
python browser.py https://httpbin.org/get
python browser.py http://neverssl.com          # HTTP (no TLS)
python browser.py --dump-headers https://github.com
python browser.py --max-body 5000 https://example.com
```

### 2. DNS Inspector (raw UDP queries)
```bash
python dns_inspector.py example.com
python dns_inspector.py --type MX gmail.com
python dns_inspector.py --type TXT github.com
python dns_inspector.py --type NS cloudflare.com
python dns_inspector.py --type AAAA google.com    # IPv6
```

### 3. TLS Inspector (certificate details)
```bash
python tls_inspector.py github.com
python tls_inspector.py google.com 443
python tls_inspector.py expired.badssl.com        # see an expired cert!
```

---

## CN Concepts Demonstrated

### DNS (Domain Name System)
| Component | Code location |
|-----------|--------------|
| `getaddrinfo()` — OS resolver | `browser.py` → `dns_resolve()` |
| Raw UDP DNS packet (RFC 1035) | `dns_inspector.py` → `build_query()` |
| Label encoding, pointer compression | `dns_inspector.py` → `parse_name()` |
| A, MX, TXT, CNAME, AAAA records | `dns_inspector.py` → `parse_rdata()` |

### TCP/IP
| Component | Code location |
|-----------|--------------|
| `socket.create_connection()` — 3-way handshake | `browser.py` → `tcp_connect()` |
| Port 80 (HTTP) vs 443 (HTTPS) | `browser.py` → `fetch()` |
| Reliable byte stream, `sendall()` / `recv()` | Throughout |

### SSL/TLS
| Component | Code location |
|-----------|--------------|
| `ssl.SSLContext` + `wrap_socket()` | `browser.py` → `tls_wrap()` |
| Cipher suite, TLS version | `tls_inspector.py` → `inspect()` |
| X.509 certificate parsing | `tls_inspector.py` → `inspect()` |
| SANs, expiry, CA chain | `tls_inspector.py` → `inspect()` |

### HTTP
| Component | Code location |
|-----------|--------------|
| Hand-crafted GET request headers | `browser.py` → `build_request()` |
| Status line + header parsing | `browser.py` → `parse_response()` |
| Chunked transfer decoding | `browser.py` → `decode_chunked()` |
| 301/302/307 redirect following | `browser.py` → `fetch()` |

### Networking Fundamentals
- Port numbers: 53 (DNS/UDP), 80 (HTTP/TCP), 443 (HTTPS/TCP)
- Protocol layering: DNS → TCP → TLS → HTTP
- Packet structure: fixed headers + variable-length data
- Timeouts, error handling, socket lifecycle

---

## Layer-by-layer Flow

```
You type:  https://example.com
               │
         ┌─────▼─────┐
         │    DNS     │  hostname → IP (UDP port 53)
         └─────┬─────┘
               │  93.184.216.34
         ┌─────▼─────┐
         │   TCP/IP   │  SYN → SYN-ACK → ACK  (port 443)
         └─────┬─────┘
               │  connected
         ┌─────▼─────┐
         │  SSL/TLS   │  ClientHello → cert → session keys
         └─────┬─────┘
               │  encrypted tunnel
         ┌─────▼─────┐
         │   HTTP     │  GET / HTTP/1.1 → 200 OK → body
         └─────┬─────┘
               │
         ┌─────▼─────┐
         │  Display   │  print headers + body text
         └───────────┘
```

---

## Sample Output

```
============================================================
Fetching: https://example.com
============================================================

[DNS]  Resolving example.com …
[DNS]  example.com → 93.184.216.34
[TCP]  Connecting to example.com:443 …
[TCP]  192.168.1.5:54312 → 93.184.216.34:443
[TLS]  Starting TLS handshake with example.com …
[TLS]  TLSv1.3  cipher=TLS_AES_256_GCM_SHA384
[TLS]  cert CN=www.example.org  expires=Mar 22 00:00:00 2025 GMT
[HTTP] → GET / HTTP/1.1
[HTTP] ← 200 OK

--- Response Headers ---
  content-type: text/html; charset=UTF-8
  content-length: 1256
  ...

--- Body (first 2000 chars) ---
<!doctype html>
<html>...
```

---

## Viva Questions & Answers

**Q: What happens when you type a URL?**
A: DNS resolves the hostname → TCP connects → TLS handshakes (if HTTPS) → HTTP GET is sent → response is parsed.

**Q: Why use TCP and not UDP for HTTP?**
A: HTTP needs reliable, ordered delivery. TCP guarantees this; UDP does not.

**Q: What is the TLS handshake?**
A: Client sends ClientHello (cipher list). Server replies with its certificate and chosen cipher. Both derive session keys. All further data is encrypted.

**Q: What is chunked transfer encoding?**
A: Server sends body in variable-size pieces, each prefixed with its hex size. Useful when content-length is unknown upfront.

**Q: What is a DNS A record vs CNAME?**
A: A record maps name → IPv4. CNAME maps name → another name (alias). The resolver follows CNAMEs until it finds an A record.
