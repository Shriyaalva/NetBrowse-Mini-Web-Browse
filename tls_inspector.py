"""
tls_inspector.py
================
Connects to a host, completes the TLS handshake, and prints
detailed certificate and cipher suite information.

CN concept: SSL/TLS
  - TLS wraps TCP; negotiation happens via ClientHello/ServerHello
  - X.509 certificates bind a public key to a domain name
  - Certificate chain: leaf → intermediate CA → root CA
  - Cipher suite = key exchange + authentication + cipher + MAC

Usage:
    python tls_inspector.py example.com
    python tls_inspector.py github.com 443
"""

import socket
import ssl
import sys
import argparse
from datetime import datetime

GREEN  = "\033[32m"
CYAN   = "\033[36m"
YELLOW = "\033[33m"
RED    = "\033[31m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def inspect(hostname: str, port: int = 443):
    print(f"\n{BOLD}TLS Inspector{RESET}")
    print(f"{'─'*50}")
    print(f"Target: {hostname}:{port}\n")

    # TCP connect
    print(f"{DIM}[TCP]{RESET}  Connecting …")
    raw = socket.create_connection((hostname, port), timeout=10)
    peer = raw.getpeername()
    print(f"{GREEN}[TCP]{RESET}  Connected to {peer[0]}:{peer[1]}")

    # TLS handshake
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode    = ssl.CERT_REQUIRED

    print(f"{DIM}[TLS]{RESET}  Performing handshake …")
    tls = ctx.wrap_socket(raw, server_hostname=hostname)

    version = tls.version()
    cipher, proto, bits = tls.cipher()
    print(f"{GREEN}[TLS]{RESET}  Handshake complete!")
    print(f"\n{BOLD}── Protocol & Cipher ──────────────────────────{RESET}")
    print(f"  TLS Version   : {version}")
    print(f"  Cipher Suite  : {cipher}")
    print(f"  Protocol      : {proto}")
    print(f"  Key bits      : {bits}")

    # Certificate details
    cert = tls.getpeercert()
    print(f"\n{BOLD}── Certificate ─────────────────────────────────{RESET}")

    subject = {k: v for pair in cert.get("subject", []) for k, v in pair}
    issuer  = {k: v for pair in cert.get("issuer",  []) for k, v in pair}

    print(f"  Subject CN    : {subject.get('commonName', '?')}")
    print(f"  Subject O     : {subject.get('organizationName', '?')}")
    print(f"  Issuer CN     : {issuer.get('commonName', '?')}")
    print(f"  Issuer O      : {issuer.get('organizationName', '?')}")

    not_before = cert.get("notBefore", "")
    not_after  = cert.get("notAfter",  "")
    print(f"  Valid From    : {not_before}")
    print(f"  Valid Until   : {not_after}")

    # Check expiry
    try:
        fmt = "%b %d %H:%M:%S %Y %Z"
        expiry = datetime.strptime(not_after, fmt)
        days_left = (expiry - datetime.utcnow()).days
        if days_left < 0:
            print(f"  {RED}EXPIRED {abs(days_left)} days ago!{RESET}")
        elif days_left < 30:
            print(f"  {YELLOW}Expiry Warning: {days_left} days left{RESET}")
        else:
            print(f"  {GREEN}Valid: {days_left} days remaining{RESET}")
    except Exception:
        pass

    # SANs
    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    print(f"\n{BOLD}── Subject Alt Names (SANs) ────────────────────{RESET}")
    for san in sans[:10]:
        print(f"  {CYAN}{san}{RESET}")
    if len(sans) > 10:
        print(f"  {DIM}… and {len(sans)-10} more{RESET}")

    tls.close()
    print(f"\n{GREEN}✓ Certificate is valid and chain is trusted.{RESET}\n")


def main():
    parser = argparse.ArgumentParser(description="TLS Certificate Inspector")
    parser.add_argument("hostname")
    parser.add_argument("port", type=int, nargs="?", default=443)
    args = parser.parse_args()
    try:
        inspect(args.hostname, args.port)
    except ssl.SSLCertVerificationError as e:
        print(f"{RED}[TLS ERROR] Certificate verification failed: {e}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[ERROR] {e}{RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
