#!/usr/bin/env python3
"""
Generate live traffic to trigger REVA detections while NetWatch is capturing.

Prerequisites:
  1. Run ONE instance of app.py as Administrator
  2. Open http://127.0.0.1:5000 and click Start Capture
  3. Run this script from a second terminal (Admin recommended for Scapy send)

Usage:
  .venv\\Scripts\\python.exe scripts\\demo_reva_traffic.py brute --target 192.168.1.100
  .venv\\Scripts\\python.exe scripts\\demo_reva_traffic.py dns-tunnel
  .venv\\Scripts\\python.exe scripts\\demo_reva_traffic.py payload --target 127.0.0.1 --port 8888
  .venv\\Scripts\\python.exe scripts\\demo_reva_traffic.py beacon --target 8.8.8.8

WARNING: 'beacon' and 'payload' can fire HIGH alerts and trigger IPS auto-block
on YOUR machine's source IP. Use --dry-run first, or test on an isolated lab VM.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time

try:
    from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP, send
except ImportError:
    print("Scapy required: pip install scapy")
    raise SystemExit(1)


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def demo_brute_force(target: str, port: int, count: int, dry_run: bool) -> None:
    print(f"Brute force demo: {count} TCP SYNs to {target}:{port}")
    if dry_run:
        print("[dry-run] Would send SYN packets")
        return
    src = get_local_ip()
    for i in range(count):
        pkt = IP(src=src, dst=target) / TCP(sport=45000 + i, dport=port, flags="S")
        send(pkt, verbose=False)
        time.sleep(0.05)
    print("Done. Check dashboard for 'Brute Force Attempt' (Unauthorized Access).")


def demo_dns_tunnel(dry_run: bool) -> None:
    long_label = "a" * 85
    qname = f"{long_label}.tunnel.demo.local"
    src = get_local_ip()
    print(f"DNS tunnel demo: query length {len(qname)} chars from {src}")
    if dry_run:
        print(f"[dry-run] Would query: {qname[:60]}...")
        return
    pkt = IP(src=src, dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(qd=DNSQR(qname=qname))
    send(pkt, verbose=False)
    print("Done. Check dashboard for 'DNS Tunneling' (Malware Activity).")


def demo_payload(target: str, port: int, dry_run: bool) -> None:
    body = (
        b"GET /run?cmd=POWERSHELL+-enc+SGVsbG8 HTTP/1.1\r\n"
        b"Host: demo.local\r\n"
        b"Connection: close\r\n\r\n"
    )
    src = get_local_ip()
    print(f"Payload demo: HTTP with POWERSHELL signature {src} -> {target}:{port}")
    if dry_run:
        print("[dry-run] Would send cleartext HTTP payload")
        return
    pkt = IP(src=src, dst=target) / TCP(sport=46000, dport=port, flags="PA") / Raw(load=body)
    send(pkt, verbose=False)
    print("Done. Check dashboard for 'Suspicious Payload' (Malware Activity, HIGH).")
    print("NOTE: HIGH alerts may trigger IPS block on your source IP.")


def demo_beacon(target: str, port: int, interval: float, count: int, dry_run: bool) -> None:
    print(
        f"C2 beacon demo: {count} packets every {interval}s to {target}:{port}\n"
        "WARNING: This is HIGH severity and may auto-block YOUR IP via IPS."
    )
    if dry_run:
        print("[dry-run] No packets sent.")
        return
    confirm = input("Type YES to continue: ").strip()
    if confirm != "YES":
        print("Aborted.")
        return
    src = get_local_ip()
    for i in range(count):
        pkt = IP(src=src, dst=target, len=100) / TCP(sport=47000, dport=port, flags="S")
        send(pkt, verbose=False)
        print(f"  sent {i + 1}/{count}")
        if i < count - 1:
            time.sleep(interval)
    print("Done. After 8+ regular packets, expect 'C2 Beacon' (Malware Activity, HIGH).")


def main() -> int:
    parser = argparse.ArgumentParser(description="Live REVA detection demo traffic")
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_brute = sub.add_parser("brute", help="Trigger brute force (auth port SYNs)")
    p_brute.add_argument("--target", required=True, help="Destination IP (lab VM)")
    p_brute.add_argument("--port", type=int, default=22, help="Auth port (default 22)")
    p_brute.add_argument("--count", type=int, default=20, help="SYN count (default 20)")

    p_dns = sub.add_parser("dns-tunnel", help="Trigger long DNS query")

    p_payload = sub.add_parser("payload", help="Trigger suspicious HTTP payload")
    p_payload.add_argument("--target", default="127.0.0.1")
    p_payload.add_argument("--port", type=int, default=8888)

    p_beacon = sub.add_parser("beacon", help="Trigger C2 beacon pattern (HIGH / IPS)")
    p_beacon.add_argument("--target", default="8.8.8.8", help="Public IP (not 203.0.113.x — reserved)")
    p_beacon.add_argument("--port", type=int, default=443)
    p_beacon.add_argument("--interval", type=float, default=30.0)
    p_beacon.add_argument("--count", type=int, default=8)

    args = parser.parse_args()
    dry = args.dry_run

    if args.cmd == "brute":
        demo_brute_force(args.target, args.port, args.count, dry)
    elif args.cmd == "dns-tunnel":
        demo_dns_tunnel(dry)
    elif args.cmd == "payload":
        demo_payload(args.target, args.port, dry)
    elif args.cmd == "beacon":
        demo_beacon(args.target, args.port, args.interval, args.count, dry)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
