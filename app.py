from flask import Flask, render_template
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, wrpcap
from collections import defaultdict, deque
from dotenv import load_dotenv
import threading
import queue
import time
import platform
import subprocess
import os
import json
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
import statistics

# Load environment variables from a local .env file if present.
load_dotenv()

app = Flask(__name__)
# SECRET_KEY is read from the environment; the literal is only a dev fallback.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'reva_sniffer_2024')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── Shared State ──────────────────────────────────────────────────────────────
captured_packets = []
packet_lock = threading.Lock()

stats = {
    "total":   0,
    "tcp":     0,
    "udp":     0,
    "icmp":    0,
    "other":   0,
    "dropped": 0,   # packets dropped because the analysis queue was full
}

ip_counter    = defaultdict(int)   # src IP → packet count
port_counter  = defaultdict(int)   # dst port → packet count
alerts        = []                 # anomaly alert list

# ── Producer-Consumer Pipeline ──────────────────────────────────────────────
# The sniffer thread only enqueues raw packets (fast producer). A pool of
# worker threads drains the queue and runs the heavy parse/detect/emit work,
# so Scapy never blocks on analysis and packet loss stays low under load.
PACKET_QUEUE_MAXSIZE = 10000
WORKER_COUNT         = 2
packet_queue: "queue.Queue" = queue.Queue(maxsize=PACKET_QUEUE_MAXSIZE)
worker_threads: list = []

# ── FEATURE 2 ─ Passive Intelligence (DNS + TTL OS Fingerprint) ─────────────
# src IP → guessed OS string, and a bounded buffer of recent DNS queries.
intel_lock        = threading.Lock()
os_fingerprints   = {}              # { src_ip: "Linux / Unix" | "Windows" | ... }
recent_dns        = deque(maxlen=30)  # [ {time, src, query}, ... ]
capture_started_at = None           # epoch seconds when the current session began

# ── Threat intelligence (AbuseIPDB + VirusTotal) ────────────────────────────
ABUSEIPDB_API_KEY  = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
THREAT_INTEL_CACHE_TTL = 600      # seconds before re-querying the same IP
ip_reputation: dict = {}          # ip -> {abuse_score, vt_malicious, country, ...}
reputation_lock     = threading.Lock()
_enriching_ips: set = set()       # IPs currently being looked up
_enriching_lock     = threading.Lock()

# ── SYN Flood tracker: src IP → list of SYN timestamps ──────────────────────
syn_tracker = defaultdict(list)

# ── FEATURE 1 ─ Sliding-Window Port Scan Tracker ────────────────────────────
# src IP → list of (timestamp, dst_port) tuples
port_scan_tracker = defaultdict(list)
PORT_SCAN_WINDOW  = 10   # seconds for the sliding window
PORT_SCAN_THRESHOLD = 15  # unique destination ports within the window

sniffing = False
sniffer_thread = None

# ── Anomaly Detection Config ─────────────────────────────────────────────────
SYN_FLOOD_THRESHOLD = 20   # SYNs from one IP within 5 seconds
ALERT_COOLDOWN      = {}   # key → last alert timestamp (cooldown map)

# ── REVA: DNS anomaly detection ─────────────────────────────────────────────
dns_query_tracker   = defaultdict(list)  # src -> [(timestamp, query_name), ...]
DNS_WINDOW          = 60
DNS_DGA_THRESHOLD   = 50
DNS_TUNNEL_MIN_LEN  = 80

# ── REVA: Auth-port brute force / unauthorized access ───────────────────────
AUTH_PORTS          = {21, 22, 23, 3389, 445, 5985, 5986}
auth_port_tracker   = defaultdict(list)  # src -> [(timestamp, dst_port), ...]
AUTH_WINDOW         = 30
AUTH_THRESHOLD      = 15

# ── REVA: C2 beaconing ──────────────────────────────────────────────────────
beacon_tracker      = defaultdict(list)  # (src,dst_ip,dst_port) -> [(ts, pkt_len), ...]
BEACON_MIN_PACKETS  = 8
BEACON_WINDOW       = 300
BEACON_MAX_JITTER   = 5.0
BEACON_SIZE_TOLERANCE = 64

# ── Alert category taxonomy (REVA grouping) ───────────────────────────────────
ALERT_CATEGORIES = {
    "Port Scan":            "Reconnaissance",
    "NULL Scan":            "Reconnaissance",
    "XMAS Scan":            "Reconnaissance",
    "Brute Force Attempt":  "Unauthorized Access",
    "DNS Tunneling":        "Malware Activity",
    "DGA DNS Activity":     "Malware Activity",
    "C2 Beacon":            "Malware Activity",
    "Suspicious Payload":   "Malware Activity",
    "SQL Injection":        "Web Exploitation",
    "XSS Attack":           "Web Exploitation",
    "Directory Traversal":  "Web Exploitation",
    "SYN Flood":            "Denial of Service",
    "Unknown Protocol":     "Protocol Anomaly",
}

# ── FEATURE 4 ─ Blocked IPs Registry (Sweeper Pattern) ─────────────────────
# Maps ip_address -> expiry_timestamp (float, epoch seconds)
# A single sweeper thread checks this dict every SWEEPER_INTERVAL seconds.
BLOCK_DURATION    = 600   # seconds an IP stays blocked (default: 10 minutes)
SWEEPER_INTERVAL  = 15    # how often the sweeper wakes up (seconds)
blocked_ips: dict = {}    # { ip_str: expiry_float }
blocked_ips_lock  = threading.Lock()


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 4 ─ Active IPS Mitigation Engine  (Sweeper Pattern)
# ══════════════════════════════════════════════════════════════════════════════
def _run_firewall_cmd(cmd: list, label: str) -> bool:
    """Execute a firewall command, log result. Returns True on success."""
    try:
        subprocess.run(cmd, timeout=5, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[IPS] {label}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[IPS][ERROR] Command failed ({label}): {e}")
    except subprocess.TimeoutExpired:
        print(f"[IPS][ERROR] Command timed out ({label})")
    except Exception as e:
        print(f"[IPS][ERROR] Unexpected error ({label}): {e}")
    return False


def mitigate_attacker(ip_address: str) -> None:
    """
    Block a HIGH-severity attacker at the OS firewall level and record its
    expiry time in the blocked_ips dict so the sweeper can lift the ban later.
    Runs in a daemon thread — never stalls the packet capture loop.
    """
    expiry = time.time() + BLOCK_DURATION

    with blocked_ips_lock:
        if ip_address in blocked_ips:
            # Already blocked — just refresh the expiry window
            blocked_ips[ip_address] = expiry
            print(f"[IPS] Expiry refreshed for {ip_address} "
                  f"(+{BLOCK_DURATION}s)")
            return
        blocked_ips[ip_address] = expiry   # register BEFORE issuing the rule

    current_os = platform.system()

    if current_os == "Linux":
        _run_firewall_cmd(
            ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
            f"iptables DROP rule added for {ip_address} "
            f"(expires in {BLOCK_DURATION}s)"
        )
    elif current_os == "Windows":
        rule_name = f"NetWatch_Block_{ip_address.replace('.', '_')}"
        _run_firewall_cmd(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={ip_address}"],
            f"Windows Firewall block rule added for {ip_address} "
            f"(expires in {BLOCK_DURATION}s)"
        )
    else:
        print(f"[IPS] Unsupported OS '{current_os}' — "
              f"manual block required for {ip_address}")


def unblock_ip(ip_address: str) -> None:
    """
    Remove the OS-level firewall rule for an IP whose ban has expired.
    Called exclusively by the sweeper thread.
    """
    current_os = platform.system()

    if current_os == "Linux":
        _run_firewall_cmd(
            ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
            f"iptables DROP rule removed for {ip_address} (ban expired)"
        )
    elif current_os == "Windows":
        rule_name = f"NetWatch_Block_{ip_address.replace('.', '_')}"
        _run_firewall_cmd(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={rule_name}"],
            f"Windows Firewall block rule removed for {ip_address} (ban expired)"
        )
    else:
        print(f"[IPS] Unsupported OS — manual unblock required for {ip_address}")


def sweeper_loop() -> None:
    """
    The single background sweeper worker.

    Wakes every SWEEPER_INTERVAL seconds. Iterates over the blocked_ips dict
    and evicts any IP whose expiry timestamp has passed:
      1. Removes the OS firewall rule via unblock_ip().
      2. Removes the entry from the blocked_ips dict.

    This approach uses exactly ONE thread regardless of how many IPs are
    blocked, keeping memory and thread overhead constant.
    """
    print(f"[SWEEPER] Started — checking every {SWEEPER_INTERVAL}s, "
          f"block duration {BLOCK_DURATION}s")
    while True:
        time.sleep(SWEEPER_INTERVAL)
        now = time.time()

        with blocked_ips_lock:
            # Snapshot expired IPs so we don't mutate the dict while iterating
            expired = [ip for ip, expiry in blocked_ips.items()
                       if now >= expiry]

        for ip in expired:
            unblock_ip(ip)             # OS firewall rule removal (outside lock)
            with blocked_ips_lock:
                blocked_ips.pop(ip, None)  # safe even if already removed

        if expired:
            print(f"[SWEEPER] Unblocked {len(expired)} IP(s): {expired}")


def _mitigate_in_background(ip_address: str) -> None:
    """Spawn a daemon thread for firewall mitigation so it never blocks the sniffer."""
    t = threading.Thread(target=mitigate_attacker, args=(ip_address,), daemon=True)
    t.start()


# ══════════════════════════════════════════════════════════════════════════════
#  Threat intelligence — AbuseIPDB + VirusTotal (async, cached)
# ══════════════════════════════════════════════════════════════════════════════
def _is_public_ip(ip_address: str) -> bool:
    """Skip RFC1918 / loopback — external APIs are not useful for LAN addresses."""
    try:
        addr = ipaddress.ip_address(ip_address.strip())
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def _http_get_json(url: str, headers: dict, timeout: int = 10):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:200]
        print(f"[THREAT_INTEL][HTTP {e.code}] {url} — {body}")
    except Exception as e:
        print(f"[THREAT_INTEL][ERROR] {url} — {e}")
    return None


def _lookup_abuseipdb(ip_address: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {}
    qs = urllib.parse.urlencode({"ipAddress": ip_address, "maxAgeInDays": 90})
    url = f"https://api.abuseipdb.com/api/v2/check?{qs}"
    data = _http_get_json(url, {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    })
    if not data or "data" not in data:
        return {}
    d = data["data"]
    return {
        "abuse_score":      d.get("abuseConfidenceScore", 0),
        "abuse_reports":    d.get("totalReports", 0),
        "country":          d.get("countryCode") or "",
        "isp":              d.get("isp") or "",
        "usage_type":       d.get("usageType") or "",
    }


def _lookup_virustotal(ip_address: str) -> dict:
    if not VIRUSTOTAL_API_KEY:
        return {}
    encoded = urllib.parse.quote(ip_address, safe="")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{encoded}"
    data = _http_get_json(url, {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
    })
    if not data or "data" not in data:
        return {}
    attrs = data["data"].get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "vt_malicious":   stats.get("malicious", 0),
        "vt_suspicious":  stats.get("suspicious", 0),
        "vt_harmless":    stats.get("harmless", 0),
        "vt_reputation":  attrs.get("reputation"),
        "vt_country":     attrs.get("country") or "",
    }


def enrich_ip_reputation(ip_address: str) -> dict:
    """
    Query AbuseIPDB and VirusTotal, merge results, cache, and return one record.
    Never call from the packet capture path — use _enrich_in_background instead.
    """
    now = time.time()
    with reputation_lock:
        cached = ip_reputation.get(ip_address)
        if cached and (now - cached.get("checked_at", 0)) < THREAT_INTEL_CACHE_TTL:
            return cached

    record = {
        "ip":         ip_address,
        "checked_at": now,
        "time":       time.strftime("%H:%M:%S"),
    }

    if not _is_public_ip(ip_address):
        record.update({
            "skipped": True,
            "note":    "Private/reserved IP — external reputation not applicable",
        })
        with reputation_lock:
            ip_reputation[ip_address] = record
        return record

    if not ABUSEIPDB_API_KEY and not VIRUSTOTAL_API_KEY:
        record["note"] = "No threat-intel API keys configured in .env"
        with reputation_lock:
            ip_reputation[ip_address] = record
        return record

    record.update(_lookup_abuseipdb(ip_address))
    record.update(_lookup_virustotal(ip_address))

    # Prefer AbuseIPDB country, fall back to VT.
    if not record.get("country") and record.get("vt_country"):
        record["country"] = record["vt_country"]

    with reputation_lock:
        ip_reputation[ip_address] = record
    return record


def _emit_threat_intel(record: dict) -> None:
    socketio.emit("threat_intel", record)
    _emit_intel()


def _enrich_in_background(ip_address: str) -> None:
    """Run reputation lookup in a daemon thread (post-alert enrichment)."""
    if not ip_address or ip_address == "N/A":
        return
    with _enriching_lock:
        if ip_address in _enriching_ips:
            return
        _enriching_ips.add(ip_address)

    def _worker() -> None:
        try:
            record = enrich_ip_reputation(ip_address)
            _emit_threat_intel(record)
        finally:
            with _enriching_lock:
                _enriching_ips.discard(ip_address)

    threading.Thread(target=_worker, daemon=True,
                     name=f"NetWatch-Intel-{ip_address}").start()


# ── Start the sweeper at module load time ─────────────────────────────────────
_sweeper_thread = threading.Thread(target=sweeper_loop, daemon=True,
                                   name="NetWatch-Sweeper")
_sweeper_thread.start()


# ══════════════════════════════════════════════════════════════════════════════
#  Helper ─ Emit & store an alert, trigger IPS for HIGH severity
# ══════════════════════════════════════════════════════════════════════════════
def _emit_alert(alert: dict) -> None:
    """
    Append the alert to the shared list, broadcast it via SocketIO,
    and trigger active mitigation when severity is HIGH.
    """
    if "category" not in alert:
        alert["category"] = ALERT_CATEGORIES.get(alert.get("type", ""), "Uncategorized")
    alerts.insert(0, alert)
    if len(alerts) > 50:
        alerts.pop()
    socketio.emit('alert', alert)

    # Threat intel: enrich source IP for HIGH / MEDIUM alerts (async, cached).
    src_ip = alert.get("src", "")
    if src_ip and src_ip != "N/A" and alert.get("severity") in ("HIGH", "MEDIUM"):
        _enrich_in_background(src_ip)

    # FEATURE 4 hook: auto-block HIGH-severity attackers
    if alert.get("severity") == "HIGH":
        if src_ip and src_ip != "N/A":
            _mitigate_in_background(src_ip)


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 3 ─ Stealth Scan Detection (TCP Flag Analysis)
# ══════════════════════════════════════════════════════════════════════════════
# TCP flag bit masks
FLAG_FIN = 0x01
FLAG_SYN = 0x02
FLAG_RST = 0x04
FLAG_PSH = 0x08
FLAG_ACK = 0x10
FLAG_URG = 0x20
XMAS_FLAGS = FLAG_FIN | FLAG_PSH | FLAG_URG  # 0x29

def check_stealth_scans(pkt, src: str, now: float) -> None:
    """
    Detect NULL and XMAS stealth scan techniques.
    NULL  → flags == 0x00  (no flags set)
    XMAS  → flags == 0x29  (FIN + PSH + URG set)
    """
    if not pkt.haslayer(TCP):
        return

    flags = int(pkt[TCP].flags)

    # ── NULL Scan ─────────────────────────────────────────────────────────────
    if flags == 0x00:
        cooldown_key = f"null_{src}"
        if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 10:
            ALERT_COOLDOWN[cooldown_key] = now
            _emit_alert({
                "time":     time.strftime("%H:%M:%S"),
                "type":     "NULL Scan",
                "severity": "HIGH",
                "src":      src,
                "detail":   "TCP packet with no flags set — stealth NULL scan detected"
            })

    # ── XMAS Scan ─────────────────────────────────────────────────────────────
    elif (flags & XMAS_FLAGS) == XMAS_FLAGS:
        cooldown_key = f"xmas_{src}"
        if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 10:
            ALERT_COOLDOWN[cooldown_key] = now
            _emit_alert({
                "time":     time.strftime("%H:%M:%S"),
                "type":     "XMAS Scan",
                "severity": "HIGH",
                "src":      src,
                "detail":   f"FIN+PSH+URG flags set (0x{flags:02X}) — XMAS scan detected"
            })


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 2 ─ Deep Packet Inspection (DPI) & Web Attack Signatures
# ══════════════════════════════════════════════════════════════════════════════
DPI_SIGNATURES = {
    "SQL Injection": [
        "UNION SELECT",
        "' OR '1'='1",
        "SELECT * FROM",
        "1=1--",
        "OR 1=1",
        "DROP TABLE",
    ],
    "XSS Attack": [
        "<script>",
        "javascript:",
        "onerror=",
        "onload=",
        "<img src=",
        "alert(",
    ],
    "Directory Traversal": [
        "../../",
        "/etc/passwd",
        "win.ini",
        "..\\..\\",
        "%2e%2e%2f",
        "%252e%252e",
    ],
}

def check_dpi(pkt, src: str, now: float) -> None:
    """
    Inspect the raw payload for known web attack signatures.
    Decodes bytes as UTF-8 (ignoring decode errors) and checks against
    the DPI_SIGNATURES dictionary.
    """
    if not pkt.haslayer(Raw):
        return

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore").upper()
    except Exception:
        return  # undecodable payload — skip silently

    for attack_type, patterns in DPI_SIGNATURES.items():
        for pattern in patterns:
            if pattern.upper() in payload:
                cooldown_key = f"dpi_{attack_type}_{src}"
                if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 20:
                    ALERT_COOLDOWN[cooldown_key] = now
                    _emit_alert({
                        "time":     time.strftime("%H:%M:%S"),
                        "type":     attack_type,
                        "severity": "HIGH",
                        "src":      src,
                        "detail":   f"Signature matched: '{pattern}' in payload"
                    })
                break  # one alert per attack_type per packet is enough


# ══════════════════════════════════════════════════════════════════════════════
#  REVA ─ Malware payload / LOLBin signatures (extends DPI pattern)
# ══════════════════════════════════════════════════════════════════════════════
MALWARE_PAYLOAD_SIGNATURES = {
    "Suspicious Payload": [
        "POWERSHELL", "CMD.EXE", "CERTUTIL", "MSHTA",
        "WSCRIPT", "CSCRIPT", "BITSADMIN",
        "PYTHON-REQUESTS", "CURL ", "WGET ",
        "/GATE.PHP", "/PANEL", "/BOT", "/UPLOAD",
        "MZ",
    ],
}


def check_malware_payloads(pkt, src: str, now: float) -> None:
    """Inspect cleartext payloads for malware / LOLBin transfer signatures."""
    if not pkt.haslayer(Raw):
        return

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore").upper()
    except Exception:
        return

    for attack_type, patterns in MALWARE_PAYLOAD_SIGNATURES.items():
        for pattern in patterns:
            if pattern.upper() in payload:
                cooldown_key = f"malware_{attack_type}_{src}"
                if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 30:
                    ALERT_COOLDOWN[cooldown_key] = now
                    _emit_alert({
                        "time":     time.strftime("%H:%M:%S"),
                        "type":     attack_type,
                        "severity": "HIGH",
                        "src":      src,
                        "detail":   f"Malware signature matched: '{pattern}' in payload",
                    })
                break


# ══════════════════════════════════════════════════════════════════════════════
#  REVA ─ Brute-force / unauthorized access (auth service ports)
# ══════════════════════════════════════════════════════════════════════════════
def check_brute_force(pkt, src: str, now: float) -> None:
    """Detect repeated connection attempts to authentication service ports."""
    if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        return

    dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
    if dst_port not in AUTH_PORTS:
        return

    auth_port_tracker[src].append((now, dst_port))
    auth_port_tracker[src] = [
        (ts, port) for ts, port in auth_port_tracker[src]
        if now - ts < AUTH_WINDOW
    ]

    if len(auth_port_tracker[src]) >= AUTH_THRESHOLD:
        cooldown_key = f"brute_{src}"
        if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 20:
            ALERT_COOLDOWN[cooldown_key] = now
            ports_hit = sorted({port for _, port in auth_port_tracker[src]})
            _emit_alert({
                "time":     time.strftime("%H:%M:%S"),
                "type":     "Brute Force Attempt",
                "severity": "MEDIUM",
                "src":      src,
                "detail":   (
                    f"{len(auth_port_tracker[src])} connections to auth ports "
                    f"({','.join(str(p) for p in ports_hit)}) in {AUTH_WINDOW}s"
                ),
            })
            auth_port_tracker[src] = []


# ══════════════════════════════════════════════════════════════════════════════
#  REVA ─ DNS anomaly detection (tunneling + DGA-style activity)
# ══════════════════════════════════════════════════════════════════════════════
def _decode_dns_qname(pkt) -> str | None:
    """Decode DNS query name from a packet, or None if unavailable."""
    if not pkt.haslayer(DNSQR):
        return None
    try:
        qname = pkt[DNSQR].qname
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="ignore")
        return qname.rstrip(".")
    except Exception:
        return None


def check_dns_anomalies(pkt, src: str, now: float) -> None:
    """Detect DNS tunneling (long labels) and DGA-style query bursts."""
    qname = _decode_dns_qname(pkt)
    if not qname:
        return

    # DNS Tunneling — unusually long query name
    if len(qname) >= DNS_TUNNEL_MIN_LEN:
        cooldown_key = f"dns_tunnel_{src}"
        if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 30:
            ALERT_COOLDOWN[cooldown_key] = now
            truncated = qname[:60] + "..." if len(qname) > 60 else qname
            _emit_alert({
                "time":     time.strftime("%H:%M:%S"),
                "type":     "DNS Tunneling",
                "severity": "MEDIUM",
                "src":      src,
                "detail":   f"Long DNS query ({len(qname)} chars): {truncated}",
            })

    # DGA / malware DNS — many unique domains from one source in a window
    dns_query_tracker[src].append((now, qname))
    dns_query_tracker[src] = [
        (ts, name) for ts, name in dns_query_tracker[src]
        if now - ts < DNS_WINDOW
    ]
    unique_domains = {name for _, name in dns_query_tracker[src]}
    if len(unique_domains) > DNS_DGA_THRESHOLD:
        cooldown_key = f"dns_dga_{src}"
        if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 60:
            ALERT_COOLDOWN[cooldown_key] = now
            _emit_alert({
                "time":     time.strftime("%H:%M:%S"),
                "type":     "DGA DNS Activity",
                "severity": "MEDIUM",
                "src":      src,
                "detail":   (
                    f"{len(unique_domains)} unique DNS queries in {DNS_WINDOW}s "
                    f"(threshold {DNS_DGA_THRESHOLD})"
                ),
            })
            dns_query_tracker[src] = []


# ══════════════════════════════════════════════════════════════════════════════
#  REVA ─ C2 beaconing (regular outbound traffic to public destinations)
# ══════════════════════════════════════════════════════════════════════════════
def check_c2_beacon(pkt, src: str, dst_ip: str, now: float) -> None:
    """Detect periodic, fixed-size outbound flows to public IPs (beaconing)."""
    if not _is_public_ip(dst_ip):
        return

    if pkt.haslayer(TCP):
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        dst_port = pkt[UDP].dport
    else:
        dst_port = 0

    key = (src, dst_ip, dst_port)
    pkt_len = len(pkt)
    beacon_tracker[key].append((now, pkt_len))
    beacon_tracker[key] = [
        (ts, plen) for ts, plen in beacon_tracker[key]
        if now - ts < BEACON_WINDOW
    ]

    entries = beacon_tracker[key]
    if len(entries) < BEACON_MIN_PACKETS:
        return

    timestamps = [ts for ts, _ in entries]
    sizes = [plen for _, plen in entries]
    intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    if len(intervals) < 2:
        return

    try:
        interval_stdev = statistics.stdev(intervals)
    except statistics.StatisticsError:
        return

    size_spread = max(sizes) - min(sizes)
    if interval_stdev <= BEACON_MAX_JITTER and size_spread <= BEACON_SIZE_TOLERANCE:
        cooldown_key = f"beacon_{src}_{dst_ip}"
        if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 120:
            ALERT_COOLDOWN[cooldown_key] = now
            avg_interval = sum(intervals) / len(intervals)
            _emit_alert({
                "time":     time.strftime("%H:%M:%S"),
                "type":     "C2 Beacon",
                "severity": "HIGH",
                "src":      src,
                "detail":   (
                    f"{len(entries)} periodic packets to {dst_ip}:{dst_port} "
                    f"(avg interval {avg_interval:.1f}s, stdev {interval_stdev:.1f}s)"
                ),
            })
            beacon_tracker[key] = []


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 1 ─ Sliding Window Port Scan Detection + Original SYN Flood
# ══════════════════════════════════════════════════════════════════════════════
def check_anomalies(pkt) -> None:
    now = time.time()
    if not pkt.haslayer(IP):
        return

    src    = pkt[IP].src
    dst_ip = pkt[IP].dst  # retained for potential future geo/reputation checks

    # ── SYN Flood Detection (unchanged logic) ────────────────────────────────
    if pkt.haslayer(TCP) and (int(pkt[TCP].flags) & FLAG_SYN):
        syn_tracker[src].append(now)
        syn_tracker[src] = [t for t in syn_tracker[src] if now - t < 5]
        if len(syn_tracker[src]) > SYN_FLOOD_THRESHOLD:
            cooldown_key = f"syn_{src}"
            if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 10:
                ALERT_COOLDOWN[cooldown_key] = now
                _emit_alert({
                    "time":     time.strftime("%H:%M:%S"),
                    "type":     "SYN Flood",
                    "severity": "HIGH",
                    "src":      src,
                    "detail":   f"{len(syn_tracker[src])} SYNs in 5s"
                })

    # ── FEATURE 1 ─ Sliding-Window Port Scan Detection ───────────────────────
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport

        # Record (timestamp, dst_port) entry for this source IP
        port_scan_tracker[src].append((now, dst_port))

        # Prune entries outside the 10-second window
        port_scan_tracker[src] = [
            (ts, port) for ts, port in port_scan_tracker[src]
            if now - ts < PORT_SCAN_WINDOW
        ]

        # Count UNIQUE destination ports within the active window
        unique_ports_in_window = {port for _, port in port_scan_tracker[src]}

        if len(unique_ports_in_window) > PORT_SCAN_THRESHOLD:
            cooldown_key = f"scan_{src}"
            if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 15:
                ALERT_COOLDOWN[cooldown_key] = now
                _emit_alert({
                    "time":     time.strftime("%H:%M:%S"),
                    "type":     "Port Scan",
                    "severity": "MEDIUM",
                    "src":      src,
                    "detail":   f"{len(unique_ports_in_window)} unique ports in {PORT_SCAN_WINDOW}s window"
                })
                # Reset tracker after firing to allow a clean next window
                port_scan_tracker[src] = []

    # ── Unknown Protocol ─────────────────────────────────────────────────────
    if not (pkt.haslayer(TCP) or pkt.haslayer(UDP) or pkt.haslayer(ICMP)):
        cooldown_key = f"proto_{src}"
        if now - ALERT_COOLDOWN.get(cooldown_key, 0) > 30:
            ALERT_COOLDOWN[cooldown_key] = now
            _emit_alert({
                "time":     time.strftime("%H:%M:%S"),
                "type":     "Unknown Protocol",
                "severity": "LOW",
                "src":      src,
                "detail":   f"Non-TCP/UDP/ICMP traffic from {src}"
            })

    # ── REVA: Brute force / unauthorized access ──────────────────────────────
    check_brute_force(pkt, src, now)

    # ── REVA: DNS anomalies ──────────────────────────────────────────────────
    check_dns_anomalies(pkt, src, now)

    # ── REVA: C2 beaconing (public destinations only) ────────────────────────
    check_c2_beacon(pkt, src, dst_ip, now)

    # ── FEATURE 3 ─ Stealth Scan Detection ───────────────────────────────────
    check_stealth_scans(pkt, src, now)

    # ── FEATURE 2 ─ Deep Packet Inspection ───────────────────────────────────
    check_dpi(pkt, src, now)

    # ── REVA: Malware payload signatures ─────────────────────────────────────
    check_malware_payloads(pkt, src, now)


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 2 ─ Passive Intelligence Helpers (DNS + TTL OS Fingerprint)
# ══════════════════════════════════════════════════════════════════════════════
def _guess_os_from_ttl(ttl: int) -> str:
    """
    Rough passive OS guess from the observed IP TTL.

    TTL decrements once per hop, so we round the observed value UP to the
    nearest common *initial* TTL to estimate the sender's stack:
      ≤64  → Linux / Unix / macOS   (initial TTL 64)
      ≤128 → Windows                (initial TTL 128)
      ≤255 → Network device / other (initial TTL 255)
    """
    if ttl <= 64:
        return "Linux / Unix"
    if ttl <= 128:
        return "Windows"
    return "Network device"


def extract_intel(pkt) -> None:
    """
    Collect passive intelligence from a packet:
      - TTL-based OS fingerprint for the source IP
      - DNS query names (DNSQR layer)
    Stored in shared structures guarded by intel_lock.
    """
    if not pkt.haslayer(IP):
        return

    src = pkt[IP].src
    ttl = int(pkt[IP].ttl)
    os_guess = _guess_os_from_ttl(ttl)

    dns_query = _decode_dns_qname(pkt)

    with intel_lock:
        os_fingerprints[src] = os_guess
        if dns_query:
            recent_dns.appendleft({
                "time":  time.strftime("%H:%M:%S"),
                "src":   src,
                "query": dns_query,
            })


def _emit_intel() -> None:
    """Broadcast fingerprints, DNS, and cached IP reputation."""
    with intel_lock:
        fingerprints = sorted(os_fingerprints.items())
        dns_list = list(recent_dns)
    with reputation_lock:
        reputations = list(ip_reputation.values())[-20:]
    socketio.emit('intel', {
        "fingerprints": fingerprints,
        "dns":          dns_list,
        "reputations":  reputations,
    })


# ── Packet Callback (Producer) ────────────────────────────────────────────────
def process_packet(pkt) -> None:
    """
    Producer: runs on the Scapy sniffer thread and does the bare minimum —
    drop the raw packet onto the queue. All heavy work happens in workers.
    """
    try:
        packet_queue.put_nowait(pkt)
    except queue.Full:
        with packet_lock:
            stats["dropped"] += 1


def _handle_packet(pkt) -> None:
    """Consumer body: parse one packet, update state, emit, run detection."""
    with packet_lock:
        captured_packets.append(pkt)
        stats["total"] += 1

        proto = "other"
        src_ip = dst_ip = src_port = dst_port = flags = "N/A"

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ip_counter[src_ip] += 1

        if pkt.haslayer(TCP):
            proto    = "tcp"
            stats["tcp"] += 1
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = str(pkt[TCP].flags)
            port_counter[dst_port] += 1
        elif pkt.haslayer(UDP):
            proto    = "udp"
            stats["udp"] += 1
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            port_counter[dst_port] += 1
        elif pkt.haslayer(ICMP):
            proto = "icmp"
            stats["icmp"] += 1
        else:
            stats["other"] += 1

        pkt_data = {
            "id":       stats["total"],
            "time":     time.strftime("%H:%M:%S"),
            "src":      src_ip,
            "dst":      dst_ip,
            "proto":    proto.upper(),
            "src_port": src_port,
            "dst_port": dst_port,
            "flags":    flags,
            "length":   len(pkt),
        }
        emit_stats = (stats["total"] % 10 == 0)
        total_now  = stats["total"]

    socketio.emit('packet', pkt_data)

    # Passive intelligence (DNS + OS fingerprint) outside the lock.
    extract_intel(pkt)

    # Run anomaly checks OUTSIDE the packet_lock to avoid blocking the lock
    # during potentially slow alert emission or firewall subprocess calls.
    check_anomalies(pkt)

    # Broadcast updated stats / intel periodically.
    if emit_stats:
        with packet_lock:
            top_ips   = sorted(ip_counter.items(),   key=lambda x: x[1], reverse=True)[:5]
            top_ports = sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:5]
            counts    = dict(stats)
        socketio.emit('stats', {
            "counts":    counts,
            "top_ips":   top_ips,
            "top_ports": top_ports,
        })
        _emit_intel()


def worker_loop() -> None:
    """
    Consumer worker: pull packets off the queue and process them until the
    capture session stops and the queue is drained.
    """
    while True:
        try:
            pkt = packet_queue.get(timeout=0.5)
        except queue.Empty:
            if not sniffing:
                return
            continue
        try:
            _handle_packet(pkt)
        except Exception as e:
            print(f"[WORKER][ERROR] {e}")
        finally:
            packet_queue.task_done()


def start_sniffing() -> None:
    global sniffing
    sniffing = True
    sniff(prn=process_packet, store=False, stop_filter=lambda _: not sniffing)


# ══════════════════════════════════════════════════════════════════════════════
#  FEATURE 5 ─ Forensic PDF Report + MITRE ATT&CK Mapping
# ══════════════════════════════════════════════════════════════════════════════
# Maps each detection type produced by the IDS to its MITRE ATT&CK technique.
MITRE_MAP = {
    "SYN Flood":           ("T1498",   "Network Denial of Service"),
    "Port Scan":           ("T1046",   "Network Service Discovery"),
    "NULL Scan":           ("T1046",   "Network Service Discovery"),
    "XMAS Scan":           ("T1046",   "Network Service Discovery"),
    "SQL Injection":       ("T1071",   "Application Layer Protocol"),
    "XSS Attack":          ("T1071",   "Application Layer Protocol"),
    "Directory Traversal": ("T1071",   "Application Layer Protocol"),
    "Unknown Protocol":    ("—",       "Informational (unmapped)"),
    "DNS Tunneling":       ("T1071.004", "Application Layer Protocol: DNS"),
    "DGA DNS Activity":    ("T1568",   "Dynamic Resolution"),
    "Brute Force Attempt": ("T1110",   "Brute Force"),
    "C2 Beacon":           ("T1071",   "Application Layer Protocol"),
    "Suspicious Payload":  ("T1105",   "Ingress Tool Transfer"),
}


def generate_report() -> str:
    """
    Build a forensic PDF summarising the current capture session and return
    its path. Groups detected anomalies by type and maps each to MITRE ATT&CK.
    """
    from fpdf import FPDF

    # Snapshot shared state under locks so the report is internally consistent.
    with packet_lock:
        counts = dict(stats)
        total_pkts = len(captured_packets)
        top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]
        top_ports = sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:5]
    alert_snapshot = list(alerts)
    with intel_lock:
        fingerprints = sorted(os_fingerprints.items())
    with reputation_lock:
        reputations = list(ip_reputation.values())

    # Group alerts by detection type and category.
    grouped = defaultdict(list)
    by_category = defaultdict(list)
    for a in alert_snapshot:
        grouped[a.get("type", "Unknown")].append(a)
        by_category[a.get("category", "Uncategorized")].append(a)

    duration = 0
    if capture_started_at:
        duration = int(time.time() - capture_started_at)

    def clean(text: str) -> str:
        # fpdf core fonts are latin-1 only; strip anything outside that range.
        return str(text).encode("latin-1", "replace").decode("latin-1")

    def pdf_heading(text: str, size: int = 13) -> None:
        pdf.set_font("Helvetica", "B", size)
        pdf.cell(0, 8, clean(text), new_x="LMARGIN", new_y="NEXT")

    def pdf_body(text: str, size: int = 10, line_h: float = 6) -> None:
        """Wrap body text at full page width (fixes clip after cell(0))."""
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "", size)
        pdf.multi_cell(pdf.epw, line_h, clean(text))

    def pdf_body_italic(text: str, line_h: float = 6) -> None:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "I", 10)
        pdf.multi_cell(pdf.epw, line_h, clean(text))

    pdf = FPDF()
    pdf.set_margins(left=18, top=18, right=18)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ── Title ──
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "NetWatch Forensic Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(110, 110, 110)
    pdf_body(
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}  |  "
        f"Host: {platform.system()} {platform.release()}",
        size=10,
    )
    pdf.set_text_color(0, 0, 0)
    pdf.ln(4)

    # ── Executive summary ──
    pdf_heading("Executive Summary")
    summary = [
        f"Capture duration: {duration} seconds",
        f"Total packets analysed: {counts.get('total', 0)} "
        f"(stored {total_pkts}, dropped {counts.get('dropped', 0)})",
        f"Protocol mix: TCP {counts.get('tcp', 0)} / UDP {counts.get('udp', 0)} / "
        f"ICMP {counts.get('icmp', 0)} / Other {counts.get('other', 0)}",
        f"Total anomaly alerts: {len(alert_snapshot)}",
        f"Distinct detection types: {len(grouped)}",
        f"Alert categories triggered: {len(by_category)}",
    ]
    for line in summary:
        pdf_body(f"- {line}")
    pdf.ln(2)

    # ── Detections by category (REVA grouping) ──
    if by_category:
        pdf_heading("Detections by Category")
        for cat, items in sorted(by_category.items(), key=lambda kv: -len(kv[1])):
            types_in_cat = sorted({a.get("type", "?") for a in items})
            pdf_body(
                f"- {cat}: {len(items)} alert(s) "
                f"({', '.join(types_in_cat)})",
                size=9,
                line_h=5,
            )
        pdf.ln(2)

    # ── Detections by type with MITRE mapping ──
    pdf_heading("Detections and MITRE ATT&CK Mapping")

    if not grouped:
        pdf_body_italic("No anomalies were detected during this session.")
    else:
        for atype, items in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
            tech_id, tech_name = MITRE_MAP.get(atype, ("-", "Unmapped"))
            sev = items[0].get("severity", "-")
            cat = items[0].get("category", ALERT_CATEGORIES.get(atype, "Uncategorized"))
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", 11)
            pdf.multi_cell(
                pdf.epw, 6,
                clean(f"{atype}  [{cat}]  [{sev}]  -  {tech_id} {tech_name}"),
            )
            pdf.set_text_color(90, 90, 90)
            pdf_body(f"Occurrences: {len(items)}", size=9, line_h=5)
            for ex in items[:3]:
                pdf_body(
                    f"  - {ex.get('time', '')}  src={ex.get('src', '')}  "
                    f"{ex.get('detail', '')}",
                    size=9,
                    line_h=5,
                )
            pdf.set_text_color(0, 0, 0)
            pdf.ln(1)

    pdf.ln(2)

    # ── Host fingerprints ──
    pdf_heading("Host OS Fingerprints (passive, TTL-based)")
    if fingerprints:
        for ip, os_guess in fingerprints[:25]:
            pdf_body(f"  {ip}  ->  {os_guess}", size=9, line_h=5)
    else:
        pdf_body_italic("No fingerprints collected.", line_h=5)

    pdf.ln(2)

    # ── Threat intelligence (cached API lookups) ──
    pdf_heading("IP Threat Intelligence (AbuseIPDB / VirusTotal)")
    if reputations:
        for rec in reputations[:15]:
            ip = rec.get("ip", "?")
            if rec.get("skipped"):
                pdf_body(f"  {ip}: {rec.get('note', 'skipped')}", size=9, line_h=5)
                continue
            abuse = rec.get("abuse_score", "n/a")
            vt_m = rec.get("vt_malicious", "n/a")
            country = rec.get("country") or "—"
            pdf_body(
                f"  {ip}  |  Abuse score: {abuse}%  |  VT malicious: {vt_m}  |  "
                f"Country: {country}",
                size=9, line_h=5,
            )
    else:
        pdf_body_italic(
            "No reputation lookups yet (triggered after HIGH/MEDIUM alerts on public IPs).",
            line_h=5,
        )

    pdf.ln(2)

    # ── Top talkers ──
    pdf_heading("Top Talkers")
    pdf_body("Top source IPs:", size=9, line_h=5)
    if top_ips:
        for ip, cnt in top_ips:
            pdf_body(f"  {ip}  ({cnt} packets)", size=9, line_h=5)
    else:
        pdf_body("  (none)", size=9, line_h=5)
    pdf.ln(1)
    pdf_body("Top destination ports:", size=9, line_h=5)
    if top_ports:
        for port, cnt in top_ports:
            pdf_body(f"  :{port}  ({cnt} packets)", size=9, line_h=5)
    else:
        pdf_body("  (none)", size=9, line_h=5)

    report_dir = os.path.dirname(os.path.abspath(__file__))
    filename = f"netwatch_report_{time.strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(report_dir, filename)
    pdf.output(path)
    return path


# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')


# ── Socket Events ─────────────────────────────────────────────────────────────
@socketio.on('start_sniff')
def handle_start():
    global sniffer_thread, sniffing, stats, captured_packets, worker_threads, capture_started_at
    if sniffing:
        return
    # Reset all state
    stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "dropped": 0}
    ip_counter.clear()
    port_counter.clear()
    alerts.clear()
    syn_tracker.clear()
    port_scan_tracker.clear()
    dns_query_tracker.clear()
    auth_port_tracker.clear()
    beacon_tracker.clear()
    captured_packets.clear()
    ALERT_COOLDOWN.clear()
    with intel_lock:
        os_fingerprints.clear()
        recent_dns.clear()
    with reputation_lock:
        ip_reputation.clear()
    with _enriching_lock:
        _enriching_ips.clear()
    # Drain any packets left in the queue from a previous session.
    while True:
        try:
            packet_queue.get_nowait()
            packet_queue.task_done()
        except queue.Empty:
            break
    # NOTE: blocked_ips dict intentionally NOT cleared on session restart.
    # The sweeper will continue to manage expiry of any active blocks
    # independently of the capture session lifecycle.

    capture_started_at = time.time()
    sniffing = True   # set before workers start so they don't exit immediately

    # Spawn the consumer worker pool.
    worker_threads = []
    for i in range(WORKER_COUNT):
        t = threading.Thread(target=worker_loop, daemon=True,
                             name=f"NetWatch-Worker-{i+1}")
        t.start()
        worker_threads.append(t)

    sniffer_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()
    socketio.emit('status', {'sniffing': True})


@socketio.on('stop_sniff')
def handle_stop():
    global sniffing
    sniffing = False
    socketio.emit('status', {'sniffing': False})


@socketio.on('export_pcap')
def handle_export():
    with packet_lock:
        if captured_packets:
            # Use a cross-platform temp path inside the project directory
            export_dir = os.path.dirname(os.path.abspath(__file__))
            path = os.path.join(export_dir, "capture.pcap")
            try:
                wrpcap(path, captured_packets)
                socketio.emit('export_ready', {'path': path, 'count': len(captured_packets)})
            except Exception as e:
                socketio.emit('export_ready', {'path': None, 'count': 0, 'error': str(e)})
        else:
            socketio.emit('export_ready', {'path': None, 'count': 0})


@socketio.on('generate_report')
def handle_generate_report():
    try:
        path = generate_report()
        socketio.emit('report_ready', {'path': path})
    except Exception as e:
        socketio.emit('report_ready', {'path': None, 'error': str(e)})


@socketio.on('get_state')
def handle_get_state():
    top_ips   = sorted(ip_counter.items(),   key=lambda x: x[1], reverse=True)[:5]
    top_ports = sorted(port_counter.items(), key=lambda x: x[1], reverse=True)[:5]
    socketio.emit('stats',  {"counts": stats, "top_ips": top_ips, "top_ports": top_ports})
    socketio.emit('status', {'sniffing': sniffing})
    _emit_intel()
    for a in alerts[:10]:
        socketio.emit('alert', a)


if __name__ == '__main__':
    print("=" * 60)
    print("  NetWatch IDS/IPS — Advanced Intrusion Detection System")
    print("  http://127.0.0.1:5000")
    print("  Run with sudo/admin privileges for live capture & IPS")
    print("=" * 60)
    print(f"  Host OS  : {platform.system()} {platform.release()}")
    print(f"  IPS Mode : Active (HIGH alerts trigger firewall blocks)")
    ti = []
    if ABUSEIPDB_API_KEY:
        ti.append("AbuseIPDB")
    if VIRUSTOTAL_API_KEY:
        ti.append("VirusTotal")
    print(f"  Threat Intel: {', '.join(ti) if ti else 'disabled (set keys in .env)'}")
    print("=" * 60)
    socketio.run(app, debug=False, host='0.0.0.0', port=5000,
                 allow_unsafe_werkzeug=True)
