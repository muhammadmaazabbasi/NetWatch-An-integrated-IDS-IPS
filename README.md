# NetWatch — Packet Sniffer & Anomaly Detector

**REVA Semester Project | Air University**

NetWatch is a lightweight **Intrusion Detection and Prevention System (IDS/IPS)** that captures live network traffic with **Scapy**, detects suspicious patterns with rule-based heuristics, and displays results on a real-time web dashboard. Captured traffic can be exported as PCAP for analysis in **Wireshark**, and session summaries can be saved as forensic PDF reports mapped to **MITRE ATT&CK**.

---

## Features

### Packet capture & dashboard
- Live packet sniffing on the default network interface (Scapy)
- Real-time web dashboard (Flask + Socket.IO)
- Live packet table (source/dest IP, ports, protocol, flags, length)
- Protocol breakdown (TCP / UDP / ICMP / Other) with charts
- Top source IPs and destination ports
- Packet rate graph over time
- PCAP export for Wireshark

### Anomaly detection (IDS)

Alerts are grouped into **REVA categories** (Reconnaissance, Unauthorized Access, Malware Activity, Web Exploitation, Denial of Service, Protocol Anomaly) and shown on the dashboard with category badges.

| Detection | Threshold | Severity | Category | MITRE ATT&CK |
|-----------|-----------|----------|----------|--------------|
| SYN Flood | >20 SYNs from one IP in 5s | HIGH | Denial of Service | T1498 |
| Port Scan | >15 unique dst ports in 10s | MEDIUM | Reconnaissance | T1046 |
| NULL Scan | TCP flags = 0 | HIGH | Reconnaissance | T1046 |
| XMAS Scan | FIN + PSH + URG set | HIGH | Reconnaissance | T1046 |
| Brute Force Attempt | ≥15 connections to auth ports in 30s | MEDIUM | Unauthorized Access | T1110 |
| DNS Tunneling | Query name ≥80 characters | MEDIUM | Malware Activity | T1071.004 |
| DGA DNS Activity | >50 unique queries from one src in 60s | MEDIUM | Malware Activity | T1568 |
| C2 Beacon | ≥8 periodic packets to public IP in 5 min | HIGH | Malware Activity | T1071 |
| Suspicious Payload | LOLBin / malware signature in cleartext | HIGH | Malware Activity | T1105 |
| SQL Injection (DPI) | Payload signature match | HIGH | Web Exploitation | T1071 |
| XSS Attack (DPI) | Payload signature match | HIGH | Web Exploitation | T1071 |
| Directory Traversal (DPI) | Payload signature match | HIGH | Web Exploitation | T1071 |
| Unknown Protocol | Non-TCP/UDP/ICMP traffic | LOW | Protocol Anomaly | — |

**Auth ports monitored for brute force:** FTP (21), SSH (22), Telnet (23), RDP (3389), SMB (445), WinRM (5985/5986).

**REVA demo notes:**
- Brute force detects repeated connection attempts to auth ports (not decrypted login failures).
- DNS rules detect behavioral abuse (long labels, query bursts), not domain blocklists.
- C2 beaconing requires regular outbound traffic to a **public** destination; lab demos should use external test IPs carefully (HIGH severity triggers IPS auto-block).
- Payload signatures work on cleartext traffic only (HTTP, FTP, etc.), not HTTPS.

### Intrusion prevention (IPS)
- **HIGH** severity alerts automatically block the source IP at the OS firewall
- Windows: `netsh advfirewall` inbound block rule
- Linux: `iptables` INPUT DROP rule
- Blocks expire after **10 minutes**; a background sweeper removes expired rules

### Passive intelligence
- **DNS query extraction** from DNSQR layer (recent queries panel)
- **TTL-based OS fingerprinting** (Linux/Unix, Windows, network device)

### Threat intelligence (optional)
- After **HIGH** or **MEDIUM** alerts on **public** IPs, async lookups via:
  - **AbuseIPDB** — abuse confidence score, country, ISP
  - **VirusTotal** — malicious engine count
- Results cached for 10 minutes; private LAN IPs are skipped

### Reporting
- **Export PCAP** — `capture.pcap` in the project folder (open in Wireshark)
- **Report** button — session forensic PDF (`netwatch_report_<timestamp>.pdf`) with MITRE mapping
- **Semester documentation** — run `python generate_project_report.py` → `NetWatch_Project_Report.pdf`

### Architecture
- **Producer–consumer queue**: sniffer thread only enqueues packets; worker threads parse, detect, and emit (reduces packet loss under load)
- Bounded queue (10,000 packets) with dropped-packet counter

---

## Requirements

- Python 3.10+
- Administrator (Windows) or root/sudo (Linux) for live capture and IPS firewall rules
- [Wireshark](https://www.wireshark.org/) (optional, for PCAP analysis)

---

## Setup

### 1. Clone / open the project and create a virtual environment (recommended)

```powershell
cd packet_sniffer
python -m venv .venv
.\.venv\Scripts\Activate.ps1    # Windows
# source .venv/bin/activate     # Linux/macOS
pip install -r requirements.txt
```

### 2. Configure environment (optional)

```powershell
copy .env.example .env
```

Edit `.env` (no spaces after `=`):

```env
SECRET_KEY=your_random_secret_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

Threat-intel keys are **optional**. Without them, capture and detection work normally; IP reputation lookups are skipped.

**Never commit `.env`** — it may contain secrets.

### 3. Run the application

**Windows** (run terminal as Administrator):

```powershell
python app.py
```

**Linux/macOS**:

```bash
sudo python app.py
```

On startup you should see:

```
http://127.0.0.1:5000
Threat Intel: AbuseIPDB, VirusTotal   # if keys are configured
```

### 4. Open the dashboard

```
http://127.0.0.1:5000
```

---

## How to Use

1. Open the dashboard in your browser (hard refresh if you restarted the server: `Ctrl+Shift+R`).
2. Click **Start** to begin capture.
3. Watch the **Live Packet Feed** and intelligence rail (stats, charts, alerts).
4. Anomaly alerts appear automatically when rules trigger.
5. After HIGH/MEDIUM alerts on public IPs, check **IP Threat Intel** for reputation data.
6. Click **Stop** to end capture.
7. Click **Export** to save `capture.pcap` → open in Wireshark for deep inspection.
8. Click **Report** to generate a forensic PDF for the current session.

### Wireshark workflow

NetWatch does **not** embed Wireshark. Use this workflow:

1. Capture live traffic in NetWatch.
2. Export PCAP.
3. Open `capture.pcap` in Wireshark.
4. Apply display filters to verify alerts (e.g. `tcp.flags.syn==1`, or many destination ports from one source IP).

Use Wireshark first on normal traffic to understand baselines; program thresholds in Scapy accordingly.

---

## Verification

NetWatch includes scripts to verify REVA detections without guessing from live traffic alone.

### 1. Offline verification (fastest — no capture needed)

From the `packet_sniffer` folder with the virtual environment active:

```powershell
python scripts\verify_reva_detections.py
```

Expected output: `Result: all checks PASSED` for brute force, DNS tunneling, DGA DNS, suspicious payload, C2 beacon, categories, and MITRE map.

Optional — also generate a sample forensic PDF:

```powershell
python scripts\verify_reva_detections.py --pdf
```

This does **not** require Administrator privileges or a running `app.py` instance.

### 2. Live dashboard verification

**Terminal 1** (Run as Administrator):

```powershell
python app.py
```

Open http://127.0.0.1:5000 → click **Start**.

**Terminal 2** (Administrator recommended for Scapy send):

```powershell
python scripts\demo_reva_traffic.py --help
python scripts\demo_reva_traffic.py dns-tunnel
python scripts\demo_reva_traffic.py brute --target 192.168.100.1 --port 22
```

| Demo command | Expected alert | Category |
|--------------|----------------|----------|
| `dns-tunnel` | DNS Tunneling | Malware Activity |
| `brute --target <ip> --port 22` | Brute Force Attempt | Unauthorized Access |
| `payload` | Suspicious Payload | Malware Activity (HIGH) |
| `beacon --target 8.8.8.8` | C2 Beacon | Malware Activity (HIGH) |

Use `--dry-run` on any demo to preview without sending packets:

```powershell
python scripts\demo_reva_traffic.py brute --target 192.168.100.1 --dry-run
```

On the dashboard, confirm **category badges** appear on alert cards and the **category filter** dropdown works.

### 3. Forensic and semester reports

| Report | How to generate |
|--------|-----------------|
| Session forensic PDF | Start capture → trigger alerts → click **Report** → `netwatch_report_<timestamp>.pdf` |
| Semester documentation | `python generate_project_report.py` → `NetWatch_Project_Report.pdf` |

### Verification checklist

- [ ] `verify_reva_detections.py` prints all checks PASSED
- [ ] At least one live alert appears with a category badge
- [ ] Category filter shows only matching alerts
- [ ] Forensic PDF includes **Detections by Category** section
- [ ] PCAP export opens in Wireshark and matches alert source IPs

### Tips and known behavior

- Run **only one** `python app.py` process. Kill stale instances: `Stop-Process -Name python -Force`
- **IPS** (`[IPS][ERROR]` in console) means HIGH alerts fired but firewall rules failed — usually because the terminal was not Administrator.
- **C2 Beacon** and **Suspicious Payload** are HIGH severity and may trigger IPS auto-block. Avoid `beacon`/`payload` demos on your main PC unless you understand the risk; prefer `dns-tunnel` or `brute` for viva demos.
- On a busy PC with open browser tabs, normal CDN/Google traffic may false-positive as C2 Beacon. Minimize background traffic during live demos.
- Forensic PDFs show `Host: Windows 10` on Windows 11 because Python's `platform.release()` reports `10` for compatibility; the actual OS build is in `platform.version()`.

---

## Project Structure

```
packet_sniffer/
├── app.py                      # Backend: Scapy capture, IDS/IPS, Socket.IO API
├── templates/
│   └── index.html              # Real-time dashboard (Tailwind, Chart.js, Lucide)
├── scripts/
│   ├── verify_reva_detections.py  # Offline detection tests (no capture)
│   └── demo_reva_traffic.py       # Live demo traffic for dashboard
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variable template
├── .env                        # Local secrets (not committed)
├── generate_project_report.py  # Generates NetWatch_Project_Report.pdf
├── README.md
├── capture.pcap                # Created on PCAP export
└── netwatch_report_*.pdf       # Created on Report button
```

---

## Socket.IO Events

| Client → Server | Server → Client | Description |
|-----------------|-----------------|-------------|
| `start_sniff` | `status` | Begin capture |
| `stop_sniff` | `status` | Stop capture |
| `export_pcap` | `export_ready` | Write `capture.pcap` |
| `generate_report` | `report_ready` | Write forensic PDF |
| `get_state` | `stats`, `status`, `alert`, `intel` | Restore UI on reconnect |

Live events during capture: `packet`, `stats`, `alert`, `intel`, `threat_intel`.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| scapy | Packet capture and parsing |
| flask | Web server |
| flask-socketio | Real-time WebSocket updates |
| fpdf2 | Forensic PDF generation |
| python-dotenv | Load `.env` configuration |

Frontend (CDN): Tailwind CSS, Chart.js, Socket.IO client, Lucide icons.

---

## Limitations

- Captures on the **default network interface** only (no interface picker in UI).
- **Heuristic detection** — may produce false positives; not a commercial IDS.
- **DPI** cannot inspect encrypted HTTPS payloads.
- **IPS** blocks inbound traffic to **this host** only; does not protect other machines on the LAN.
- **Threat intel** APIs work best for **public** IPs; LAN addresses are skipped.
- Run **only one** instance of `app.py` at a time (multiple processes cause stale behavior on port 5000).

To stop all Python servers before restarting:

```powershell
Stop-Process -Name python -Force
```

---

## Ethical & Legal Notice

Only capture and analyse traffic on networks you **own** or have **explicit permission** to monitor. Unauthorized packet sniffing may violate law or policy.

---

## Tools Used

- **Scapy** — Live capture, layer dissection, anomaly logic
- **Flask + Flask-SocketIO** — Backend and real-time dashboard
- **Wireshark** — Offline PCAP verification and baseline analysis
- **AbuseIPDB / VirusTotal** — Optional IP reputation enrichment
- **MITRE ATT&CK** — Technique mapping in forensic reports

---

## License & Attribution

Semester project for REVA / Air University. For academic use and demonstration.
