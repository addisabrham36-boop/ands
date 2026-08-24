# ANDS — Live SOC Analyst & Network Anomaly Detection System (v2.0)

ANDS (**Anomaly-based Network Detection System**) is a real-time cybersecurity defense, intrusion detection, and auditing platform for Linux. Designed with both a Metasploit-style interactive console and a sleek Monochrome Cyber SOC Analyst Web & Desktop Dashboard, ANDS pairs statistical baseline anomaly detection (standard Z-score, robust Median Absolute Deviation - MAD, and adaptive Exponential Moving Averages - EMA) with signature and behavioral detection across 40+ specialized modules and simulation payloads.

---

## Key Features

- **Live Continuous Packet Sentinel**: Background packet sniffer and stream dispatcher with zero packet duplication.
- **False-Positive Reduction Engine**: 
  - Robust **Median Absolute Deviation (MAD)** and Modified Z-Scores ($M_i = 0.6745 \cdot (x - \text{med}) / \text{MAD}$) to withstand benign burst noise.
  - Stateful **TCP 3-Way Handshake Tracking**: distinguishes legitimate high-throughput connections from port scans and SYN floods.
  - Whitelist suppression and confidence rating (0–100%).
- **Monochrome Minimalist Cyber Web Dashboard & Arch Linux Desktop App**:
  - High-contrast black and white styling, real-time PPS & bandwidth charts, live anomaly meters, protocol radar, interactive alert inspection, and 1-Click active firewall IP bans.
  - Native Arch Linux `.desktop` launcher and standalone app window support.
- **Suite of 40+ Defense, Audit, Capture, Simulation, & Response Modules**:
  - Port scans, SYN floods, ARP spoofing, DNS tunneling, C2 beaconing, credential brute-force, web threats (SQLi/XSS), NTP amplification, SSDP reflection, DNS amplification, SMB exploit probes, SNMP guessing, IP fragmentation / Teardrop, cleartext credential sniffing, and more.

---

## Requirements

- **OS**: Linux (Optimized for Arch Linux, Ubuntu, Debian, Fedora)
- **Python**: 3.10+
- **Privileges**: Root/sudo access (required for raw packet sniffing and `iptables` active response)
- **Dependencies**: `scapy`, `numpy`, `colorama`, `reportlab`, `psutil`

---

## Installation

```bash
git clone https://github.com/addisabrham36-boop/ands.git
cd ands
pip install -e .
```

### Launch the Arch Linux Desktop Application:
```bash
./bin/ands-app
```
*(Also available directly in your GNOME/KDE/XFCE Application Menu as **ANDS SOC Sentinel**)*

---

## Usage

### 1. Launching the Interactive Shell Console:
```bash
sudo python ands.py
# or
sudo ANDS-shell
```

```text
ands ❯ live start enp1s0
[✓] Live Detection Engine started on interface: enp1s0

ands ❯ show modules
ands ❯ use detect/portscan
ands (detect/portscan) ❯ show options
ands (detect/portscan) ❯ set DURATION 30
ands (detect/portscan) ❯ run
```

### 2. Launching the Web SOC Dashboard:
```bash
sudo python ands.py dashboard 8899
```
Then navigate to `http://localhost:8899` in your browser.

---

## Module Catalog (40+ Modules & Payloads)

| Category | Module | Description | MITRE ATT&CK |
|---|---|---|---|
| **Detect** | `detect/portscan` | Multi-mode scan detection (SYN, FIN, NULL, XMAS, UDP, sweeps) with handshake validation | T1046 |
| **Detect** | `detect/zscore` | Live sliding-window Z-Score & MAD statistical volumetric anomaly detection | T1498 |
| **Detect** | `detect/synflood` | Half-open TCP connection tracker and SYN/ACK ratio flood detector | T1498.001 |
| **Detect** | `detect/arpspoof` | Real-time ARP poisoning, duplicate IP claims, and gateway MAC drift detector | T1557.002 |
| **Detect** | `detect/dns_tunnel` | Shannon entropy & high-frequency TXT/NULL record DNS tunneling detector | T1071.004 |
| **Detect** | `detect/beaconing` | Periodic C2 heartbeat & timing jitter coefficient-of-variation analyzer | T1071 |
| **Detect** | `detect/bruteforce` | Rapid authentication attempt detector for SSH, FTP, Telnet, RDP, and HTTP | T1110.001 |
| **Detect** | `detect/icmp_tunnel` | Oversized payload entropy & Ping of Death / ICMP flood detector | T1095 / T1498 |
| **Detect** | `detect/http_anomaly`| Web threat inspection (SQL Injection, XSS, Path Traversal, Web Shells) | T1190 / T1059 |
| **Detect** | `detect/slowloris` | Low-and-slow HTTP connection starvation and socket exhaustion detector | T1499.003 |
| **Detect** | `detect/land_smurf` | Malformed Land Attack (src == dst) & Smurf broadcast amplification detector | T1498.001 |
| **Detect** | `detect/dhcp_rogue` | Rogue / unauthorized DHCP server Offer/ACK spoofer detector | T1557 |
| **Detect** | `detect/threat_intel`| Threat intelligence IOC blacklist & malicious IP feed matcher | T1071 |
| **Detect** | `detect/ntp_amplification`| NTP monlist (0x2a) and reflection DDoS flood detector | T1498.002 |
| **Detect** | `detect/ssdp_amplification`| SSDP M-SEARCH UPnP reflection DDoS probe detector | T1498.002 |
| **Detect** | `detect/dns_amplification`| DNS ANY query and EDNS0 oversized response reflection detector | T1498.002 |
| **Detect** | `detect/smb_anomaly`| SMBv1 dialect negotiation & EternalBlue (MS17-010) exploit probe detector | T1210 |
| **Detect** | `detect/snmp_bruteforce`| SNMP community string guessing & enumeration detector | T1110.001 |
| **Detect** | `detect/ip_fragmentation`| Teardrop overlapping IP offset and fragment flood detector | T1498.001 |
| **Detect** | `detect/packet_fuzzing`| Malformed packet headers, illegal TCP flags, and zero TTL fuzzer detector | T1499 |
| **Audit** | `audit/cleartext_creds`| Passive packet sniffer for plaintext credentials (HTTP Basic, FTP, Telnet, POP3, IMAP) | T1552 |
| **Audit** | `audit/network_inventory`| Passive subnet asset discovery, MAC vendor lookup, and OS fingerprinting | T1046 |
| **Audit** | `audit/ssl_tls` | Cryptographic auditor detecting deprecated SSLv2, SSLv3, TLS 1.0, and TLS 1.1 | T1557 |
| **Audit** | `audit/dns_resolver` | Outbound DNS policy auditor identifying unauthorized shadow DNS resolvers | T1071.004 |
| **Capture** | `capture/traffic_baseline`| Multi-feature vector baseline profiler (packet rate, byte rate, protocol distribution) | — |
| **Capture** | `capture/live_stream` | Continuous rolling PCAP ring-buffer capture for incident forensics | — |
| **Capture** | `capture/flow_analyzer`| NetFlow / IPFIX-style 5-tuple flow aggregator & Top Talkers analyzer | — |
| **Generate** | `generate/synthetic` | Multi-profile traffic generator (Normal, Port Scan, SYN Flood, UDP, ICMP Spike) | — |
| **Generate** | `generate/dns_payload`| Generates high-entropy simulated DNS tunneling queries for lab validation | — |
| **Generate** | `generate/arp_payload`| Generates simulated gratuitous ARP packets for testing ARP defenses | — |
| **Generate** | `generate/c2_beacon_payload`| Generates periodic beacon heartbeats with configurable timing jitter | — |
| **Generate** | `generate/ntp_monlist_payload`| Generates safe NTP monlist queries for reflection rule validation | — |
| **Generate** | `generate/http_bench_payload`| High-throughput HTTP GET benchmark burst simulator | — |
| **Generate** | `generate/ssdp_probe_payload`| SSDP M-SEARCH discovery query probe simulator | — |
| **Generate** | `generate/snmp_test_payload`| Generates SNMP community test queries for sentinel validation | — |
| **Generate** | `generate/fragmented_payload`| Emits overlapping fragmented IP packets for Teardrop defense testing | — |
| **Response** | `response/iptables_block`| Active response firewall manager: 1-click ban/unban malicious IPs via iptables | — |
| **Response** | `response/pcap_extractor`| Extracts targeted forensic PCAP slices around incident timestamps for Wireshark | — |
| **Report** | `report/generate_report`| Generates executive HTML & PDF incident reports with MITRE ATT&CK breakdown | — |
| **Report** | `report/json_export` | Exports session alerts to SIEM-ready JSONL, JSON, and CEF formats | — |
| **System** | `system/selftest` | Automated mathematical and algorithmic self-test suite | — |
| **System** | `system/interface_info`| Network adapter diagnostics, MTU, duplex, and throughput inspector | — |
| **Custom** | `custom/*` | Auto-discovers any custom `ModuleBase` subclass placed in `modules/custom/` | — |

---

## Author & Credits

**Abrham Addis Tefera**  
Bahir Dar University / INSA Cybersecurity Program  
GitHub: [@addisabrham36-boop](https://github.com/addisabrham36-boop)  
Bahir Dar, Ethiopia — 2026