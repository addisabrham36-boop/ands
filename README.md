# 🛡️ ANDS SENTINEL v2.0
### **Anomaly-based Network Detection System & Real-Time SOC Analyst Suite**

[![License: MIT](https://img.shields.io/badge/License-MIT-white.svg?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-black.svg?style=for-the-badge&logo=python&logoColor=white)](pyproject.toml)
[![Docker](https://img.shields.io/badge/Docker-Ready-0db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](docker-compose.yml)
[![Linux Platform](https://img.shields.io/badge/Platform-Arch%20%7C%20Debian%20%7C%20Kali%20%7C%20Fedora-black.svg?style=for-the-badge&logo=linux&logoColor=white)](install.sh)
[![Modules](https://img.shields.io/badge/Modules-75%2B%20Loaded-success.svg?style=for-the-badge)](modules/)

---

## ⚡ Overview

**ANDS (Anomaly-based Network Detection System)** is a modular, high-performance network security telemetry and threat-hunting framework built for **SOC Analysts, Network Auditors, and Incident Responders**.

It combines a real-time statistical anomaly detection engine (using **Median Absolute Deviation** and **Modified Z-Scores** to eliminate false positives) with a **Monochrome Black & White SOC Dashboard**, a dedicated **Arch Linux Desktop App**, and an extensible suite of **75+ defensive detection, auditing, capture, simulation, and active-response modules**.

---

## 🌟 Key Features

- 🛰️ **Live Wire Packet Sentinel**: Continuous raw socket sniffing with Scapy, sliding-window throughput metering, and instantaneous threat classification.
- 📉 **Adaptive False-Positive Elimination**: Robust outlier detection utilizing Median Absolute Deviation (MAD) rather than fragile mean/stdev averages.
- 🎛️ **75+ Primary Modules & Payloads**: Dedicated detection sentinels, compliance auditors, packet profilers, safe lab test simulators, and automated response mitigators.
- 🖥️ **Monochromatic Cyber SOC Dashboard**: High-contrast, dark-graphite web interface with live streaming PPS line charts, protocol distribution doughnuts, dynamic alert feeds, and interactive module runners.
- 🪟 **Arch Linux Desktop Application**: Standalone GUI desktop window integrating terminal control and telemetry streams.
- 🚀 **1-Click 3-in-1 Unified Launcher**: Run `sudo ANDS-shell all` to launch the background engine, web server, desktop app, and interactive CLI simultaneously.
- 🐳 **Docker & Container Ready**: Run everywhere with Docker and Docker Compose using host network packet capture.
- 🔒 **Active Response & Containment**: Real-time Netfilter/iptables blocking and Layer-2 MAC address isolation.

---

## 🚀 Quick Start & Installation

### Option 1: Universal 1-Click Installer (Recommended for Linux / Arch)

Clone the repository and run the automated installer:

```bash
git clone https://github.com/addisabrham36-boop/ands.git
cd ands
sudo ./install.sh
```

This will automatically:
1. Install all necessary system dependencies (`libpcap`, `tcpdump`, `iptables`, `gcc`).
2. Provision an isolated virtual environment with all required Python packages.
3. Link the global `ANDS-shell` binary into `/usr/local/bin`.
4. Install the desktop launcher shortcut in your application menu.

---

### Option 2: Docker & Docker Compose

Deploy the complete ANDS SOC Sentinel in seconds without installing local Python packages:

```bash
git clone https://github.com/addisabrham36-boop/ands.git
cd ands
docker compose up -d
```

> **Note**: Docker runs in `network_mode: "host"` with `NET_ADMIN` and `NET_RAW` capabilities to enable direct raw socket sniffing on host network interfaces.

Access the SOC Dashboard at **`http://localhost:8899`**.

To run custom commands inside Docker:
```bash
docker run --rm -it --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW ands-sentinel live
```

---

### Option 3: Manual Installation

```bash
git clone https://github.com/addisabrham36-boop/ands.git
cd ands
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

---

## 💻 Usage & Commands

### 1. Launch All (3-in-1 Unified Suite)
Spawns the background Live Sentinel Engine, spins up the Web SOC Dashboard on port `8899`, opens the Desktop App window, and drops into the interactive console:
```bash
sudo ANDS-shell all
```

### 2. Interactive Console
Launch the interactive Metasploit-style shell:
```bash
sudo ANDS-shell
```
Inside the shell:
```text
ands ❯ modules                      # View all 75 modules & descriptions
ands ❯ use detect/portscan          # Select a module
ands (detect/portscan) ❯ show options
ands (detect/portscan) ❯ set DURATION 15
ands (detect/portscan) ❯ run         # Execute active module
ands (detect/portscan) ❯ live view   # Open full-screen dynamic monitoring HUD
```

### 3. Dedicated Terminal Live Monitoring HUD
Inspect throughput, baseline PPS, protocol distribution bars, and live threats updating every second:
```bash
sudo ANDS-shell live
```

### 4. Headless SOC Web Server
Run the web dashboard as a standalone service (default port 8899, with auto port-fallback avoiding 5000, 8000, 8080):
```bash
sudo ANDS-shell dashboard 8899
```

---

## 📦 Complete 75-Module Catalog

| Category | Modules | Description |
|---|---|---|
| **DETECT** (32) | `arpspoof`, `beaconing`, `bruteforce`, `covert_icmp`, `dhcp_rogue`, `dns_amplification`, `dns_dga`, `dns_tunnel`, `dns_zone_transfer`, `ftp_bruteforce`, `icmp_tunnel`, `ip_fragmentation`, `ipv6_ra_flood`, `land_smurf`, `ldap_anonymous`, `llmnr_nbtns_poison`, `memcached_amplification`, `ntp_amplification`, `packet_fuzzing`, `path_traversal`, `portscan`, `rdp_bluekeep`, `sip_invite_flood`, `slowloris`, `snmp_bruteforce`, `sql_injection`, `ssdp_amplification`, `ssh_bruteforce`, `synflood`, `threat_intel`, `webshell_probe`, `zscore` | Real-time threat detection sentinels covering Layer 2 through Layer 7 attacks, volumetric DDoS, C2 beacons, and malware queries. |
| **AUDIT** (10) | `cleartext_creds`, `dns_resolver`, `http_methods`, `mac_spoofing`, `network_inventory`, `rogue_dns`, `smtp_open_relay`, `ssl_tls`, `telnet_insecure`, `weak_cipher` | Passive compliance auditors identifying unencrypted protocols, dangerous HTTP methods, weak cipher suites, and asset inventories. |
| **CAPTURE** (6) | `bandwidth_meter`, `baseline`, `flow_analyzer`, `live_stream`, `protocol_profiler`, `traffic_baseline` | 5-tuple NetFlow analyzers, bandwidth meters, continuous packet streams, and L3/L4 protocol distribution profilers. |
| **GENERATE** (17)| `arp`, `c2_beacon`, `dga_test`, `dns`, `fragmented`, `http_bench`, `icmp_flood`, `memcached_test`, `ntp_monlist`, `path_traversal`, `slowloris`, `snmp_test`, `sql_injection`, `ssdp_probe`, `synthetic`, `telnet_test`, `xss_test` | Benign lab test payload generators for validating SOC detection rules and training security auditors. |
| **RESPONSE** (3) | `iptables_block`, `mac_blacklist`, `pcap_extractor` | Active response Linux Netfilter / iptables blocking, Layer-2 MAC isolation, and incident PCAP evidence extraction. |
| **REPORT** (4) | `compliance_report`, `generate_report`, `json_export`, `report` | CIS Benchmark / PCI-DSS compliance audits, PDF/HTML executive incident reports, and SIEM JSON threat feeds. |
| **SYSTEM** (3) | `interface_info`, `selftest`, `example_check` | Network adapter diagnostics, mathematical anomaly engine verification, and custom module template. |

---

## 🏗️ Architecture

```text
┌────────────────────────────────────────────────────────────────────────┐
│                          ANDS SENTINEL v2.0                            │
└────────────────────────────────────────────────────────────────────────┘
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
┌──────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│  LIVE SENTINEL   │       │  MONOCHROME SOC  │       │ 75+ CYBER MODULE │
│  SNIFFING ENGINE │       │  DASHBOARD & APP │       │  STUDIO SUITE    │
└──────────────────┘       └──────────────────┘       └──────────────────┘
  • Scapy Raw Socket         • Pure JS & SSE Stream     • 32 Detectors
  • 1s Sliding Window        • Monochromatic Charts     • 10 Auditors
  • MAD & Mod-Z Score        • 1-Click Test Buttons     • 17 Simulators
  • BPF Packet Filter        • REST API Backend         • Active Mitigation
```

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

Developed with 🛡️ by **Addis Abrham** for cybersecurity auditors, SOC analysts, and network defense practitioners.