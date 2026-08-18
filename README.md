# ANDS — Anomaly-based Network Detection System

ANDS watches network traffic and flags suspicious activity two ways: statistically (unusual spikes in traffic volume, via z-score analysis) and by pattern (port scan detection). It's built as an interactive console, similar in style to Metasploit, so detection capabilities are organized as modules you load, configure, and run.

## Why

Most student network security projects wrap existing tools (nmap, Wireshark) around a simple script. ANDS instead builds original detection logic from packet-level data — a behavioral baseline of "normal" traffic, then statistical and pattern-based methods to catch deviations from it, including attacks it has never seen a signature for.

## Requirements

- Linux (uses raw sockets via scapy; not tested on macOS/Windows)
- Python 3.10+
- Root/sudo access (required for raw packet capture)

## Installation

```bash
git clone https://github.com/addisabrham36-boop/ands.git
cd ands
pipx install .
pipx ensurepath
sudo ln -s ~/.local/bin/ANDS-shell /usr/local/bin/ANDS-shell
```

Open a new terminal after this so your PATH updates.

## Usage

```bash
sudo ANDS-shell
```
ands > use detect/portscan
ands (detect/portscan) > set INTERFACE eth0
ands (detect/portscan) > set DURATION 30
ands (detect/portscan) > run


## Modules

| Module | What it does |
|---|---|
| `capture/baseline` | Captures live traffic, extracts packet-rate features into a baseline profile. Supports reading/writing `.pcap` files. |
| `detect/zscore` | Flags traffic windows that deviate statistically from the baseline. |
| `detect/portscan` | Flags source hosts that touch more than a threshold number of distinct ports — signature-style detection. |
| `generate/synthetic` | Sends simulated normal/portscan/flood traffic — used for testing and demos. |
| `report/generate` | Generates a PDF report from the session's alert history. |
| `system/selftest` | Runs built-in checks confirming detection logic behaves correctly against known values. |
| `custom/*` | Any `ModuleBase` subclass dropped into `modules/custom/` is auto-discovered via `reload`. |

## Commands

`use`, `set`, `setg`, `show options`, `show modules`, `run`, `back`, `uniq`, `search`, `reload`, `exit`. Plain read-only Linux commands (`ls`, `cat`, `pwd`, `grep`) also pass through directly.

## Testing

```bash
pytest tests/
```

Unit tests validate the z-score detection math against known synthetic spikes. `system/selftest` validates core logic live inside the console. Both port scan and z-score detection have been confirmed live against a Metasploitable2 VM in an isolated VirtualBox host-only network.

## Out of scope

ANDS does not block, prevent, or actively respond to detected threats — detection only. Not designed for distributed/multi-host monitoring. Detection methods are statistical and pattern-based, not machine-learning-driven. Tested only in a controlled lab environment (Metasploitable2, host-only VirtualBox network), not production networks.

## Author

Built as an admission project for the INSA Bahir Dar University Cybersecurity program.

**Abrham Addis Tefera**
GitHub: [@addisabrham36-boop](https://github.com/addisabrham36-boop)
Bahir Dar, Ethiopia — 2026