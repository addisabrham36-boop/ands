from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, UDP
import time
import collections
from datetime import datetime
from core.statistics import classify_severity


class PortScanDetect(ModuleBase):
    """
    Advanced Multi-Vector Port Scan & Host Sweep Detection Engine.
    Detects SYN scans, FIN/NULL/XMAS stealth scans, and UDP sweeps with
    stateful TCP handshake validation to eliminate false positives.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor (e.g. eth0, enp1s0)"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "SCAN_THRESHOLD": {"value": "8", "required": True, "desc": "Distinct destination ports from one source to trigger alert"},
            "TIME_WINDOW": {"value": "15", "required": True, "desc": "Sliding time window in seconds for rate tracking"},
        }
        # source_ip -> list of (timestamp, dport, dst_ip, scan_type)
        self.probes = collections.defaultdict(list)
        self.already_alerted = set()
        self.established_flows = set()

    def _classify_tcp_flags(self, flags) -> str:
        # flags int / Flag object
        f_val = int(flags)
        if f_val == 0x02:
            return "SYN_SCAN"
        elif f_val == 0x00:
            return "NULL_SCAN"
        elif f_val == 0x01:
            return "FIN_SCAN"
        elif f_val == 0x29 or (f_val & 0x29 == 0x29):
            return "XMAS_SCAN"
        elif f_val & 0x10 and f_val & 0x02:
            return "SYN_ACK"
        elif f_val & 0x10:
            return "ACK"
        return "OTHER"

    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return
            
        src = pkt[IP].src
        dst = pkt[IP].dst
        
        # False-positive reduction: ignore whitelisted IPs
        if self.session.is_whitelisted(src):
            return

        now = time.time()
        window = float(self.options["TIME_WINDOW"]["value"])
        threshold = int(self.options["SCAN_THRESHOLD"]["value"])

        scan_type = None
        dport = None

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            dport = tcp.dport
            sport = tcp.sport
            flag_type = self._classify_tcp_flags(tcp.flags)

            # Check established 3-way handshake to ignore normal browsing / downloads
            if flag_type == "SYN_ACK":
                self.established_flows.add((dst, sport, src, dport))
                return
            elif flag_type == "ACK":
                if (src, sport, dst, dport) in self.established_flows:
                    return  # Normal established traffic, ignore

            if flag_type in ("SYN_SCAN", "NULL_SCAN", "FIN_SCAN", "XMAS_SCAN"):
                scan_type = flag_type

        elif pkt.haslayer(UDP):
            dport = pkt[UDP].dport
            # Filter common noisy UDP broadcast services (mDNS, SSDP, DHCP, NTP)
            if dport not in (53, 67, 68, 123, 1900, 5353):
                scan_type = "UDP_SWEEP"

        if scan_type and dport is not None:
            # Add probe and trim outside time window
            self.probes[src].append((now, dport, dst, scan_type))
            self.probes[src] = [p for p in self.probes[src] if now - p[0] <= window]

            unique_ports = {p[1] for p in self.probes[src]}
            unique_targets = {p[2] for p in self.probes[src]}
            
            # Check vertical scan (one target, many ports) or horizontal sweep (many targets)
            is_vertical = len(unique_ports) >= threshold
            is_horizontal = len(unique_targets) >= (threshold // 2) and len(unique_ports) >= 1

            if (is_vertical or is_horizontal) and src not in self.already_alerted:
                self.already_alerted.add(src)
                confidence = min(0.98, 0.6 + (len(unique_ports) / (threshold * 2)))
                detected_pattern = "HORIZONTAL_SWEEP" if is_horizontal and not is_vertical else scan_type
                severity = "HIGH" if (scan_type in ("NULL_SCAN", "XMAS_SCAN") or len(unique_ports) > 20) else "MEDIUM"
                
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] {src:<16} -> {dst:<16} [{detected_pattern}] Ports: {len(unique_ports)} ({ts})")
                
                self.session.add_alert({
                    "type": "PORT_SCAN",
                    "severity": severity,
                    "confidence": round(confidence, 2),
                    "mitre_id": "T1046",
                    "source": src,
                    "destination": dst,
                    "protocol": "TCP" if pkt.haslayer(TCP) else "UDP",
                    "description": f"Network reconnaissance probe detected from {src}: {len(unique_ports)} distinct ports touched in {window}s ({detected_pattern})",
                    "details": {
                        "scan_type": detected_pattern,
                        "distinct_ports_count": len(unique_ports),
                        "ports_sample": sorted(list(unique_ports))[:20],
                        "distinct_targets": len(unique_targets),
                        "window_seconds": window,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])
        threshold = int(self.options["SCAN_THRESHOLD"]["value"])

        self.probes.clear()
        self.already_alerted.clear()
        self.established_flows.clear()

        print(f"[*] PortScan Sentinel monitoring {iface} (threshold: {threshold} ports)...")
        timeout_arg = duration if duration > 0 else None

        try:
            sniff(iface=iface, filter="tcp or udp", prn=self._on_packet, timeout=timeout_arg, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo to capture packets.")
            return
        except OSError as e:
            print(f"[-] Interface error: {e}. Check the interface name.")
            return
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user.")
            return

        print(f"[+] Scan completed — {len(self.already_alerted)} scan alert(s), {len(self.probes)} unique probe sources.")