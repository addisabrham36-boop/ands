from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP
import time
import collections
from datetime import datetime


class BruteForceDetect(ModuleBase):
    """
    Authentication Brute-Force & Credential Stuffing Sentinel.
    Monitors high-rate authentication attempts against SSH (22), FTP (21),
    Telnet (23), RDP (3389), VNC (5900), and HTTP/HTTPS admin endpoints.
    """

    AUTH_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        80: "HTTP_AUTH",
        443: "HTTPS_AUTH",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP_ADMIN",
    }

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "ATTEMPT_THRESHOLD": {"value": "10", "required": True, "desc": "Connection attempts per window to trigger brute-force alert"},
            "WINDOW": {"value": "15", "required": True, "desc": "Sliding window in seconds"},
        }
        # (src, dst, dport) -> list of timestamps
        self.attempts = collections.defaultdict(list)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        # Only count SYN packets (new connection attempts)
        if int(tcp.flags) != 0x02:
            return

        src = ip.src
        dst = ip.dst
        dport = tcp.dport

        if dport not in self.AUTH_SERVICES:
            return

        if self.session.is_whitelisted(src):
            return

        now = time.time()
        key = (src, dst, dport)
        self.attempts[key].append(now)

        window = float(self.options["WINDOW"]["value"])
        thresh = int(self.options["ATTEMPT_THRESHOLD"]["value"])

        # Retain only attempts in window
        self.attempts[key] = [t for t in self.attempts[key] if now - t <= window]
        count = len(self.attempts[key])

        if count >= thresh and key not in self.already_alerted:
            self.already_alerted.add(key)
            service_name = self.AUTH_SERVICES.get(dport, f"Port {dport}")
            confidence = min(0.99, 0.7 + (count / (thresh * 3)))
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[ALERT] Credential Brute-Force Detected: {src} -> {dst}:{dport} ({service_name}) [{count} attempts in {window}s] [{ts}]")

            self.session.add_alert({
                "type": "BRUTE_FORCE",
                "severity": "CRITICAL" if dport in (22, 3389) else "HIGH",
                "confidence": round(confidence, 2),
                "mitre_id": "T1110.001",
                "source": src,
                "destination": f"{dst}:{dport}",
                "protocol": service_name,
                "description": f"Credential Brute Force / Password Guessing attack detected from {src} against {service_name} on {dst}:{dport} ({count} connection attempts in {window}s)",
                "details": {
                    "target_service": service_name,
                    "target_port": dport,
                    "attempt_count": count,
                    "window_seconds": window,
                }
            })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.attempts.clear()
        self.already_alerted.clear()

        print(f"[*] Brute-Force Sentinel monitoring {iface} on auth ports (SSH/FTP/Telnet/RDP)...")
        bpf = "tcp and (port 21 or port 22 or port 23 or port 80 or port 443 or port 3389 or port 5900)"
        try:
            sniff(iface=iface, filter=bpf, prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Monitoring halted by user.")
            return

        print(f"[+] Brute-force scan complete — {len(self.already_alerted)} brute-force source(s) identified.")
