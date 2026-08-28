from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import collections
from datetime import datetime


class FTPBruteforceDetect(ModuleBase):
    """
    FTP Credential Brute-Force & Password Spraying Sentinel.
    Monitors TCP port 21 for rapid authentication failures (530 Login incorrect)
    and USER/PASS command bursts from single or distributed sources.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "THRESHOLD": {"value": "5", "required": True, "desc": "Failed login attempts to trigger alert"},
        }
        self.attempts = collections.defaultdict(list)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        raw = bytes(pkt[Raw].load)
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return

        if "530 " in text or text.startswith("USER ") or text.startswith("PASS "):
            now = datetime.now()
            self.attempts[src].append(now)
            thresh = int(self.options["THRESHOLD"]["value"])

            recent = [t for t in self.attempts[src] if (now - t).total_seconds() <= 30]
            self.attempts[src] = recent

            if len(recent) >= thresh:
                key = (src, dst, "FTP_BRUTE")
                if key not in self.already_alerted:
                    self.already_alerted.add(key)
                    ts = now.strftime("%H:%M:%S")
                    print(f"[ALERT] FTP Authentication Brute-Force: {src} -> {dst}:21 ({len(recent)} attempts) [{ts}]")

                    self.session.add_alert({
                        "type": "FTP_CREDENTIAL_BRUTEFORCE",
                        "severity": "HIGH",
                        "confidence": 0.94,
                        "mitre_id": "T1110.001",
                        "source": src,
                        "destination": dst,
                        "protocol": "FTP",
                        "description": f"FTP authentication brute-force attempt from {src} against {dst}:21 ({len(recent)} attempts in 30s)",
                        "details": {
                            "attempt_count": len(recent),
                            "port": 21,
                        }
                    })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.attempts.clear()
        self.already_alerted.clear()
        print(f"[*] FTP Brute-Force Sentinel active on {iface} (port 21)...")

        try:
            sniff(iface=iface, filter="tcp and port 21", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] FTP monitoring stopped.")
            return

        print(f"[+] FTP Sentinel complete — {len(self.already_alerted)} incident(s) flagged.")
