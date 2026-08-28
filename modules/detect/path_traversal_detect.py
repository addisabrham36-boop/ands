from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import re
import urllib.parse
from datetime import datetime


class PathTraversalDetect(ModuleBase):
    """
    Path Traversal & Arbitrary File Access Sentinel.
    Inspects HTTP requests for directory traversal sequences (../, ..\\, %2e%2e%2f,
    /etc/passwd, /etc/shadow, win.ini, boot.ini, and proc/self/environ).
    """

    TRAVERSAL_PATTERNS = [
        re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e\/|\.\.\%2f)", re.IGNORECASE),
        re.compile(r"/(etc/passwd|etc/shadow|etc/hosts|proc/self|proc/version)", re.IGNORECASE),
        re.compile(r"(win\.ini|boot\.ini|windows/system32)", re.IGNORECASE),
    ]

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
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
            decoded_text = urllib.parse.unquote(text)
        except Exception:
            return

        matched = None
        for pat in self.TRAVERSAL_PATTERNS:
            match = pat.search(decoded_text)
            if match:
                matched = match.group(0)
                break

        if matched:
            key = (src, dst, matched)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] Path Traversal Probe: {src} -> {dst} (Pattern: {matched}) [{ts}]")

                self.session.add_alert({
                    "type": "PATH_TRAVERSAL_EXPLOIT_PROBE",
                    "severity": "HIGH",
                    "confidence": 0.96,
                    "mitre_id": "T1083",
                    "source": src,
                    "destination": dst,
                    "protocol": "HTTP",
                    "description": f"Directory traversal / sensitive file access probe from {src} against {dst}: '{matched}'",
                    "details": {
                        "matched_string": matched,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Path Traversal Sentinel active on {iface}...")

        try:
            sniff(iface=iface, filter="tcp port 80 or tcp port 8080 or tcp port 8899", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Traversal monitoring stopped.")
            return

        print(f"[+] Path Traversal scan complete — {len(self.already_alerted)} incident(s) flagged.")
