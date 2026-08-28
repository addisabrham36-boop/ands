from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import re
from datetime import datetime


class HTTPMethodsAudit(ModuleBase):
    """
    Dangerous HTTP Methods & Web Server Configuration Auditor.
    Monitors HTTP requests for dangerous HTTP verbs (PUT, DELETE, TRACE,
    OPTIONS, CONNECT, TRACK) that may allow unauthorized uploads or XST attacks.
    """

    RISKY_METHODS = ["PUT ", "DELETE ", "TRACE ", "TRACK ", "CONNECT "]

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Audit duration in seconds"},
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
        except Exception:
            return

        matched_method = None
        for m in self.RISKY_METHODS:
            if text.startswith(m):
                matched_method = m.strip()
                break

        if matched_method:
            key = (src, dst, matched_method)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[AUDIT ALERT] Risky HTTP Verb Observed: {src} -> {dst} (Method: {matched_method}) [{ts}]")

                self.session.add_alert({
                    "type": "RISKY_HTTP_METHOD_USAGE",
                    "severity": "MEDIUM",
                    "confidence": 0.95,
                    "mitre_id": "T1190",
                    "source": src,
                    "destination": dst,
                    "protocol": "HTTP",
                    "description": f"Dangerous HTTP method '{matched_method}' used from {src} against {dst}. Restrict dangerous verbs in web server configuration.",
                    "details": {
                        "http_method": matched_method,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] HTTP Methods Security Auditor active on {iface}...")

        try:
            sniff(iface=iface, filter="tcp port 80 or tcp port 8080 or tcp port 8899", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] HTTP audit stopped.")
            return

        print(f"[+] HTTP Methods Audit complete — {len(self.already_alerted)} risky request(s) caught.")
