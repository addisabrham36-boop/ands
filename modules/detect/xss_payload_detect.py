from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import re
import urllib.parse
from datetime import datetime


class XSSPayloadDetect(ModuleBase):
    """
    Cross-Site Scripting (XSS) Web Threat Sentinel.
    Inspects HTTP requests for reflective and stored XSS vectors (<script>,
    javascript:, onerror=, onload=, <iframe>, and SVG script vectors).
    """

    XSS_PATTERNS = [
        re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript\s*:\s*[^\s]+", re.IGNORECASE),
        re.compile(r"on(error|load|click|mouseover|focus)\s*=", re.IGNORECASE),
        re.compile(r"<\s*iframe[^>]*>", re.IGNORECASE),
        re.compile(r"<\s*svg[^>]*onload\s*=", re.IGNORECASE),
        re.compile(r"document\.(cookie|location|write)", re.IGNORECASE),
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

        matched_pattern = None
        for pat in self.XSS_PATTERNS:
            match = pat.search(decoded_text)
            if match:
                matched_pattern = match.group(0)
                break

        if matched_pattern:
            key = (src, dst, matched_pattern[:20])
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] XSS Payload Detected: {src} -> {dst} (Vector: {matched_pattern}) [{ts}]")

                self.session.add_alert({
                    "type": "CROSS_SITE_SCRIPTING_XSS",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "mitre_id": "T1059.007",
                    "source": src,
                    "destination": dst,
                    "protocol": "HTTP",
                    "description": f"Cross-Site Scripting (XSS) payload observed in HTTP stream: '{matched_pattern}'",
                    "details": {
                        "vector": matched_pattern,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] XSS Threat Sentinel active on {iface} (HTTP traffic)...")

        try:
            sniff(iface=iface, filter="tcp port 80 or tcp port 8080 or tcp port 8899", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] XSS monitoring halted.")
            return

        print(f"[+] XSS Sentinel complete — {len(self.already_alerted)} violation(s) logged.")
