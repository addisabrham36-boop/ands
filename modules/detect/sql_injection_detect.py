from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import re
import urllib.parse
from datetime import datetime


class SQLInjectionDetect(ModuleBase):
    """
    SQL Injection (SQLi) Web Application Threat Sentinel.
    Inspects HTTP GET query parameters and POST bodies for SQL injection patterns,
    tautologies (' OR 1=1--), UNION SELECT, stacked queries, and blind SQLi sleep delays.
    """

    SQLI_PATTERNS = [
        re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
        re.compile(r"\b(UNION\s+ALL\s+SELECT|UNION\s+SELECT)\b", re.IGNORECASE),
        re.compile(r"\b(OR|AND)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+", re.IGNORECASE),
        re.compile(r"\b(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)\b", re.IGNORECASE),
        re.compile(r"\b(DROP\s+TABLE|INSERT\s+INTO|SELECT\s+.*\s+FROM)\b", re.IGNORECASE),
        re.compile(r"\b(INFORMATION_SCHEMA|PG_SLEEP|LOAD_FILE)\b", re.IGNORECASE),
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
        for pat in self.SQLI_PATTERNS:
            match = pat.search(decoded_text)
            if match:
                matched_pattern = match.group(0)
                break

        if matched_pattern:
            key = (src, dst, matched_pattern[:20])
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] SQL Injection Detected: {src} -> {dst} (Pattern: {matched_pattern}) [{ts}]")

                self.session.add_alert({
                    "type": "SQL_INJECTION_ATTACK",
                    "severity": "CRITICAL",
                    "confidence": 0.97,
                    "mitre_id": "T1190",
                    "source": src,
                    "destination": dst,
                    "protocol": "HTTP",
                    "description": f"SQL Injection attack string observed in HTTP payload from {src} against {dst}: '{matched_pattern}'",
                    "details": {
                        "matched_signature": matched_pattern,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] SQL Injection Sentinel active on {iface} (HTTP traffic)...")

        try:
            sniff(iface=iface, filter="tcp port 80 or tcp port 8080 or tcp port 8899", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SQLi monitoring halted.")
            return

        print(f"[+] SQLi Sentinel complete — {len(self.already_alerted)} injection incident(s) flagged.")
