from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import re
from datetime import datetime


class HTTPAnomalyDetect(ModuleBase):
    """
    Passive HTTP Web Application Threat & Payload Inspection Sentinel.
    Analyzes cleartext HTTP requests for SQL Injection, Cross-Site Scripting (XSS),
    Path Traversal, Remote Code Execution (RCE) probes, and automated vulnerability scanners.
    """

    PATTERNS = [
        ("SQL_INJECTION", re.compile(r"(\bUNION\b.{1,20}\bSELECT\b|'\s*OR\s*['\d=]|--\s*$|\bSLEEP\(\d+\)|information_schema)", re.IGNORECASE), "CRITICAL", "T1190"),
        ("XSS_ATTACK", re.compile(r"(<script\b|javascript:|onerror\s*=|onload\s*=|alert\(|<svg/onload)", re.IGNORECASE), "HIGH", "T1059.007"),
        ("PATH_TRAVERSAL", re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/windows/win\.ini|\.env|\.git/config)", re.IGNORECASE), "HIGH", "T1083"),
        ("COMMAND_INJECTION", re.compile(r"(;\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh|powershell)\b|\|\|\s*(whoami|id))", re.IGNORECASE), "CRITICAL", "T1059.004"),
        ("SCANNER_PROBE", re.compile(r"(sqlmap|nikto|dirbuster|gobuster|wpscan|masscan|zgrab|nmap\s*nse)", re.IGNORECASE), "MEDIUM", "T1595.002"),
    ]

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "PORTS": {"value": "80,8080,8000,3000,5000,8888", "required": True, "desc": "HTTP ports to inspect"},
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

        raw_payload = pkt[Raw].load
        try:
            payload_text = raw_payload.decode("utf-8", errors="ignore")
        except Exception:
            return

        # Check if HTTP request
        if not any(payload_text.startswith(m) for m in ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
            return

        for attack_name, regex, severity, mitre_id in self.PATTERNS:
            match = regex.search(payload_text)
            if match:
                matched_snippet = match.group(0)[:50]
                key = (src, attack_name, dst)
                if key not in self.already_alerted:
                    self.already_alerted.add(key)
                    first_line = payload_text.splitlines()[0] if payload_text else ""
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"[ALERT] Web Attack [{attack_name}]: {src} -> {dst} (Pattern: '{matched_snippet}') [{ts}]")

                    self.session.add_alert({
                        "type": f"HTTP_{attack_name}",
                        "severity": severity,
                        "confidence": 0.94,
                        "mitre_id": mitre_id,
                        "source": src,
                        "destination": dst,
                        "protocol": "HTTP",
                        "description": f"HTTP Threat detected from {src} against {dst}: matched pattern for {attack_name} ('{matched_snippet}') in request '{first_line[:60]}'",
                        "details": {
                            "attack_type": attack_name,
                            "matched_signature": matched_snippet,
                            "http_request_line": first_line[:120],
                        }
                    })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])
        ports_str = self.options["PORTS"]["value"]
        port_list = [p.strip() for p in ports_str.split(",") if p.strip()]
        bpf = "tcp and (" + " or ".join(f"port {p}" for p in port_list) + ")"

        self.already_alerted.clear()
        print(f"[*] HTTP Web Threat Sentinel active on {iface} (ports: {ports_str})...")

        try:
            sniff(iface=iface, filter=bpf, prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Web threat monitoring halted.")
            return

        print(f"[+] HTTP Threat scan completed — {len(self.already_alerted)} web attack signature(s) detected.")
