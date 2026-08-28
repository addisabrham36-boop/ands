from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import re
from datetime import datetime


class WebShellProbeDetect(ModuleBase):
    """
    Web Shell & Backdoor Scanner Sentinel.
    Monitors HTTP requests for known web shell filenames and backdoors
    (c99.php, r57.php, b374k.php, alftem.php, cmd.jsp, shell.aspx, etc.).
    """

    SHELL_NAMES = [
        re.compile(r"/(c99|r57|b374k|wso|alfa|cmd|shell|backdoor|weevely)\.(php|phtml|jsp|asp|aspx)", re.IGNORECASE),
        re.compile(r"/(eval-stdin|phpinfo|uploader|uploadify)\.php", re.IGNORECASE),
        re.compile(r"/(web_shell|sh|webshell)\.(php|jsp|cgi)", re.IGNORECASE),
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
        except Exception:
            return

        matched = None
        for pat in self.SHELL_NAMES:
            match = pat.search(text)
            if match:
                matched = match.group(0)
                break

        if matched:
            key = (src, dst, matched)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] Web Shell Probe: {src} -> {dst} (Target: {matched}) [{ts}]")

                self.session.add_alert({
                    "type": "WEBSHELL_PROBE_SCAN",
                    "severity": "CRITICAL",
                    "confidence": 0.98,
                    "mitre_id": "T1505.003",
                    "source": src,
                    "destination": dst,
                    "protocol": "HTTP",
                    "description": f"Known web shell backdoor probe from {src} targeting {dst}: '{matched}'",
                    "details": {
                        "target_uri": matched,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Web Shell Probe Sentinel active on {iface}...")

        try:
            sniff(iface=iface, filter="tcp port 80 or tcp port 8080 or tcp port 8899", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Web shell monitoring stopped.")
            return

        print(f"[+] Web Shell Sentinel complete — {len(self.already_alerted)} probe(s) flagged.")
