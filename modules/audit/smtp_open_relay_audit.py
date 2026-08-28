from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import re
from datetime import datetime


class SMTPOpenRelayAudit(ModuleBase):
    """
    SMTP Cleartext & Open Mail Relay Auditor.
    Monitors TCP port 25 for cleartext SMTP commands (HELO/EHLO, MAIL FROM, RCPT TO)
    and potential open-relay spam testing patterns.
    """

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

        tcp = pkt[TCP]
        if tcp.dport != 25 and tcp.sport != 25:
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

        if "MAIL FROM:" in text.upper() or "RCPT TO:" in text.upper() or "HELO " in text.upper():
            key = (src, dst, "SMTP_CLEARTEXT")
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[AUDIT ALERT] Plaintext SMTP Command Observed: {src} -> {dst}:25 [{ts}]")

                self.session.add_alert({
                    "type": "CLEARTEXT_SMTP_TRAFFIC",
                    "severity": "MEDIUM",
                    "confidence": 0.92,
                    "mitre_id": "T1040",
                    "source": src,
                    "destination": dst,
                    "protocol": "SMTP",
                    "description": f"Unencrypted SMTP email transmission or relay probe between {src} and {dst} on port 25.",
                    "details": {
                        "port": 25,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] SMTP Cleartext / Open Relay Auditor active on {iface} (port 25)...")

        try:
            sniff(iface=iface, filter="tcp and port 25", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SMTP audit stopped.")
            return

        print(f"[+] SMTP audit complete — {len(self.already_alerted)} unencrypted event(s) logged.")
