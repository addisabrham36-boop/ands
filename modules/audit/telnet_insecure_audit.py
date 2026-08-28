from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime


class TelnetInsecureAudit(ModuleBase):
    """
    Insecure Telnet Protocol & Cleartext Shell Auditor.
    Identifies unencrypted legacy Telnet sessions (TCP port 23) transmitting
    plaintext administrative commands, credentials, and banner information.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Audit duration in seconds"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        tcp = pkt[TCP]
        if tcp.dport != 23 and tcp.sport != 23:
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        key = (src, dst, "TELNET")
        if key not in self.already_alerted:
            self.already_alerted.add(key)
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[AUDIT ALERT] Insecure Telnet Traffic Detected: {src} -> {dst}:23 [{ts}]")

            self.session.add_alert({
                "type": "INSECURE_TELNET_TRAFFIC",
                "severity": "HIGH",
                "confidence": 0.99,
                "mitre_id": "T1040",
                "source": src,
                "destination": dst,
                "protocol": "TELNET",
                "description": f"Unencrypted Telnet protocol session observed between {src} and {dst}. Migrate to SSH immediately for compliance.",
                "details": {
                    "port": 23,
                    "compliance_violation": "PCI-DSS 2.3 / CIS Control 4.1",
                }
            })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Insecure Telnet Protocol Auditor active on {iface} (port 23)...")

        try:
            sniff(iface=iface, filter="tcp and port 23", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Telnet audit halted.")
            return

        print(f"[+] Telnet audit finished — {len(self.already_alerted)} unencrypted session(s) caught.")
