from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime


class SMBAnomalyDetect(ModuleBase):
    """
    SMB Protocol & Lateral Movement Exploit Sentinel.
    Monitors TCP port 445 for deprecated SMBv1 dialect negotiations,
    EternalBlue (MS17-010) exploit signatures, and suspicious IPC$ pipe connections.
    """

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
        tcp = pkt[TCP]

        if tcp.dport != 445 and tcp.sport != 445:
            return

        if self.session.is_whitelisted(src):
            return

        raw = bytes(pkt[Raw].load)
        alert_type = None
        desc = ""
        sev = "HIGH"
        mitre = "T1210"

        # SMB Header magic: \xffSMB
        if b"\xffSMB" in raw:
            # Check for SMBv1 (header starts with \xffSMB)
            alert_type = "SMBV1_DIALECT_USAGE"
            desc = "Insecure, legacy SMBv1 protocol negotiation observed (vulnerable to EternalBlue / WannaCry)"
            sev = "HIGH"

            # Check for EternalBlue NT Trans / Tree Connect exploit signatures
            if b"\x00\x00\x00\x00\xa0" in raw or b"IPC$" in raw:
                alert_type = "SMB_ETERNALBLUE_EXPLOIT_PROBE"
                desc = "Potential MS17-010 (EternalBlue) exploit probe or anomalous IPC$ pipe invocation"
                sev = "CRITICAL"

        if alert_type:
            key = (src, dst, alert_type)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] SMB Threat [{alert_type}]: {src} -> {dst} [{ts}]")

                self.session.add_alert({
                    "type": alert_type,
                    "severity": sev,
                    "confidence": 0.96,
                    "mitre_id": mitre,
                    "source": src,
                    "destination": dst,
                    "protocol": "SMB",
                    "description": f"SMB Security Anomaly detected from {src} against {dst}: {desc}",
                    "details": {
                        "destination_port": tcp.dport,
                        "threat_pattern": alert_type,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] SMB Lateral Movement Sentinel active on {iface} (port 445)...")

        try:
            sniff(iface=iface, filter="tcp and port 445", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SMB sentinel stopped.")
            return

        print(f"[+] SMB scan complete — {len(self.already_alerted)} violation(s) flagged.")
