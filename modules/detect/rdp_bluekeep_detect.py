from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime


class RDPBlueKeepDetect(ModuleBase):
    """
    RDP Reconnaissance & BlueKeep (CVE-2019-0708) Exploit Sentinel.
    Inspects TCP port 3389 for unauthorized RDP connection scans and
    MS_T120 static channel negotiation indicators associated with BlueKeep.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.dport != 3389 and tcp.sport != 3389:
            return

        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        raw = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        alert_type = None
        desc = ""
        sev = "HIGH"

        # Check BlueKeep MS_T120 channel exploit probe
        if b"MS_T120" in raw or b"\x03\x00\x00\x13\x0e\xe0\x00\x00" in raw:
            alert_type = "RDP_BLUEKEEP_EXPLOIT_PROBE"
            desc = "Potential CVE-2019-0708 (BlueKeep) MS_T120 channel probe detected"
            sev = "CRITICAL"
        elif tcp.dport == 3389 and tcp.flags == 0x02:  # SYN
            alert_type = "RDP_SCAN_RECONNAISSANCE"
            desc = "RDP service reconnaissance / port probe targeting TCP 3389"
            sev = "MEDIUM"

        if alert_type:
            key = (src, dst, alert_type)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] RDP Threat [{alert_type}]: {src} -> {dst} [{ts}]")

                self.session.add_alert({
                    "type": alert_type,
                    "severity": sev,
                    "confidence": 0.94 if sev == "CRITICAL" else 0.85,
                    "mitre_id": "T1210" if sev == "CRITICAL" else "T1046",
                    "source": src,
                    "destination": dst,
                    "protocol": "RDP",
                    "description": f"RDP Security Event detected: {desc} from {src} against {dst}",
                    "details": {
                        "port": 3389,
                        "threat_pattern": alert_type,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] RDP & BlueKeep Sentinel active on {iface} (port 3389)...")

        try:
            sniff(iface=iface, filter="tcp and port 3389", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] RDP monitoring stopped.")
            return

        print(f"[+] RDP Sentinel finished — {len(self.already_alerted)} event(s) caught.")
