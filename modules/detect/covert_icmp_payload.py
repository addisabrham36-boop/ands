from core.module_base import ModuleBase
from scapy.all import sniff, IP, ICMP, Raw
import collections
import math
from datetime import datetime


class CovertICMPPayload(ModuleBase):
    """
    Covert ICMP Data Exfiltration & Payload Tunnel Sentinel.
    Analyzes ICMP Echo Request/Reply data payloads for high-entropy data,
    non-standard byte patterns, and payload sizes larger than default OS pings.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "SIZE_LIMIT": {"value": "64", "required": True, "desc": "Max allowable normal ping payload size in bytes"},
        }
        self.already_alerted = set()

    def _entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = collections.Counter(data)
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP) and pkt.haslayer(Raw)):
            return

        ip = pkt[IP]
        icmp = pkt[ICMP]

        if icmp.type not in (8, 0):  # Echo Request / Reply
            return

        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        load = bytes(pkt[Raw].load)
        size_limit = int(self.options["SIZE_LIMIT"]["value"])

        if len(load) > size_limit:
            ent = self._entropy(load)
            if ent > 3.2 or len(load) > 128:
                key = (src, dst, "ICMP_COVERT")
                if key not in self.already_alerted:
                    self.already_alerted.add(key)
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"[ALERT] Covert ICMP Tunnel / Data Exfiltration: {src} -> {dst} (Size: {len(load)}B, Entropy: {ent:.2f}) [{ts}]")

                    self.session.add_alert({
                        "type": "ICMP_COVERT_EXFILTRATION",
                        "severity": "HIGH",
                        "confidence": 0.93,
                        "mitre_id": "T1095",
                        "source": src,
                        "destination": dst,
                        "protocol": "ICMP",
                        "description": f"Covert data tunneling observed in ICMP echo payload ({len(load)} bytes, Entropy: {ent:.2f}) between {src} and {dst}",
                        "details": {
                            "payload_size": len(load),
                            "entropy": round(ent, 2),
                        }
                    })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Covert ICMP Tunnel Sentinel active on {iface}...")

        try:
            sniff(iface=iface, filter="icmp", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] ICMP monitoring stopped.")
            return

        print(f"[+] ICMP Sentinel complete — {len(self.already_alerted)} anomaly event(s) logged.")
