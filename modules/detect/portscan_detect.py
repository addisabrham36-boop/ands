from core.module_base import ModuleBase
from scapy.all import sniff, TCP
import time
from collections import defaultdict


class PortScanDetect(ModuleBase):
    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": "", "required": True, "desc": "Network interface to monitor (e.g. eth0)"},
            "DURATION": {"value": "20", "required": True, "desc": "Monitoring duration in seconds"},
            "SCAN_THRESHOLD": {"value": "10", "required": True, "desc": "Distinct ports from one source to trigger an alert"},
        }
        self.ports_by_source = defaultdict(set)

    def _on_packet(self, pkt):
        if pkt.haslayer(TCP):
            src = pkt[0][1].src if pkt.haslayer("IP") else None
            if src:
                self.ports_by_source[src].add(pkt[TCP].dport)

    def run(self):
        iface = self.options["INTERFACE"]["value"]
        duration = int(self.options["DURATION"]["value"])
        threshold = int(self.options["SCAN_THRESHOLD"]["value"])

        self.ports_by_source = defaultdict(set)
        print(f"[*] Watching {iface} for port scans ({duration}s, threshold={threshold} ports)...")

        sniff(iface=iface, filter="tcp", prn=self._on_packet, timeout=duration)

        alerts = 0
        for src, ports in self.ports_by_source.items():
            if len(ports) >= threshold:
                alerts += 1
                print(f"[ALERT] {src}  (Status: PORT_SCAN) [ports: {len(ports)}]")
                self.session.add_alert({
                    "type": "PORT_SCAN",
                    "source": src,
                    "port_count": len(ports),
                })

        print(f"\n[+] Scan complete — {alerts} alert(s) across {len(self.ports_by_source)} host(s)")