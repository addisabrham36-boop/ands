from core.module_base import ModuleBase
from scapy.all import sniff, TCP
from datetime import datetime
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
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if pkt.haslayer(TCP):
            src = pkt[0][1].src if pkt.haslayer("IP") else None
            if not src:
                return
            self.ports_by_source[src].add(pkt[TCP].dport)
            threshold = int(self.options["SCAN_THRESHOLD"]["value"])
            if len(self.ports_by_source[src]) >= threshold and src not in self.already_alerted:
                self.already_alerted.add(src)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] {src:<16} (Status: PORT_SCAN) [ports: {len(self.ports_by_source[src])}] [{ts}]")
                self.session.add_alert({
                    "type": "PORT_SCAN",
                    "source": src,
                    "port_count": len(self.ports_by_source[src]),
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"]
        duration = int(self.options["DURATION"]["value"])
        threshold = int(self.options["SCAN_THRESHOLD"]["value"])

        self.ports_by_source = defaultdict(set)
        self.already_alerted = set()

        print(f"[*] Watching {iface} for {duration}s (threshold: {threshold} ports)")

        try:
            sniff(iface=iface, filter="tcp", prn=self._on_packet, timeout=duration)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo to capture packets.")
            return
        except OSError as e:
            print(f"[-] Interface error: {e}. Check the interface name with 'ip a'.")
            return
        except KeyboardInterrupt:
            print("\n[*] Monitoring interrupted by user.")
            return

        print(f"[+] Done — {len(self.already_alerted)} alert(s), {len(self.ports_by_source)} host(s) seen")