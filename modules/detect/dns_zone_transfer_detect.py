from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, DNS, DNSQR
from datetime import datetime


class DNSZoneTransferDetect(ModuleBase):
    """
    DNS Full Zone Transfer (AXFR) Leak Sentinel.
    Monitors TCP port 53 for AXFR (qtype 252) or IXFR (qtype 251) zone transfer
    requests used to dump an organization's entire internal DNS infrastructure.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(DNS)):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        if pkt.haslayer(DNSQR):
            qtype = pkt[DNSQR].qtype
            if qtype in (252, 251):  # AXFR or IXFR
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                key = (src, dst, qname)
                if key not in self.already_alerted:
                    self.already_alerted.add(key)
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"[ALERT] DNS AXFR Zone Transfer Query: {src} -> {dst} (Zone: {qname}) [{ts}]")

                    self.session.add_alert({
                        "type": "DNS_AXFR_ZONE_TRANSFER_ATTEMPT",
                        "severity": "CRITICAL",
                        "confidence": 0.98,
                        "mitre_id": "T1590.002",
                        "source": src,
                        "destination": dst,
                        "protocol": "DNS",
                        "description": f"DNS Full Zone Transfer (AXFR) requested by {src} against {dst} for zone '{qname}'",
                        "details": {
                            "queried_zone": qname,
                            "qtype": "AXFR" if qtype == 252 else "IXFR",
                        }
                    })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] DNS Zone Transfer (AXFR) Sentinel active on {iface} (port 53 TCP)...")

        try:
            sniff(iface=iface, filter="tcp and port 53", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] AXFR monitoring stopped.")
            return

        print(f"[+] AXFR Sentinel complete — {len(self.already_alerted)} incident(s) flagged.")
