from core.module_base import ModuleBase
from scapy.all import sniff, IPv6, ICMPv6ND_RA
import collections
from datetime import datetime


class IPv6RAFloodDetect(ModuleBase):
    """
    IPv6 Rogue Router Advertisement (RA) Flood Sentinel.
    Detects high-frequency ICMPv6 Type 134 Router Advertisements used to perform
    Man-in-the-Middle default gateway hijacking or CPU exhaustion denial-of-service.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "RATE_LIMIT": {"value": "4", "required": True, "desc": "Max allowable RA packets in 10-second window"},
        }
        self.ra_packets = collections.defaultdict(list)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IPv6) and pkt.haslayer(ICMPv6ND_RA)):
            return

        ip6 = pkt[IPv6]
        src = ip6.src
        now = datetime.now()
        self.ra_packets[src].append(now)

        recent = [t for t in self.ra_packets[src] if (now - t).total_seconds() <= 10]
        self.ra_packets[src] = recent
        rate_limit = int(self.options["RATE_LIMIT"]["value"])

        if len(recent) >= rate_limit:
            if src not in self.already_alerted:
                self.already_alerted.add(src)
                ts = now.strftime("%H:%M:%S")
                print(f"[ALERT] IPv6 Rogue Router Advertisement Flood: {src} ({len(recent)} RAs) [{ts}]")

                self.session.add_alert({
                    "type": "IPV6_ROUTER_ADVERTISEMENT_FLOOD",
                    "severity": "CRITICAL",
                    "confidence": 0.96,
                    "mitre_id": "T1557",
                    "source": src,
                    "destination": "ff02::1",
                    "protocol": "ICMPv6",
                    "description": f"Rogue IPv6 Router Advertisement (RA) flood / gateway hijacking attempt from {src} ({len(recent)} RAs in 10s)",
                    "details": {
                        "packet_count": len(recent),
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.ra_packets.clear()
        self.already_alerted.clear()
        print(f"[*] IPv6 Router Advertisement Sentinel active on {iface}...")

        try:
            sniff(iface=iface, filter="icmp6", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] IPv6 monitoring stopped.")
            return

        print(f"[+] IPv6 Sentinel complete — {len(self.already_alerted)} flood source(s) caught.")
