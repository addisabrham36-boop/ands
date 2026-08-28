from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, Raw
from datetime import datetime


class MemcachedAmplificationDetect(ModuleBase):
    """
    Memcached UDP Amplification DDoS Sentinel.
    Monitors UDP port 11211 for 'stats' / 'get' command floods and oversized
    Memcached response bursts weaponized for volumetric reflective DDoS.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return

        udp = pkt[UDP]
        if udp.dport != 11211 and udp.sport != 11211:
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        is_amp = False
        if len(pkt) > 400 and udp.sport == 11211:
            is_amp = True
        elif pkt.haslayer(Raw):
            load = bytes(pkt[Raw].load)
            if b"stats" in load or b"get " in load or b"set " in load:
                is_amp = True

        if is_amp:
            key = (src, dst, "MEMCACHED_AMP")
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] Memcached Amplification DDoS: {src} -> {dst} (Size: {len(pkt)}B) [{ts}]")

                self.session.add_alert({
                    "type": "MEMCACHED_UDP_AMPLIFICATION",
                    "severity": "CRITICAL",
                    "confidence": 0.96,
                    "mitre_id": "T1498.002",
                    "source": src,
                    "destination": dst,
                    "protocol": "MEMCACHED",
                    "description": f"Memcached UDP amplification probe or volumetric response ({len(pkt)}B) observed between {src} and {dst}",
                    "details": {
                        "packet_size": len(pkt),
                        "port": 11211,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Memcached Reflection Sentinel active on {iface} (port 11211)...")

        try:
            sniff(iface=iface, filter="udp and port 11211", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Memcached monitoring stopped.")
            return

        print(f"[+] Memcached Sentinel finished — {len(self.already_alerted)} incident(s) flagged.")
