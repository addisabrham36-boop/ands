from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, Raw
from datetime import datetime


class NTPAmplificationDetect(ModuleBase):
    """
    NTP Reflection & Monlist Amplification DDoS Sentinel.
    Monitors UDP port 123 for monlist command requests (code 0x2a) and
    large NTP response bursts commonly used in reflective amplification attacks.
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
        if udp.dport != 123 and udp.sport != 123:
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        is_monlist = False
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""

        # Monlist request: Mode 7 (private), Request code 42 (0x2a)
        if len(payload) >= 4:
            req_code = payload[3] if len(payload) > 3 else 0
            if req_code == 42 or b"\x17\x00\x03\x2a" in payload:
                is_monlist = True

        # Large NTP response packet (> 400 bytes) indicates amplification
        if len(pkt) > 400 and udp.sport == 123:
            is_monlist = True

        if is_monlist:
            key = (src, dst, "NTP_AMP")
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] NTP Amplification / Monlist Attack: {src} -> {dst} (Size: {len(pkt)}B) [{ts}]")

                self.session.add_alert({
                    "type": "NTP_AMPLIFICATION",
                    "severity": "CRITICAL",
                    "confidence": 0.96,
                    "mitre_id": "T1498.002",
                    "source": src,
                    "destination": dst,
                    "protocol": "NTP",
                    "description": f"NTP Reflection / Amplification DDoS attempt detected from {src} targeting {dst}: payload matches monlist command / oversized response ({len(pkt)} bytes)",
                    "details": {
                        "packet_size": len(pkt),
                        "src_port": udp.sport,
                        "dst_port": udp.dport,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] NTP Amplification Sentinel active on {iface} (port 123)...")

        try:
            sniff(iface=iface, filter="udp and port 123", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] NTP monitoring stopped.")
            return

        print(f"[+] NTP scan finished — {len(self.already_alerted)} amplification incident(s) flagged.")
