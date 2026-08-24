from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, Raw
from datetime import datetime


class SSDPAmplificationDetect(ModuleBase):
    """
    SSDP (Simple Service Discovery Protocol) Reflection DDoS Sentinel.
    Monitors UDP port 1900 for M-SEARCH discovery broadcasts and large UPnP device
    responses abused to amplify volumetric denial-of-service traffic.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            return

        udp = pkt[UDP]
        if udp.dport != 1900 and udp.sport != 1900:
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        payload = bytes(pkt[Raw].load)
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return

        is_amp = False
        if "M-SEARCH * HTTP/1.1" in text and ("ssdp:all" in text.lower() or "upnp:rootdevice" in text.lower()):
            is_amp = True
        elif udp.sport == 1900 and len(pkt) > 300 and "HTTP/1.1 200 OK" in text:
            is_amp = True

        if is_amp:
            key = (src, dst, "SSDP_AMP")
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] SSDP Reflection / Amplification Detected: {src} -> {dst} [{ts}]")

                self.session.add_alert({
                    "type": "SSDP_AMPLIFICATION",
                    "severity": "HIGH",
                    "confidence": 0.94,
                    "mitre_id": "T1498.002",
                    "source": src,
                    "destination": dst,
                    "protocol": "SSDP",
                    "description": f"SSDP (UPnP) Reflection DDoS probe or amplified response observed between {src} and {dst} on port 1900",
                    "details": {
                        "packet_length": len(pkt),
                        "src_port": udp.sport,
                        "dst_port": udp.dport,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] SSDP Reflection Sentinel active on {iface} (port 1900)...")

        try:
            sniff(iface=iface, filter="udp and port 1900", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SSDP monitoring stopped.")
            return

        print(f"[+] SSDP Sentinel finished — {len(self.already_alerted)} reflection event(s) detected.")
