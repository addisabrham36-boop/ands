from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


class LandSmurfDetect(ModuleBase):
    """
    Malformed Packet & Broadcast Amplification Sentinel.
    Detects classic Land Attacks (Source IP equals Destination IP) and
    Smurf / Fraggle broadcast amplification attacks.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        # Land Attack: Source IP == Destination IP
        if src == dst and src not in ("127.0.0.1", "0.0.0.0"):
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else 0
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else 0
            key = ("LAND", src, sport, dport)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] LAND Attack Detected! Source == Destination ({src}:{sport}) [{ts}]")

                self.session.add_alert({
                    "type": "LAND_ATTACK",
                    "severity": "CRITICAL",
                    "confidence": 0.99,
                    "mitre_id": "T1498.001",
                    "source": src,
                    "destination": dst,
                    "protocol": "TCP" if pkt.haslayer(TCP) else "IP",
                    "description": f"Malformed Land Attack packet detected: Source IP ({src}) identical to Destination IP ({dst}), risking OS TCP stack starvation",
                    "details": {
                        "src_ip": src,
                        "dst_ip": dst,
                        "src_port": sport,
                        "dst_port": dport,
                    }
                })

        # Smurf Attack: ICMP Echo to broadcast address (.255 or 255.255.255.255)
        if pkt.haslayer(ICMP) and (dst.endswith(".255") or dst == "255.255.255.255"):
            key = ("SMURF", src, dst)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] Smurf Broadcast Amplification Probe: {src} -> Broadcast {dst} [{ts}]")

                self.session.add_alert({
                    "type": "SMURF_AMPLIFICATION",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "mitre_id": "T1498.002",
                    "source": src,
                    "destination": dst,
                    "protocol": "ICMP",
                    "description": f"Smurf Amplification attack probe: ICMP Echo sent to directed broadcast address {dst} with spoofed source {src}",
                    "details": {
                        "broadcast_target": dst,
                        "spoofed_source": src,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Land / Smurf Malformed Packet Sentinel active on {iface}...")
        try:
            sniff(iface=iface, filter="ip", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Sentinel halted.")
            return

        print(f"[+] Malformed packet scan finished — {len(self.already_alerted)} violation(s) flagged.")
