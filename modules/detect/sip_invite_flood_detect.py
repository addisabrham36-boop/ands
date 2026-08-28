from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, Raw
import collections
from datetime import datetime


class SIPInviteFloodDetect(ModuleBase):
    """
    VoIP SIP Flood & Telephony Telemetry Sentinel.
    Monitors UDP port 5060 for SIP INVITE floods, REGISTER brute-forcing,
    and VoIP toll fraud scanning probes.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "THRESHOLD": {"value": "10", "required": True, "desc": "SIP messages to trigger alert in 10s"},
        }
        self.sip_counts = collections.defaultdict(list)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            return

        udp = pkt[UDP]
        if udp.dport != 5060 and udp.sport != 5060:
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        raw = bytes(pkt[Raw].load)
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return

        if "INVITE sip:" in text or "REGISTER sip:" in text:
            now = datetime.now()
            self.sip_counts[src].append(now)
            thresh = int(self.options["THRESHOLD"]["value"])

            recent = [t for t in self.sip_counts[src] if (now - t).total_seconds() <= 10]
            self.sip_counts[src] = recent

            if len(recent) >= thresh:
                key = (src, dst, "SIP_FLOOD")
                if key not in self.already_alerted:
                    self.already_alerted.add(key)
                    ts = now.strftime("%H:%M:%S")
                    print(f"[ALERT] VoIP SIP Flood / Scanning: {src} -> {dst}:5060 ({len(recent)} msgs) [{ts}]")

                    self.session.add_alert({
                        "type": "VOIP_SIP_INVITE_FLOOD",
                        "severity": "HIGH",
                        "confidence": 0.94,
                        "mitre_id": "T1499",
                        "source": src,
                        "destination": dst,
                        "protocol": "SIP",
                        "description": f"VoIP SIP INVITE/REGISTER flood or telephony toll fraud probe from {src} against {dst}:5060",
                        "details": {
                            "packet_count": len(recent),
                            "port": 5060,
                        }
                    })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.sip_counts.clear()
        self.already_alerted.clear()
        print(f"[*] VoIP SIP Sentinel active on {iface} (port 5060)...")

        try:
            sniff(iface=iface, filter="udp and port 5060", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SIP monitoring stopped.")
            return

        print(f"[+] SIP Sentinel complete — {len(self.already_alerted)} flood source(s) flagged.")
