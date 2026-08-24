from core.module_base import ModuleBase
from scapy.all import sniff, IP, ICMP, Raw
import time
import collections
from datetime import datetime
from core.statistics import calculate_shannon_entropy


class ICMPTunnelDetect(ModuleBase):
    """
    ICMP Tunneling, Oversized Echo & Ping Flood Sentinel.
    Inspects ICMP Echo packets for covert data encapsulation, high-entropy payloads,
    oversized packets (> 128 bytes), and volumetric ICMP floods.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "MAX_PAYLOAD_SIZE": {"value": "128", "required": True, "desc": "Maximum normal ICMP payload size in bytes"},
            "ENTROPY_THRESHOLD": {"value": "3.8", "required": True, "desc": "Shannon entropy threshold indicating encrypted/encoded data"},
            "FLOOD_THRESHOLD": {"value": "40", "required": True, "desc": "ICMP packets per 5-second window indicating a flood"},
        }
        self.flood_counter = collections.defaultdict(int)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(ICMP)):
            return

        ip = pkt[IP]
        icmp = pkt[ICMP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        # Echo request (8) or reply (0)
        if icmp.type not in (0, 8):
            return

        max_size = int(self.options["MAX_PAYLOAD_SIZE"]["value"])
        ent_thresh = float(self.options["ENTROPY_THRESHOLD"]["value"])
        flood_thresh = int(self.options["FLOOD_THRESHOLD"]["value"])

        self.flood_counter[src] += 1

        # Check payload if present
        payload_bytes = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        payload_len = len(payload_bytes)

        if payload_len > max_size:
            ent = calculate_shannon_entropy(payload_bytes)
            if ent >= ent_thresh:
                key = (src, "TUNNEL", dst)
                if key not in self.already_alerted:
                    self.already_alerted.add(key)
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"[ALERT] ICMP Tunneling / Data Exfiltration: {src} -> {dst} [Payload: {payload_len}B, Entropy: {ent:.2f}] [{ts}]")
                    self.session.add_alert({
                        "type": "ICMP_TUNNELING",
                        "severity": "HIGH",
                        "confidence": 0.92,
                        "mitre_id": "T1095",
                        "source": src,
                        "destination": dst,
                        "protocol": "ICMP",
                        "description": f"Covert ICMP Tunneling / Encapsulated Exfiltration detected from {src}: {payload_len} bytes payload with high entropy ({ent:.2f})",
                        "details": {
                            "payload_size_bytes": payload_len,
                            "shannon_entropy": round(ent, 3),
                            "icmp_type": icmp.type,
                        }
                    })

        # Check flood
        if self.flood_counter[src] >= flood_thresh:
            key = (src, "FLOOD", dst)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] ICMP Ping Flood: {src} -> {dst} [{self.flood_counter[src]} packets] [{ts}]")
                self.session.add_alert({
                    "type": "ICMP_FLOOD",
                    "severity": "MEDIUM",
                    "confidence": 0.88,
                    "mitre_id": "T1498.001",
                    "source": src,
                    "destination": dst,
                    "protocol": "ICMP",
                    "description": f"ICMP Ping Flood / Bandwidth Exhaustion detected from {src} ({self.flood_counter[src]} echo requests)",
                    "details": {
                        "packet_count": self.flood_counter[src],
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.flood_counter.clear()
        self.already_alerted.clear()

        print(f"[*] ICMP Anomaly & Tunneling Sentinel active on {iface}...")
        try:
            sniff(iface=iface, filter="icmp", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] ICMP monitoring halted.")
            return

        print(f"[+] ICMP scan complete — {len(self.already_alerted)} suspicious ICMP event(s) recorded.")
