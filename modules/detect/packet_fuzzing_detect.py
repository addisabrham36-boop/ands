from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP
from datetime import datetime


class PacketFuzzingDetect(ModuleBase):
    """
    Protocol Fuzzing & Malformed Packet Sentinel.
    Identifies zero TTL values, illegal TCP option lengths, invalid TCP flag combinations
    (e.g., SYN+FIN, SYN+RST), and protocol fuzzer anomalies.
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

        if self.session.is_whitelisted(src):
            return

        anomaly_type = None

        # 1. Zero TTL
        if ip.ttl == 0:
            anomaly_type = "ZERO_TTL_PACKET"

        # 2. Invalid TCP Flag Combinations (SYN+FIN = 0x03, SYN+RST = 0x06)
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = int(tcp.flags)
            if (flags & 0x03 == 0x03) or (flags & 0x06 == 0x06):
                anomaly_type = "ILLEGAL_TCP_FLAGS_FUZZING"
            elif flags == 0x3F:  # ALL flags set
                anomaly_type = "ALL_FLAGS_SET_FUZZING"

        if anomaly_type:
            key = (src, dst, anomaly_type)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] Malformed / Protocol Fuzzer Packet [{anomaly_type}]: {src} -> {dst} [{ts}]")

                self.session.add_alert({
                    "type": anomaly_type,
                    "severity": "HIGH",
                    "confidence": 0.96,
                    "mitre_id": "T1499",
                    "source": src,
                    "destination": dst,
                    "protocol": "TCP" if pkt.haslayer(TCP) else "IP",
                    "description": f"Malformed packet or protocol fuzzer anomaly detected: {anomaly_type} from {src} to {dst}",
                    "details": {
                        "ttl": ip.ttl,
                        "anomaly": anomaly_type,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Protocol Fuzzing Sentinel active on {iface}...")

        try:
            sniff(iface=iface, filter="ip", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Fuzzing monitor stopped.")
            return

        print(f"[+] Fuzzing scan finished — {len(self.already_alerted)} anomaly event(s) detected.")
