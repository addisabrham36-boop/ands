from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, DNS, DNSQR
from datetime import datetime


class DNSAmplificationDetect(ModuleBase):
    """
    DNS Reflection & ANY Query Amplification DDoS Sentinel.
    Detects high-frequency ANY/ALL record DNS queries (qtype 255) and oversized
    EDNS0 buffer responses (> 512 bytes) weaponized for DDoS reflection.
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

        dns = pkt[DNS]
        is_amp = False
        qname = ""

        # Check ANY query (qtype 255)
        if pkt.haslayer(DNSQR):
            if pkt[DNSQR].qtype == 255:  # ANY query
                is_amp = True
                try:
                    qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore")
                except Exception:
                    qname = "UNKNOWN"

        # Check oversized response (> 512 bytes on UDP)
        if dns.qr == 1 and len(pkt) > 512 and pkt.haslayer(UDP):
            is_amp = True

        if is_amp:
            key = (src, dst, "DNS_AMP")
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] DNS Amplification Probe: {src} -> {dst} (Domain: {qname}) [{ts}]")

                self.session.add_alert({
                    "type": "DNS_AMPLIFICATION",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "mitre_id": "T1498.002",
                    "source": src,
                    "destination": dst,
                    "protocol": "DNS",
                    "description": f"DNS Amplification attack indicator: ANY query or oversized DNS response ({len(pkt)} bytes) detected between {src} and {dst}",
                    "details": {
                        "packet_length": len(pkt),
                        "queried_domain": qname,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] DNS Amplification Sentinel active on {iface} (port 53)...")

        try:
            sniff(iface=iface, filter="udp and port 53", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] DNS amplification monitoring halted.")
            return

        print(f"[+] DNS Amplification Sentinel finished — {len(self.already_alerted)} violation(s) flagged.")
