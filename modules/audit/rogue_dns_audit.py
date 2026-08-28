from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, DNS
from datetime import datetime


class RogueDNSAudit(ModuleBase):
    """
    Rogue / External DNS Nameserver Policy Auditor.
    Monitors outbound DNS queries on port 53 targeting unapproved external resolvers,
    identifying shadow IT, split-brain DNS, and circumvention of internal DNS filtering.
    """

    APPROVED_DNS = {"10.0.0.1", "192.168.1.1", "127.0.0.1", "127.0.0.53"}

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Audit duration in seconds"},
            "APPROVED_SERVERS": {"value": "1.1.1.1,8.8.8.8,127.0.0.1,127.0.0.53", "required": True, "desc": "Comma-separated approved DNS server IPs"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return

        udp = pkt[UDP]
        if udp.dport != 53:
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        approved = set(s.strip() for s in self.options["APPROVED_SERVERS"]["value"].split(",") if s.strip())
        if dst not in approved:
            key = (src, dst, "UNAPPROVED_DNS")
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[AUDIT ALERT] Unapproved DNS Resolver Target: {src} -> {dst}:53 [{ts}]")

                self.session.add_alert({
                    "type": "UNAPPROVED_EXTERNAL_DNS_RESOLVER",
                    "severity": "MEDIUM",
                    "confidence": 0.91,
                    "mitre_id": "T1071.004",
                    "source": src,
                    "destination": dst,
                    "protocol": "DNS",
                    "description": f"Outbound DNS query from {src} to unapproved external resolver {dst} bypassing internal DNS policies",
                    "details": {
                        "resolver_ip": dst,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Rogue DNS Policy Auditor active on {iface}...")

        try:
            sniff(iface=iface, filter="udp and port 53", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] DNS audit stopped.")
            return

        print(f"[+] Rogue DNS Audit complete — {len(self.already_alerted)} unapproved resolver(s) caught.")
