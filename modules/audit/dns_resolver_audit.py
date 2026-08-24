from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, DNS
from datetime import datetime


class DNSResolverAudit(ModuleBase):
    """
    DNS Resolver & Outbound Query Policy Auditor.
    Audits destination DNS servers queried by local endpoints to detect DNS policy
    bypasses, shadow IT DNS resolvers, and unapproved external nameservers.
    """

    APPROVED_DEFAULTS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "127.0.0.53"}

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "APPROVED_SERVERS": {"value": "1.1.1.1,8.8.8.8,127.0.0.53", "required": False, "desc": "Comma-separated list of approved DNS server IPs"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS)):
            return

        ip = pkt[IP]
        udp = pkt[UDP]

        # Only check outbound DNS requests (dport == 53)
        if udp.dport != 53:
            return

        src = ip.src
        dst_dns = ip.dst

        if self.session.is_whitelisted(src):
            return

        approved_opt = self.options["APPROVED_SERVERS"]["value"]
        approved_set = {s.strip() for s in approved_opt.split(",") if s.strip()} or self.APPROVED_DEFAULTS

        if dst_dns not in approved_set:
            key = (src, dst_dns)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[AUDIT ALERT] Unapproved DNS Resolver: {src} -> {dst_dns} (Not in policy) [{ts}]")

                self.session.add_alert({
                    "type": "UNAPPROVED_DNS_RESOLVER",
                    "severity": "LOW",
                    "confidence": 0.90,
                    "mitre_id": "T1071.004",
                    "source": src,
                    "destination": dst_dns,
                    "protocol": "DNS",
                    "description": f"Endpoint {src} queried unapproved external DNS resolver {dst_dns}, potentially bypassing security filtering",
                    "details": {
                        "resolver_ip": dst_dns,
                        "client_ip": src,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] DNS Policy & Resolver Auditor active on {iface}...")

        try:
            sniff(iface=iface, filter="udp and dst port 53", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] DNS auditor stopped.")
            return

        print(f"[+] DNS Policy Audit finished — {len(self.already_alerted)} unapproved resolver flow(s) identified.")
