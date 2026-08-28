from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime


class LDAPAnonymousDetect(ModuleBase):
    """
    LDAP Anonymous Bind & Reconnaissance Sentinel.
    Inspects TCP port 389/636 for anonymous directory bind requests (bind simple with empty DN)
    used by attackers to enumerate domain users, groups, and Active Directory objects.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        tcp = pkt[TCP]
        if tcp.dport not in (389, 636, 3268) and tcp.sport not in (389, 636, 3268):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        raw = bytes(pkt[Raw].load)
        # LDAP BindRequest: 0x30 ... 0x60 (bindRequest) with empty auth or simple bind
        if b"\x60" in raw and (b"\x80\x00" in raw or b"\x02\x01\x03\x04\x00" in raw):
            key = (src, dst, "LDAP_ANON")
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] LDAP Anonymous Bind Attempt: {src} -> {dst}:389 [{ts}]")

                self.session.add_alert({
                    "type": "LDAP_ANONYMOUS_RECONNAISSANCE",
                    "severity": "HIGH",
                    "confidence": 0.95,
                    "mitre_id": "T1087.002",
                    "source": src,
                    "destination": dst,
                    "protocol": "LDAP",
                    "description": f"Anonymous LDAP directory enumeration / bind request from {src} targeting {dst}:389",
                    "details": {
                        "port": tcp.dport,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] LDAP Reconnaissance Sentinel active on {iface} (port 389/636)...")

        try:
            sniff(iface=iface, filter="tcp and (port 389 or port 636)", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] LDAP monitoring stopped.")
            return

        print(f"[+] LDAP Sentinel complete — {len(self.already_alerted)} incident(s) flagged.")
