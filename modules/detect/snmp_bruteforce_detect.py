from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, Raw
import collections
from datetime import datetime


class SNMPBruteforceDetect(ModuleBase):
    """
    SNMP Community String Guessing & Enumeration Sentinel.
    Monitors UDP port 161 for rapid community string probes ('public', 'private',
    'cisco', 'manager') used in network device discovery and reconnaissance.
    """

    DEFAULT_COMMUNITIES = {b"public", b"private", b"cisco", b"manager", b"secret", b"admin"}

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "PROBE_THRESHOLD": {"value": "5", "required": True, "desc": "Distinct community strings / query bursts to trigger alert"},
        }
        self.probes = collections.defaultdict(set)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(Raw)):
            return

        udp = pkt[UDP]
        if udp.dport != 161:
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        raw = bytes(pkt[Raw].load)
        matched_comm = None
        for comm in self.DEFAULT_COMMUNITIES:
            if comm in raw:
                matched_comm = comm.decode("ascii")
                break

        if matched_comm:
            self.probes[src].add(matched_comm)
            thresh = int(self.options["PROBE_THRESHOLD"]["value"])

            if len(self.probes[src]) >= thresh or len(self.probes[src]) >= 2:
                if src not in self.already_alerted:
                    self.already_alerted.add(src)
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"[ALERT] SNMP Community Guessing: {src} -> {dst} (Tried: {', '.join(self.probes[src])}) [{ts}]")

                    self.session.add_alert({
                        "type": "SNMP_COMMUNITY_BRUTEFORCE",
                        "severity": "HIGH",
                        "confidence": 0.94,
                        "mitre_id": "T1110.001",
                        "source": src,
                        "destination": dst,
                        "protocol": "SNMP",
                        "description": f"SNMP Community string brute-force / enumeration probe from {src} against {dst}: tested community strings {sorted(list(self.probes[src]))}",
                        "details": {
                            "tested_communities": sorted(list(self.probes[src])),
                            "target_port": 161,
                        }
                    })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.probes.clear()
        self.already_alerted.clear()

        print(f"[*] SNMP Reconnaissance Sentinel active on {iface} (port 161)...")

        try:
            sniff(iface=iface, filter="udp and port 161", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SNMP monitoring stopped.")
            return

        print(f"[+] SNMP scan complete — {len(self.already_alerted)} brute-force source(s) identified.")
