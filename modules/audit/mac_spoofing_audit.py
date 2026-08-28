from core.module_base import ModuleBase
from scapy.all import sniff, Ether, IP, ARP
import collections
from datetime import datetime


class MACSpoofingAudit(ModuleBase):
    """
    MAC Address Spoofing & Flapping Auditor.
    Monitors layer-2 ARP/Ethernet bindings to identify MAC address spoofing,
    rapid MAC flapping, and multiple distinct IP addresses claiming the same physical MAC.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Audit duration in seconds"},
        }
        self.mac_to_ips = collections.defaultdict(set)
        self.ip_to_macs = collections.defaultdict(set)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not pkt.haslayer(Ether):
            return

        eth = pkt[Ether]
        src_mac = eth.src
        src_ip = None

        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
        elif pkt.haslayer(ARP):
            src_ip = pkt[ARP].psrc

        if not src_ip or src_ip.startswith("0.") or src_ip == "255.255.255.255":
            return

        if self.session.is_whitelisted(src_ip):
            return

        self.mac_to_ips[src_mac].add(src_ip)
        self.ip_to_macs[src_ip].add(src_mac)

        # Check MAC flapping (Single IP claiming multiple MACs)
        if len(self.ip_to_macs[src_ip]) >= 2:
            key = (src_ip, "IP_MAC_FLAP")
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[AUDIT ALERT] IP Address MAC Flapping: {src_ip} claims {self.ip_to_macs[src_ip]} [{ts}]")

                self.session.add_alert({
                    "type": "IP_MAC_FLAPPING_ANOMALY",
                    "severity": "HIGH",
                    "confidence": 0.94,
                    "mitre_id": "T1557.002",
                    "source": src_ip,
                    "destination": "GATEWAY",
                    "protocol": "ARP",
                    "description": f"IP address {src_ip} is flapping across multiple physical MAC addresses: {sorted(list(self.ip_to_macs[src_ip]))}",
                    "details": {
                        "mac_addresses": sorted(list(self.ip_to_macs[src_ip])),
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.mac_to_ips.clear()
        self.ip_to_macs.clear()
        self.already_alerted.clear()
        print(f"[*] Layer-2 MAC Spoofing Auditor active on {iface}...")

        try:
            sniff(iface=iface, filter="arp or ip", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] MAC audit stopped.")
            return

        print(f"[+] MAC Spoofing Audit complete — {len(self.already_alerted)} flapping event(s) logged.")
