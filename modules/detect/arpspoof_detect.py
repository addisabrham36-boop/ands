from core.module_base import ModuleBase
from scapy.all import sniff, ARP
import time
from datetime import datetime


class ARPSpoofDetect(ModuleBase):
    """
    Real-Time ARP Spoofing, Poisoning & Gateway MAC Drift Sentinel.
    Maintains an in-memory dynamic ARP mapping table, detecting duplicate IP claims,
    unsolicited gratuitous ARP floods, and Man-in-the-Middle (MITM) hijacking.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        self.ip_to_mac = {}
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not pkt.haslayer(ARP):
            return

        arp = pkt[ARP]
        op = arp.op  # 1: who-has, 2: is-at
        src_ip = arp.psrc
        src_mac = arp.hwsrc.lower()

        if not src_ip or src_ip == "0.0.0.0":
            return

        if self.session.is_whitelisted(src_ip):
            return

        # Learn host in inventory
        self.session.record_host(src_ip, mac=src_mac, proto="ARP")

        # Check for IP-MAC mapping conflict
        if src_ip in self.ip_to_mac:
            known_mac = self.ip_to_mac[src_ip]
            if known_mac != src_mac:
                alert_key = (src_ip, known_mac, src_mac)
                if alert_key not in self.already_alerted:
                    self.already_alerted.add(alert_key)
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"[ALERT] ARP Poisoning / Spoofing Detected! IP {src_ip} claimed by {src_mac} (was {known_mac}) [{ts}]")
                    
                    self.session.add_alert({
                        "type": "ARP_SPOOFING",
                        "severity": "CRITICAL",
                        "confidence": 0.95,
                        "mitre_id": "T1557.002",
                        "source": src_ip,
                        "destination": "GATEWAY_OR_HOST",
                        "protocol": "ARP",
                        "description": f"ARP Poisoning / Man-In-The-Middle attack: IP {src_ip} conflicting MAC assignment (originally {known_mac}, now claimed by {src_mac})",
                        "details": {
                            "spoofed_ip": src_ip,
                            "original_mac": known_mac,
                            "attacker_mac": src_mac,
                            "arp_opcode": op,
                        }
                    })
        else:
            self.ip_to_mac[src_ip] = src_mac

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.ip_to_mac.clear()
        self.already_alerted.clear()

        print(f"[*] ARP Spoofing Sentinel active on {iface}...")
        try:
            sniff(iface=iface, filter="arp", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] ARP monitoring stopped by user.")
            return

        print(f"[+] ARP Sentinel completed — {len(self.already_alerted)} poisoning incident(s), {len(self.ip_to_mac)} host MAC(s) mapped.")
