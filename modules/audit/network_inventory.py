from core.module_base import ModuleBase
from scapy.all import sniff, IP, ARP, TCP, UDP
import time


class NetworkInventoryAudit(ModuleBase):
    """
    Passive Network Asset & Host Inventory Discovery Auditor.
    Maps active subnet hosts, open ports, communication protocols,
    MAC vendors, and passive OS fingerprinting without active port scanning.
    """

    OUI_TABLE = {
        "00:0c:29": "VMware", "00:50:56": "VMware",
        "08:00:27": "Oracle VirtualBox",
        "52:54:00": "QEMU/KVM",
        "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi",
        "00:1a:11": "Google", "3c:5a:b4": "Google",
        "ac:de:48": "Apple", "f0:18:98": "Apple",
        "00:15:5d": "Microsoft Hyper-V",
        "70:85:c2": "Intel", "00:1e:67": "Intel",
        "04:0e:3c": "Realtek/Local PC",
    }

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "20", "required": True, "desc": "Discovery duration in seconds (0 = continuous)"},
        }

    def _lookup_vendor(self, mac: str) -> str:
        if not mac or len(mac) < 8:
            return "Unknown"
        prefix = mac[:8].lower()
        return self.OUI_TABLE.get(prefix, "Standard NIC / Hardware")

    def _on_packet(self, pkt):
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            src_ip = arp.psrc
            src_mac = arp.hwsrc.lower()
            vendor = self._lookup_vendor(src_mac)
            self.session.record_host(src_ip, mac=src_mac, vendor=vendor, proto="ARP")

        elif pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            ttl = ip.ttl
            
            os_hint = "Linux/Android" if ttl <= 64 else ("Windows" if ttl <= 128 else "Cisco/Solaris")

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                self.session.record_host(src_ip, os_hint=os_hint, port=tcp.sport, proto="TCP")
                self.session.record_host(dst_ip, port=tcp.dport, proto="TCP")
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                self.session.record_host(src_ip, os_hint=os_hint, port=udp.sport, proto="UDP")
                self.session.record_host(dst_ip, port=udp.dport, proto="UDP")
            else:
                self.session.record_host(src_ip, os_hint=os_hint, proto="IP")

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        print(f"[*] Passive Network Inventory Discovery active on {iface} for {duration}s...")
        try:
            sniff(iface=iface, prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Inventory discovery stopped.")

        inventory = self.session.get_inventory()
        print(f"\n[+] Discovered {len(inventory)} Active Host(s) on the Network:\n")
        print(f"{'IP Address':<17}{'MAC / Vendor':<28}{'OS Hint':<16}{'Active Ports':<20}{'Alerts':<8}")
        print("-" * 90)
        for h in inventory:
            mac_info = f"{h['mac'] or 'N/A'} ({h['vendor'] or 'Unknown'})"[:26]
            ports_str = ",".join(str(p) for p in h["ports"][:6]) or "N/A"
            print(f"{h['ip']:<17}{mac_info:<28}{h['os_hint'] or 'Unknown':<16}{ports_str:<20}{h['alerts']:<8}")
        print("-" * 90 + "\n")
