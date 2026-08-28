from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw
import collections


class ProtocolProfiler(ModuleBase):
    """
    L3/L4 Protocol Distribution & Network Traffic Profiler.
    Generates a deep protocol histogram, packet size distribution,
    and flags unrecognized or non-standard protocol encapsulations.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "15", "required": True, "desc": "Profiling duration in seconds"},
        }
        self.proto_counts = collections.defaultdict(int)
        self.size_bins = collections.defaultdict(int)

    def _on_packet(self, pkt):
        length = len(pkt)
        bin_key = f"{(length // 256) * 256}-{(length // 256 + 1) * 256 - 1}B"
        self.size_bins[bin_key] += 1

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.dport in (80, 8080) or tcp.sport in (80, 8080):
                self.proto_counts["HTTP (TCP/80)"] += 1
            elif tcp.dport == 443 or tcp.sport == 443:
                self.proto_counts["HTTPS / TLS (TCP/443)"] += 1
            elif tcp.dport == 22 or tcp.sport == 22:
                self.proto_counts["SSH (TCP/22)"] += 1
            elif tcp.dport == 445 or tcp.sport == 445:
                self.proto_counts["SMB (TCP/445)"] += 1
            else:
                self.proto_counts[f"TCP-Other ({tcp.dport})"] += 1

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            if udp.dport == 53 or udp.sport == 53 or pkt.haslayer(DNS):
                self.proto_counts["DNS (UDP/53)"] += 1
            elif udp.dport in (67, 68) or udp.sport in (67, 68):
                self.proto_counts["DHCP (UDP/67-68)"] += 1
            elif udp.dport == 123 or udp.sport == 123:
                self.proto_counts["NTP (UDP/123)"] += 1
            else:
                self.proto_counts[f"UDP-Other ({udp.dport})"] += 1

        elif pkt.haslayer(ICMP):
            self.proto_counts["ICMP"] += 1
        elif pkt.haslayer(ARP):
            self.proto_counts["ARP"] += 1
        else:
            self.proto_counts["Other-Raw"] += 1

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.proto_counts.clear()
        self.size_bins.clear()
        print(f"[*] Profiling L3/L4 protocol distribution on {iface} for {duration} seconds...")

        try:
            sniff(iface=iface, prn=self._on_packet, timeout=duration, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Profiling stopped.")

        total_pkts = sum(self.proto_counts.values()) or 1
        print(f"\n{'='*70}")
        print(f"🔬 PROTOCOL TELEMETRY PROFILER ({total_pkts} Packets Sampled)")
        print(f"{'='*70}")
        print(f"{'PROTOCOL / SERVICE':<30} {'PACKET COUNT':<16} {'PERCENTAGE':<12}")
        print(f"{'-'*70}")

        for proto, cnt in sorted(self.proto_counts.items(), key=lambda x: -x[1]):
            pct = (cnt / total_pkts) * 100
            bar = "█" * int(pct // 4)
            print(f"{proto:<30} {cnt:<16} {pct:<6.1f}% | {bar}")

        print(f"\nPACKET SIZE HISTOGRAM:")
        for b_name, b_cnt in sorted(self.size_bins.items()):
            b_pct = (b_cnt / total_pkts) * 100
            print(f"  • {b_name:<16}: {b_cnt:<6} ({b_pct:4.1f}%)")
        print(f"{'='*70}\n")
