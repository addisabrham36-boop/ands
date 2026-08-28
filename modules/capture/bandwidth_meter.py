from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, UDP
import collections
import time


class BandwidthMeter(ModuleBase):
    """
    Per-Host & Per-Port Bandwidth Consumption Meter.
    Tracks packet counts, total transferred bytes, and throughput rates
    per IP endpoint to identify top talkers and excessive bandwidth consumers.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "15", "required": True, "desc": "Monitoring interval in seconds"},
            "TOP_N": {"value": "10", "required": False, "desc": "Number of top talkers to display"},
        }
        self.host_bytes = collections.defaultdict(int)
        self.host_pkts = collections.defaultdict(int)
        self.port_bytes = collections.defaultdict(int)

    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        pkt_len = len(pkt)

        self.host_bytes[src] += pkt_len
        self.host_bytes[dst] += pkt_len
        self.host_pkts[src] += 1
        self.host_pkts[dst] += 1

        if pkt.haslayer(TCP):
            self.port_bytes[f"TCP/{pkt[TCP].dport}"] += pkt_len
        elif pkt.haslayer(UDP):
            self.port_bytes[f"UDP/{pkt[UDP].dport}"] += pkt_len

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])
        top_n = int(self.options["TOP_N"]["value"] or 10)

        self.host_bytes.clear()
        self.host_pkts.clear()
        self.port_bytes.clear()

        print(f"[*] Measuring network bandwidth across {iface} for {duration} seconds...")

        try:
            sniff(iface=iface, prn=self._on_packet, timeout=duration, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Metering stopped.")

        total_bytes = sum(self.host_bytes.values()) // 2
        total_kbps = (total_bytes * 8 / (max(1, duration) * 1024.0))

        print(f"\n{'='*70}")
        print(f"📊 BANDWIDTH UTILIZATION SUMMARY ({duration}s Window)")
        print(f"   Total Volume: {total_bytes / (1024.0 * 1024.0):.2f} MB | Average Rate: {total_kbps:.2f} KB/s")
        print(f"{'='*70}")
        print(f"{'HOST IP':<24} {'PACKETS':<12} {'BYTES':<16} {'RATE (KB/s)':<14}")
        print(f"{'-'*70}")

        sorted_hosts = sorted(self.host_bytes.items(), key=lambda x: -x[1])[:top_n]
        for host, b in sorted_hosts:
            pkts = self.host_pkts[host]
            kbps = (b * 8 / (duration * 1024.0))
            print(f"{host:<24} {pkts:<12} {b / 1024.0:<15.1f}KB {kbps:<14.2f}")

        print(f"\nTOP PORTS BY VOLUME:")
        for port, b in sorted(self.port_bytes.items(), key=lambda x: -x[1])[:5]:
            print(f"  • {port:<12}: {b / 1024.0:.1f} KB")
        print(f"{'='*70}\n")
