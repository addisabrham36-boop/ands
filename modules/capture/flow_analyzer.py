from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, UDP, ICMP
import time
import collections


class FlowAnalyzer(ModuleBase):
    """
    NetFlow & IPFIX-Style 5-Tuple Network Flow Aggregator.
    Reconstructs bidirectional session flows, measuring packet volumes,
    byte consumption, flow durations, and identifying Top Talkers across the subnet.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "20", "required": True, "desc": "Aggregation duration in seconds"},
            "TOP_N": {"value": "10", "required": True, "desc": "Number of top talkers/flows to display"},
        }
        # (src, sport, dst, dport, proto) -> {"pkts": int, "bytes": int, "start": float, "last": float}
        self.flows = collections.defaultdict(lambda: {"pkts": 0, "bytes": 0, "start": time.time(), "last": time.time()})
        self.host_bytes = collections.defaultdict(int)

    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        length = len(pkt)

        self.host_bytes[src] += length
        self.host_bytes[dst] += length

        proto = "IP"
        sport = 0
        dport = 0

        if pkt.haslayer(TCP):
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif pkt.haslayer(ICMP):
            proto = "ICMP"

        flow_key = (src, sport, dst, dport, proto)
        flow = self.flows[flow_key]
        flow["pkts"] += 1
        flow["bytes"] += length
        flow["last"] = time.time()

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])
        top_n = int(self.options["TOP_N"]["value"])

        self.flows.clear()
        self.host_bytes.clear()

        print(f"[*] Aggregating NetFlow 5-tuples on {iface} for {duration}s...")
        try:
            sniff(iface=iface, prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Flow aggregation interrupted.")

        # Display Top Talkers
        print(f"\n{'='*70}")
        print(f"Top {top_n} Bandwidth Talkers:")
        print(f"{'Rank':<6}{'Host IP':<22}{'Bytes Transferred':<20}{'KB':<12}")
        print("-" * 70)
        sorted_hosts = sorted(self.host_bytes.items(), key=lambda x: x[1], reverse=True)[:top_n]
        for i, (host, b) in enumerate(sorted_hosts, 1):
            print(f"[{i:<2}]  {host:<22}{b:<20}{round(b/1024.0, 1):<12}")

        # Display Top Flows
        print(f"\n{'='*70}")
        print(f"Top {top_n} Network Conversations (5-Tuples):")
        print(f"{'Source':<20}{'Destination':<20}{'Proto':<8}{'Packets':<10}{'KB':<10}")
        print("-" * 70)
        sorted_flows = sorted(self.flows.items(), key=lambda x: x[1]["bytes"], reverse=True)[:top_n]
        for (src, sp, dst, dp, proto), stats in sorted_flows:
            src_str = f"{src}:{sp}" if sp else src
            dst_str = f"{dst}:{dp}" if dp else dst
            kb_str = f"{stats['bytes']/1024.0:.1f} KB"
            print(f"{src_str:<20}{dst_str:<20}{proto:<8}{stats['pkts']:<10}{kb_str:<10}")
        print(f"{'='*70}\n")
