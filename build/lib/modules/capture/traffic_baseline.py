from core.module_base import ModuleBase
from scapy.all import sniff, wrpcap, rdpcap
from core.spinner import Spinner
import time
import json
import os


class TrafficBaseline(ModuleBase):
    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": "", "required": True, "desc": "Network interface to capture on (e.g. eth0)"},
            "DURATION": {"value": "10", "required": True, "desc": "Capture duration in seconds"},
            "FILTER": {"value": "", "required": False, "desc": "BPF filter, e.g. 'tcp or icmp'"},
            "WINDOW": {"value": "5", "required": True, "desc": "Feature window size in seconds"},
            "PCAP_OUT": {"value": "", "required": False, "desc": "Save captured packets to this .pcap file"},
            "PCAP_IN": {"value": "", "required": False, "desc": "Read from this .pcap file instead of live capture"},
        }
        self.packets = []

    def _on_packet(self, pkt):
        self.packets.append(pkt)

    def _extract_features(self, packets, window_size):
        """Bucket packets into time windows, compute packet rate per window."""
        if not packets:
            return []

        start_time = float(packets[0].time)
        buckets = {}
        for pkt in packets:
            bucket_idx = int((float(pkt.time) - start_time) // window_size)
            buckets.setdefault(bucket_idx, []).append(pkt)

        features = []
        for idx in sorted(buckets.keys()):
            bucket_pkts = buckets[idx]
            features.append({
                "window": idx,
                "packet_count": len(bucket_pkts),
                "packet_rate": len(bucket_pkts) / window_size,
                "avg_size": sum(len(p) for p in bucket_pkts) / len(bucket_pkts),
            })
        return features

    def run(self):
        pcap_in = self.options["PCAP_IN"]["value"]
        window = int(self.options["WINDOW"]["value"])

        if pcap_in:
            if not os.path.exists(pcap_in):
                print(f"[-] File not found: {pcap_in}")
                return
            try:
                print(f"[*] Reading from {pcap_in}...")
                self.packets = rdpcap(pcap_in)
                print(f"[+] Loaded {len(self.packets)} packets")
            except Exception as e:
                print(f"[-] Failed to read pcap: {e}")
                return
        else:
            iface = self.options["INTERFACE"]["value"]
            duration = int(self.options["DURATION"]["value"])
            bpf_filter = self.options["FILTER"]["value"] or None

            self.packets = []
            print(f"[*] Capturing on {iface} for {duration}s...")
            spinner = Spinner(["Sniffing the wire...", "Counting packets like sheep...", "Watching traffic go by..."])
            elapsed = 0
            try:
                spinner.start()
                start = time.time()
                sniff(iface=iface, filter=bpf_filter, prn=self._on_packet, timeout=duration)
                elapsed = time.time() - start
            except PermissionError:
                spinner.stop()
                print("[-] Permission denied. Run ANDS with sudo to capture packets.")
                return
            except OSError as e:
                spinner.stop()
                print(f"[-] Interface error: {e}. Check the interface name with 'ip a'.")
                return
            except KeyboardInterrupt:
                spinner.stop()
                print("\n[*] Capture interrupted by user.")
                return
            finally:
                spinner.stop()
            print(f"[+] Capture complete: {len(self.packets)} packets in {elapsed:.1f}s")

        pcap_out = self.options["PCAP_OUT"]["value"]
        if pcap_out and self.packets:
            try:
                os.makedirs(os.path.dirname(pcap_out), exist_ok=True)
                wrpcap(pcap_out, self.packets)
                print(f"[+] Saved capture to {pcap_out}")
                self.session.artifacts["pcap"] = pcap_out
            except Exception as e:
                print(f"[-] Failed to save pcap: {e}")

        features = self._extract_features(self.packets, window)
        if features:
            try:
                os.makedirs("data/baseline_profiles", exist_ok=True)
                baseline_path = "data/baseline_profiles/latest.json"
                with open(baseline_path, "w") as f:
                    json.dump(features, f, indent=2)
                print(f"[+] Baseline saved to {baseline_path} ({len(features)} windows)")
            except Exception as e:
                print(f"[-] Failed to save baseline: {e}")
        else:
            print("[-] No packets captured — no baseline generated.")