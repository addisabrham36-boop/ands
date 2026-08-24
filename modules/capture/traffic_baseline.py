from core.module_base import ModuleBase
from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP, ICMP
from core.spinner import Spinner
import time
import json
import os
import statistics


class TrafficBaseline(ModuleBase):
    """
    Multi-Dimensional Network Behavioral Baseline Generator.
    Extracts rolling packet rates, byte rates, protocol distributions,
    and statistical moments (mean, median, stdev, MAD) for anomaly modeling.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to capture on"},
            "DURATION": {"value": "20", "required": True, "desc": "Capture duration in seconds"},
            "FILTER": {"value": "", "required": False, "desc": "Optional BPF filter (e.g. 'ip')"},
            "WINDOW": {"value": "2", "required": True, "desc": "Feature time window size in seconds"},
            "PCAP_OUT": {"value": "data/captures/baseline.pcap", "required": False, "desc": "Save captured packets to this .pcap file"},
            "PCAP_IN": {"value": "", "required": False, "desc": "Read from this .pcap file instead of live capture"},
            "OUTPUT_PROFILE": {"value": "data/baseline_profiles/latest.json", "required": True, "desc": "Baseline JSON destination path"},
        }
        self.packets = []

    def _on_packet(self, pkt):
        self.packets.append(pkt)

    def _extract_features(self, packets, window_size):
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
            tcp_cnt = sum(1 for p in bucket_pkts if p.haslayer(TCP))
            udp_cnt = sum(1 for p in bucket_pkts if p.haslayer(UDP))
            icmp_cnt = sum(1 for p in bucket_pkts if p.haslayer(ICMP))
            total_bytes = sum(len(p) for p in bucket_pkts)

            features.append({
                "window": idx,
                "packet_count": len(bucket_pkts),
                "packet_rate": len(bucket_pkts) / window_size,
                "byte_rate_kbps": (total_bytes * 8 / 1024.0) / window_size,
                "avg_size": total_bytes / len(bucket_pkts),
                "tcp_ratio": round(tcp_cnt / len(bucket_pkts), 2),
                "udp_ratio": round(udp_cnt / len(bucket_pkts), 2),
                "icmp_ratio": round(icmp_cnt / len(bucket_pkts), 2),
            })
        return features

    def run(self):
        pcap_in = self.options["PCAP_IN"]["value"]
        window = float(self.options["WINDOW"]["value"])
        out_profile = self.options["OUTPUT_PROFILE"]["value"]

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
            iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
            duration = int(self.options["DURATION"]["value"])
            bpf_filter = self.options["FILTER"]["value"] or None

            self.packets = []
            print(f"[*] Profiling baseline on {iface} for {duration}s...")
            spinner = Spinner(["Sampling wire traffic...", "Computing distribution vectors...", "Profiling statistical norms..."])
            elapsed = 0
            try:
                spinner.start()
                start = time.time()
                sniff(iface=iface, filter=bpf_filter, prn=self._on_packet, timeout=duration)
                elapsed = time.time() - start
            except PermissionError:
                spinner.stop()
                print("[-] Permission denied. Run ANDS with sudo.")
                return
            except OSError as e:
                spinner.stop()
                print(f"[-] Interface error: {e}")
                return
            except KeyboardInterrupt:
                spinner.stop()
                print("\n[*] Baseline capture interrupted.")
                return
            finally:
                spinner.stop()

            print(f"[+] Baseline capture complete: {len(self.packets)} packets in {elapsed:.1f}s")

        pcap_out = self.options["PCAP_OUT"]["value"]
        if pcap_out and self.packets:
            try:
                os.makedirs(os.path.dirname(pcap_out) or ".", exist_ok=True)
                wrpcap(pcap_out, self.packets)
                print(f"[+] Saved raw capture to {pcap_out}")
                self.session.artifacts["baseline_pcap"] = pcap_out
            except Exception as e:
                print(f"[-] Failed to write pcap: {e}")

        features = self._extract_features(self.packets, window)
        if features:
            rates = [f["packet_rate"] for f in features]
            mean_r = statistics.mean(rates)
            stdev_r = statistics.stdev(rates) if len(rates) > 1 else 0.0
            med_r = statistics.median(rates)

            profile_payload = {
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "interface": self.options["INTERFACE"]["value"],
                "total_packets": len(self.packets),
                "windows_count": len(features),
                "summary": {
                    "mean_rate_pps": round(mean_r, 2),
                    "stdev_rate_pps": round(stdev_r, 2),
                    "median_rate_pps": round(med_r, 2),
                },
                "windows": features,
            }

            try:
                os.makedirs(os.path.dirname(out_profile) or ".", exist_ok=True)
                with open(out_profile, "w") as f:
                    json.dump(features, f, indent=2)
                print(f"[+] Profile saved: {out_profile} ({len(features)} windows | Mean: {mean_r:.2f} pps)")
                self.session.artifacts["baseline_json"] = out_profile
            except Exception as e:
                print(f"[-] Failed to write baseline JSON: {e}")
        else:
            print("[-] No packets captured — baseline not generated.")