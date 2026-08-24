from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP
import time
import collections
import statistics
from datetime import datetime


class BeaconingDetect(ModuleBase):
    """
    Command & Control (C2) Beaconing & Periodic Heartbeat Sentinel.
    Analyzes inter-packet arrival times (delta intervals) between endpoints,
    identifying low-jitter, strictly periodic outbound communication patterns.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "45", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "MIN_CONNECTIONS": {"value": "5", "required": True, "desc": "Minimum connection occurrences required to test for periodicity"},
            "MAX_JITTER_CV": {"value": "0.20", "required": True, "desc": "Maximum Coefficient of Variation (std/mean) to classify as periodic beacon"},
        }
        # (src, dst, dport) -> list of epoch timestamps
        self.connection_times = collections.defaultdict(list)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        
        # Only track SYN packets (new connection establishment attempts)
        if int(tcp.flags) != 0x02:
            return

        src = ip.src
        dst = ip.dst
        dport = tcp.dport

        if self.session.is_whitelisted(src) or self.session.is_whitelisted(dst):
            return

        flow_key = (src, dst, dport)
        now = time.time()
        self.connection_times[flow_key].append(now)

        min_conn = int(self.options["MIN_CONNECTIONS"]["value"])
        max_cv = float(self.options["MAX_JITTER_CV"]["value"])

        times = self.connection_times[flow_key]
        if len(times) >= min_conn:
            # Compute deltas
            deltas = [times[i] - times[i - 1] for i in range(1, len(times))]
            if not deltas:
                return

            mean_delta = statistics.mean(deltas)
            # Only consider beacons with meaningful interval (e.g. >= 0.5s)
            if mean_delta < 0.5:
                return

            stdev_delta = statistics.stdev(deltas) if len(deltas) > 1 else 0.0
            cv = stdev_delta / mean_delta if mean_delta > 0 else 1.0

            if cv <= max_cv and flow_key not in self.already_alerted:
                self.already_alerted.add(flow_key)
                confidence = min(0.95, 0.65 + (1.0 - cv) * 0.3)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] C2 Beaconing Pattern Detected: {src} -> {dst}:{dport} (Interval: {mean_delta:.2f}s, Jitter CV: {cv:.3f}) [{ts}]")

                self.session.add_alert({
                    "type": "C2_BEACONING",
                    "severity": "HIGH",
                    "confidence": round(confidence, 2),
                    "mitre_id": "T1071",
                    "source": src,
                    "destination": f"{dst}:{dport}",
                    "protocol": "TCP",
                    "description": f"Potential Command & Control (C2) beaconing detected: {src} communicating periodically with {dst}:{dport} every {mean_delta:.2f}s (Jitter CV: {cv:.3f})",
                    "details": {
                        "destination_ip": dst,
                        "destination_port": dport,
                        "mean_interval_sec": round(mean_delta, 2),
                        "stdev_interval_sec": round(stdev_delta, 3),
                        "coefficient_of_variation": round(cv, 3),
                        "total_beacons_seen": len(times),
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.connection_times.clear()
        self.already_alerted.clear()

        print(f"[*] C2 Beaconing Sentinel active on {iface}...")
        try:
            sniff(iface=iface, filter="tcp", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Beaconing monitoring stopped by user.")
            return

        print(f"[+] Beaconing detection complete — {len(self.already_alerted)} beacon flow(s) identified.")
