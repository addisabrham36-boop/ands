from core.module_base import ModuleBase
import json
import os
import time
import collections
import statistics
from datetime import datetime
from scapy.all import sniff
from core.statistics import zscore, median_absolute_deviation, modified_zscore, exponential_moving_average


class ZScoreAnomaly(ModuleBase):
    """
    Real-Time Sliding Window & Baseline Statistical Anomaly Detector.
    Uses standard Z-Score and robust Median Absolute Deviation (MAD)
    to flag abnormal traffic spikes, data surges, and volumetric anomalies.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "MODE": {"value": "live", "required": True, "desc": "live (monitor interface) or offline (analyze baseline JSON)"},
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": False, "desc": "Network interface for live mode"},
            "DURATION": {"value": "30", "required": False, "desc": "Live monitoring duration in seconds (0 = continuous)"},
            "WINDOW": {"value": "2", "required": True, "desc": "Sliding analysis window size in seconds"},
            "BASELINE": {"value": "data/baseline_profiles/latest.json", "required": False, "desc": "Path to baseline JSON for offline comparison"},
            "THRESHOLD": {"value": "3.5", "required": True, "desc": "Modified Z-Score / MAD threshold to trigger an alert"},
        }
        self.window_packets = 0
        self.window_bytes = 0
        self.history = collections.deque(maxlen=60)
        self.baseline_median = 10.0
        self.baseline_mad = 2.0

    def _on_packet(self, pkt):
        self.window_packets += 1
        self.window_bytes += len(pkt)

    def _run_live(self, iface, duration, window, threshold):
        print(f"[*] Starting Live Statistical Anomaly Sentinel on {iface} (window: {window}s, threshold: z >= {threshold})...")
        start_time = time.time()
        next_eval = start_time + window
        alerts_count = 0

        # Pre-seed baseline with small initial buffer if empty
        if not self.history:
            self.history.extend([10.0, 12.0, 11.0, 9.0, 10.5])

        def stop_check(pkt):
            nonlocal next_eval, alerts_count
            now = time.time()
            if duration > 0 and (now - start_time) >= duration:
                return True

            if now >= next_eval:
                pps = self.window_packets / window
                bps = (self.window_bytes * 8) / window
                self.window_packets = 0
                self.window_bytes = 0
                next_eval = now + window

                self.history.append(pps)
                med, mad = median_absolute_deviation(list(self.history))
                self.baseline_median = exponential_moving_average(self.baseline_median, med, 0.2)
                self.baseline_mad = max(0.5, exponential_moving_average(self.baseline_mad, max(mad, 1.0), 0.2))

                mod_z = modified_zscore(pps, self.baseline_median, self.baseline_mad)
                
                # Check for volumetric spike
                if mod_z >= threshold and pps > 20:
                    alerts_count += 1
                    conf = min(0.99, 0.6 + (mod_z / 10.0))
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"[ALERT] Statistical Anomaly! Rate: {pps:.1f} pkt/s | Base Median: {self.baseline_median:.1f} | Mod-Z: {mod_z:.2f} [{ts}]")
                    self.session.add_alert({
                        "type": "STATISTICAL_ANOMALY",
                        "severity": "HIGH" if mod_z > 5.0 else "MEDIUM",
                        "confidence": round(conf, 2),
                        "mitre_id": "T1498",
                        "source": "NETWORK_STREAM",
                        "destination": iface,
                        "protocol": "IP",
                        "description": f"Statistical volumetric anomaly detected on {iface}: {pps:.1f} pkt/s (Modified Z-score: {mod_z:.2f})",
                        "details": {
                            "packet_rate_pps": round(pps, 2),
                            "byte_rate_kbps": round(bps / 1024.0, 2),
                            "baseline_median": round(self.baseline_median, 2),
                            "baseline_mad": round(self.baseline_mad, 2),
                            "modified_zscore": round(mod_z, 2),
                        }
                    })
            return False

        try:
            sniff(iface=iface, prn=self._on_packet, stop_filter=stop_check, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
        except KeyboardInterrupt:
            print("\n[*] Live statistical anomaly monitoring halted.")

        print(f"[+] Live analysis completed — {alerts_count} anomaly alert(s) recorded.")

    def _run_offline(self, path, threshold):
        if not os.path.exists(path):
            print(f"[-] Baseline file not found: {path}")
            return

        with open(path) as f:
            features = json.load(f)

        if len(features) < 2:
            print("[-] Baseline must contain at least 2 time windows.")
            return

        rates = [w["packet_rate"] for w in features]
        mean_rate = statistics.mean(rates)
        stdev_rate = statistics.stdev(rates) if len(rates) > 1 else 0.0
        med_rate, mad_rate = median_absolute_deviation(rates)

        print(f"[*] Analyzing profile ({len(features)} windows):")
        print(f"    Mean: {mean_rate:.2f} pkt/s | StDev: {stdev_rate:.2f}")
        print(f"    Median: {med_rate:.2f} pkt/s | MAD: {mad_rate:.2f}")
        print(f"[*] Anomaly Threshold: |Z| >= {threshold}\n")

        alerts = 0
        for w in features:
            rate = w["packet_rate"]
            z = zscore(rate, mean_rate, stdev_rate)
            mod_z = modified_zscore(rate, med_rate, mad_rate)

            if abs(mod_z) >= threshold:
                alerts += 1
                print(f"[ALERT] Window {w['window']:<3} | Rate: {rate:<7.2f} pkt/s | Z-Score: {z:<5.2f} | Mod-Z: {mod_z:<5.2f}")
                self.session.add_alert({
                    "type": "OFFLINE_ANOMALY",
                    "severity": "HIGH" if abs(mod_z) > 5.0 else "MEDIUM",
                    "confidence": round(min(0.95, 0.5 + abs(mod_z) / 10.0), 2),
                    "mitre_id": "T1498",
                    "source": f"WINDOW_{w['window']}",
                    "destination": "BASELINE",
                    "protocol": "IP",
                    "description": f"Statistical outlier in window {w['window']}: {rate:.2f} pkt/s (Mod-Z: {mod_z:.2f})",
                    "details": {
                        "window": w["window"],
                        "rate": rate,
                        "zscore": round(z, 2),
                        "modified_zscore": round(mod_z, 2),
                    }
                })

        print(f"\n[+] Analysis complete — {alerts} anomaly window(s) flagged out of {len(features)} total windows.")

    def run(self):
        mode = self.options["MODE"]["value"].lower().strip()
        threshold = float(self.options["THRESHOLD"]["value"])

        if mode == "live":
            iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
            duration = int(self.options["DURATION"]["value"] or 30)
            window = float(self.options["WINDOW"]["value"] or 2)
            self._run_live(iface, duration, window, threshold)
        elif mode == "offline":
            path = self.options["BASELINE"]["value"]
            self._run_offline(path, threshold)
        else:
            print(f"[-] Invalid MODE: '{mode}'. Use 'live' or 'offline'.")