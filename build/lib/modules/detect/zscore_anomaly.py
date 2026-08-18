from core.module_base import ModuleBase
import json
import os
import statistics


class ZScoreAnomaly(ModuleBase):
    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "BASELINE": {"value": "data/baseline_profiles/latest.json", "required": True, "desc": "Path to baseline JSON produced by capture/baseline"},
            "THRESHOLD": {"value": "3.0", "required": True, "desc": "Z-score threshold above which a window is flagged"},
        }

    def _zscore(self, value, mean, stdev):
        if stdev == 0:
            return 0.0
        return (value - mean) / stdev

    def run(self):
        path = self.options["BASELINE"]["value"]
        threshold = float(self.options["THRESHOLD"]["value"])

        if not os.path.exists(path):
            print(f"[-] Baseline file not found: {path}")
            print("[*] Run capture/baseline first.")
            return

        with open(path) as f:
            features = json.load(f)

        if len(features) < 2:
            print("[-] Not enough windows to compute a baseline (need at least 2).")
            return

        rates = [w["packet_rate"] for w in features]
        mean_rate = statistics.mean(rates)
        stdev_rate = statistics.stdev(rates)

        print(f"[*] Baseline: mean={mean_rate:.2f} pkt/s, stdev={stdev_rate:.2f}")
        print(f"[*] Threshold: z >= {threshold}\n")

        alerts = 0
        for w in features:
            z = self._zscore(w["packet_rate"], mean_rate, stdev_rate)
            if abs(z) >= threshold:
                alerts += 1
                print(f"[ALERT] window {w['window']}  rate={w['packet_rate']:.2f} pkt/s  [z-score: {z:.2f}]")
                self.session.add_alert({
                    "type": "ANOMALY",
                    "window": w["window"],
                    "zscore": round(z, 2),
                    "rate": w["packet_rate"],
                })

        print(f"\n[+] Scan complete — {alerts} alert(s) across {len(features)} windows")