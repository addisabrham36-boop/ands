from core.module_base import ModuleBase
import statistics
from core.statistics import zscore, median_absolute_deviation, modified_zscore, calculate_shannon_entropy, exponential_moving_average


class SelfTest(ModuleBase):
    """
    ANDS Detection Engine & Mathematical Self-Test Suite.
    Runs comprehensive unit checks validating statistical algorithms, entropy formulas,
    false-positive suppression logic, and detection math against known ground-truth vectors.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {}

    def run(self):
        print("[*] Running ANDS Deep Self-Test Suite...\n")
        passed, failed = 0, 0

        # Test 1: Standard Z-Score spike
        try:
            normal = [100, 102, 98, 101, 99, 100, 103, 97]
            spike = 400
            mean = statistics.mean(normal)
            stdev = statistics.stdev(normal)
            z = zscore(spike, mean, stdev)
            ok = z >= 3.0
            print(f"  [{'PASS' if ok else 'FAIL'}] zscore_spike_detection         z={z:.2f}")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] zscore_spike_detection         {e}")
            failed += 1

        # Test 2: Standard Z-Score normal
        try:
            normal = [100, 102, 98, 101, 99, 100, 103, 97]
            typical = 101
            mean = statistics.mean(normal)
            stdev = statistics.stdev(normal)
            z = zscore(typical, mean, stdev)
            ok = abs(z) < 3.0
            print(f"  [{'PASS' if ok else 'FAIL'}] zscore_normal_rejection         z={z:.2f}")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] zscore_normal_rejection        {e}")
            failed += 1

        # Test 3: Median Absolute Deviation (MAD) & Modified Z-Score
        try:
            data = [10, 12, 11, 10, 10, 11, 12, 10]
            med, mad = median_absolute_deviation(data)
            mod_z_spike = modified_zscore(100, med, mad)
            mod_z_norm = modified_zscore(11, med, mad)
            ok = mod_z_spike > 3.5 and mod_z_norm < 1.0
            print(f"  [{'PASS' if ok else 'FAIL'}] mad_modified_zscore_robustness  spike_mod_z={mod_z_spike:.2f}")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] mad_modified_zscore_robustness {e}")
            failed += 1

        # Test 4: Shannon Entropy on DNS tunneling payload
        try:
            normal_domain = "google.com"
            tunnel_subdomain = "a3f89c49d8e12b7a9f0c2e4d"
            ent_norm = calculate_shannon_entropy(normal_domain)
            ent_tunnel = calculate_shannon_entropy(tunnel_subdomain)
            ok = ent_tunnel > 3.4 and ent_norm < 3.0
            print(f"  [{'PASS' if ok else 'FAIL'}] shannon_entropy_exfiltration    tunnel_H={ent_tunnel:.2f} norm_H={ent_norm:.2f}")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] shannon_entropy_exfiltration   {e}")
            failed += 1

        # Test 5: Exponential Moving Average (EMA) adaptation
        try:
            ema_prev = 10.0
            ema_new = exponential_moving_average(ema_prev, 20.0, alpha=0.2)
            ok = abs(ema_new - 12.0) < 1e-4
            print(f"  [{'PASS' if ok else 'FAIL'}] ema_baseline_smoothing         ema={ema_new:.2f}")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] ema_baseline_smoothing         {e}")
            failed += 1

        # Test 6: Whitelist filter check in session
        try:
            self.session.add_whitelist("10.0.0.99")
            ok = self.session.is_whitelisted("10.0.0.99") and not self.session.is_whitelisted("192.168.1.55")
            print(f"  [{'PASS' if ok else 'FAIL'}] whitelist_suppression_engine  whitelisted=True")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] whitelist_suppression_engine   {e}")
            failed += 1

        print(f"\n[*] Self-test suite results: {passed} PASSED, {failed} FAILED")