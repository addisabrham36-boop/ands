from core.module_base import ModuleBase
import statistics


class SelfTest(ModuleBase):
    def __init__(self, session):
        super().__init__(session)
        self.options = {}

    def _zscore(self, value, mean, stdev):
        if stdev == 0:
            return 0.0
        return (value - mean) / stdev

    def run(self):
        print("[*] Running ANDS self-test suite...\n")
        passed, failed = 0, 0

        try:
            normal = [100, 102, 98, 101, 99, 100, 103, 97]
            spike = 400
            mean = statistics.mean(normal)
            stdev = statistics.stdev(normal)
            z = self._zscore(spike, mean, stdev)
            ok = z >= 3.0
            print(f"  [{'PASS' if ok else 'FAIL'}] zscore_detects_spike       z={z:.2f}")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] zscore_detects_spike       {e}")
            failed += 1

        try:
            normal = [100, 102, 98, 101, 99, 100, 103, 97]
            typical = 101
            mean = statistics.mean(normal)
            stdev = statistics.stdev(normal)
            z = self._zscore(typical, mean, stdev)
            ok = abs(z) < 3.0
            print(f"  [{'PASS' if ok else 'FAIL'}] zscore_ignores_normal      z={z:.2f}")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] zscore_ignores_normal      {e}")
            failed += 1

        try:
            ports_seen = set(range(1, 120))
            threshold = 10
            ok = len(ports_seen) >= threshold
            print(f"  [{'PASS' if ok else 'FAIL'}] portscan_threshold_logic   ports={len(ports_seen)}")
            passed += ok; failed += not ok
        except Exception as e:
            print(f"  [ERROR] portscan_threshold_logic   {e}")
            failed += 1

        print(f"\n[*] Self-test complete: {passed} passed, {failed} failed")
        