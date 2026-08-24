from core.module_base import ModuleBase
from scapy.all import IP, TCP, send
import time
import random


class C2BeaconPayloadGenerator(ModuleBase):
    """
    Periodic C2 Beaconing & Heartbeat Simulation Payload Generator.
    Emits periodic outbound connection attempts with configurable timing jitter
    to validate C2 beaconing detection algorithms and SOC timeline visualizations.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET_C2": {"value": "127.0.0.1", "required": True, "desc": "Simulated C2 destination IP"},
            "PORT": {"value": "4444", "required": True, "desc": "Destination C2 listener port"},
            "INTERVAL": {"value": "2.0", "required": True, "desc": "Base beacon period in seconds"},
            "JITTER_PERCENT": {"value": "5", "required": False, "desc": "Timing jitter percentage (0 to 50%)"},
            "COUNT": {"value": "8", "required": True, "desc": "Number of beacon heartbeats to transmit"},
        }

    def run(self):
        target = self.options["TARGET_C2"]["value"]
        port = int(self.options["PORT"]["value"])
        base_interval = float(self.options["INTERVAL"]["value"])
        jitter_pct = float(self.options["JITTER_PERCENT"]["value"] or 5) / 100.0
        count = int(self.options["COUNT"]["value"])

        print(f"[*] Emitting {count} simulated C2 beacons to {target}:{port} (interval: {base_interval}s, jitter: {jitter_pct*100:.0f}%)...")
        try:
            for i in range(1, count + 1):
                sport = random.randint(1024, 65535)
                pkt = IP(dst=target) / TCP(sport=sport, dport=port, flags="S")
                send(pkt, verbose=0)
                print(f"  [>] Sent C2 Beacon heartbeat [{i}/{count}] to {target}:{port}")

                if i < count:
                    # Apply jitter
                    actual_sleep = base_interval + random.uniform(-base_interval * jitter_pct, base_interval * jitter_pct)
                    time.sleep(max(0.1, actual_sleep))
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] C2 beacon simulation cancelled.")
            return

        print(f"[+] C2 beacon emission complete.")
