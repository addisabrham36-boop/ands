from core.module_base import ModuleBase
from scapy.all import IP, UDP, Raw, send
import time


class NTPMonlistPayloadGenerator(ModuleBase):
    """
    NTP Monlist & Reflection Test Query Payload Generator.
    Emits controlled NTP mode 7 monlist request packets in laboratory environments
    to validate NTP reflection sentinels and SOC DDoS alert rules safely.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET_NTP": {"value": "127.0.0.1", "required": True, "desc": "Target NTP server IP"},
            "COUNT": {"value": "5", "required": True, "desc": "Number of test probe packets to send"},
            "INTERVAL": {"value": "0.4", "required": False, "desc": "Interval in seconds between packets"},
        }

    def run(self):
        target = self.options["TARGET_NTP"]["value"]
        count = int(self.options["COUNT"]["value"])
        interval = float(self.options["INTERVAL"]["value"] or 0.4)

        print(f"[*] Emitting {count} safe NTP monlist audit probes to {target}:123...")
        monlist_payload = b"\x17\x00\x03\x2a" + b"\x00" * 4

        try:
            for i in range(1, count + 1):
                pkt = IP(dst=target) / UDP(sport=54321, dport=123) / Raw(load=monlist_payload)
                send(pkt, verbose=0)
                print(f"  [>] Sent NTP Monlist Probe [{i}/{count}] to {target}")
                time.sleep(interval)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] NTP generation stopped.")
            return

        print(f"[+] NTP probe emission finished.")
