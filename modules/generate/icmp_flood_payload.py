from core.module_base import ModuleBase
from scapy.all import IP, ICMP, Raw, send
import time


class ICMPFloodPayloadGenerator(ModuleBase):
    """
    ICMP Echo Flood & Ping Spike Test Generator.
    Emits controlled ICMP echo request bursts to test pipeline rate tracking,
    modified Z-Score statistical spikes, and Ping of Death sentinels.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target destination IP"},
            "COUNT": {"value": "20", "required": True, "desc": "Number of ICMP packets to send"},
            "SIZE": {"value": "64", "required": False, "desc": "Payload size in bytes"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        count = int(self.options["COUNT"]["value"])
        size = int(self.options["SIZE"]["value"] or 64)

        print(f"[*] Emitting {count} test ICMP echo packets ({size} bytes) to {target}...")
        payload = b"X" * size

        try:
            for i in range(1, count + 1):
                pkt = IP(dst=target) / ICMP(type=8, code=0, id=1337, seq=i) / Raw(load=payload)
                send(pkt, verbose=0)
                time.sleep(0.05)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] ICMP generation stopped.")

        print(f"[+] Transmitted {count} ICMP test packets to {target}.")
