from core.module_base import ModuleBase
from scapy.all import IP, UDP, Raw, send
import time


class MemcachedTestPayloadGenerator(ModuleBase):
    """
    Memcached UDP Stats Query Generator.
    Emits controlled Memcached 'stats' query packets to UDP port 11211 to test
    Memcached reflective amplification sentinels in safe lab environments.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target Memcached server IP"},
            "COUNT": {"value": "4", "required": True, "desc": "Number of test packets to send"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        count = int(self.options["COUNT"]["value"])

        print(f"[*] Emitting {count} test Memcached queries to {target}:11211...")
        memcached_req = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"

        try:
            for i in range(1, count + 1):
                pkt = IP(dst=target) / UDP(sport=51211, dport=11211) / Raw(load=memcached_req)
                send(pkt, verbose=0)
                print(f"  [>] Sent Memcached Test Query [{i}/{count}]")
                time.sleep(0.4)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Generation stopped.")

        print(f"[+] Memcached test probe emission finished.")
