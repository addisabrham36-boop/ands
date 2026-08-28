from core.module_base import ModuleBase
from scapy.all import IP, TCP, Raw, send
import time


class TelnetTestPayloadGenerator(ModuleBase):
    """
    Simulated Telnet Insecure Protocol Traffic Generator.
    Emits simulated Telnet command negotiation frames to test insecure protocol
    auditing rules and compliance sentinels in safe lab environments.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target server IP"},
            "COUNT": {"value": "3", "required": True, "desc": "Number of test probes to send"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        count = int(self.options["COUNT"]["value"])

        print(f"[*] Emitting {count} test Telnet probe frames to {target}:23...")
        telnet_data = b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27"

        try:
            for i in range(1, count + 1):
                pkt = IP(dst=target) / TCP(sport=52300 + i, dport=23, flags="PA") / Raw(load=telnet_data)
                send(pkt, verbose=0)
                print(f"  [>] Sent Telnet probe #{i} to {target}:23")
                time.sleep(0.3)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Telnet generation stopped.")

        print(f"[+] Telnet probe emission finished.")
