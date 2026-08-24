from core.module_base import ModuleBase
from scapy.all import IP, TCP, Raw, send
import time
import random


class HTTPBenchPayloadGenerator(ModuleBase):
    """
    High-Throughput HTTP Burst & Volumetric Benchmark Generator.
    Emits simulated HTTP GET requests to test pipeline throughput, baseline
    rate computation, and volumetric anomaly detection in lab environments.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target web server IP"},
            "PORT": {"value": "80", "required": True, "desc": "Destination web server port"},
            "DURATION": {"value": "10", "required": True, "desc": "Burst duration in seconds"},
            "RATE": {"value": "100", "required": False, "desc": "Target packets per second"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        port = int(self.options["PORT"]["value"])
        duration = int(self.options["DURATION"]["value"])
        rate = int(self.options["RATE"]["value"] or 100)
        delay = 1.0 / max(1, rate)

        print(f"[*] Emitting HTTP request benchmark burst to {target}:{port} for {duration}s (~{rate} pps)...")
        end = time.time() + duration
        sent = 0

        try:
            while time.time() < end:
                sport = random.randint(1024, 65535)
                req_data = f"GET /api/test?seq={sent} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: ANDS-Bench/2.0\r\n\r\n".encode()
                pkt = IP(dst=target) / TCP(sport=sport, dport=port, flags="PA") / Raw(load=req_data)
                send(pkt, verbose=0)
                sent += 1
                time.sleep(delay)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Benchmark generation halted.")
            return

        print(f"[+] Benchmark finished — transmitted {sent} HTTP request packets.")
