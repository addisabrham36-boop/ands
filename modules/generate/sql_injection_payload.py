from core.module_base import ModuleBase
from scapy.all import IP, TCP, Raw, send
import time
import urllib.parse


class SQLInjectionPayloadGenerator(ModuleBase):
    """
    SQL Injection Test Payload Generator.
    Emits controlled HTTP requests containing classic SQL injection test strings
    (' OR 1=1--, UNION SELECT, SLEEP(5)) to validate SOC detection rules.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target web server IP"},
            "PORT": {"value": "80", "required": True, "desc": "Destination web server port"},
            "COUNT": {"value": "3", "required": True, "desc": "Number of test payloads to emit"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        port = int(self.options["PORT"]["value"])
        count = int(self.options["COUNT"]["value"])

        payloads = [
            "/api/users?id=1%27+OR+1%3D1--",
            "/search?q=admin%27+UNION+SELECT+1%2Cversion%28%29%2C3--",
            "/login?user=admin%27%3B+WAITFOR+DELAY+%270%3A0%3A5%27--",
        ]

        print(f"[*] Emitting {count} safe SQLi test probes to {target}:{port}...")

        try:
            for i in range(count):
                uri = payloads[i % len(payloads)]
                req = f"GET {uri} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: ANDS-Test-SQLi/2.0\r\n\r\n".encode()
                pkt = IP(dst=target) / TCP(sport=53000 + i, dport=port, flags="PA") / Raw(load=req)
                send(pkt, verbose=0)
                print(f"  [>] Sent SQLi Probe [{i+1}/{count}]: {uri}")
                time.sleep(0.4)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SQLi generation stopped.")
            return

        print(f"[+] SQLi test probe emission completed.")
