from core.module_base import ModuleBase
from scapy.all import IP, TCP, Raw, send
import time


class PathTraversalPayloadGenerator(ModuleBase):
    """
    Path Traversal & Arbitrary File Access Test Generator.
    Emits simulated directory traversal requests (../../../../etc/passwd, %2e%2e%2f)
    to test web application firewall and NIDS sentinel detection rules.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target web server IP"},
            "PORT": {"value": "80", "required": True, "desc": "Target web server port"},
            "COUNT": {"value": "3", "required": True, "desc": "Number of test probes to send"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        port = int(self.options["PORT"]["value"])
        count = int(self.options["COUNT"]["value"])

        probes = [
            "/view?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "/download?path=..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",
            "/api/read?doc=%2e%2e%2f%2e%2e%2fetc%2fshadow",
        ]

        print(f"[*] Emitting {count} safe path traversal test probes to {target}:{port}...")

        try:
            for i in range(count):
                uri = probes[i % len(probes)]
                req = f"GET {uri} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: ANDS-Test-Traversal/2.0\r\n\r\n".encode()
                pkt = IP(dst=target) / TCP(sport=53200 + i, dport=port, flags="PA") / Raw(load=req)
                send(pkt, verbose=0)
                print(f"  [>] Sent Path Traversal Probe [{i+1}/{count}]: {uri}")
                time.sleep(0.4)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Traversal generation stopped.")

        print(f"[+] Path traversal probe emission finished.")
