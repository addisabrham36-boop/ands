from core.module_base import ModuleBase
from scapy.all import IP, TCP, Raw, send
import time


class XSSTestPayloadGenerator(ModuleBase):
    """
    Cross-Site Scripting (XSS) Probe Generator.
    Emits benign XSS test queries (<script>alert(1)</script>, <svg/onload=alert(1)>)
    to test web application firewall and NIDS detection capabilities.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target web server IP"},
            "PORT": {"value": "80", "required": True, "desc": "Destination web server port"},
            "COUNT": {"value": "3", "required": True, "desc": "Number of test probes to send"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        port = int(self.options["PORT"]["value"])
        count = int(self.options["COUNT"]["value"])

        payloads = [
            "/comment?text=%3Cscript%3Ealert(%27ANDS-TEST%27)%3C%2Fscript%3E",
            "/search?q=%3Csvg+onload%3Dalert(1)%3E",
            "/profile?name=%3Ciframe+src%3Djavascript%3Aalert(1)%3E",
        ]

        print(f"[*] Emitting {count} safe XSS test probes to {target}:{port}...")

        try:
            for i in range(count):
                uri = payloads[i % len(payloads)]
                req = f"GET {uri} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: ANDS-Test-XSS/2.0\r\n\r\n".encode()
                pkt = IP(dst=target) / TCP(sport=53100 + i, dport=port, flags="PA") / Raw(load=req)
                send(pkt, verbose=0)
                print(f"  [>] Sent XSS Probe [{i+1}/{count}]: {uri}")
                time.sleep(0.4)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] XSS generation stopped.")
            return

        print(f"[+] XSS probe emission finished.")
