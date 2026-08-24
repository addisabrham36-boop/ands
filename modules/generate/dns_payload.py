from core.module_base import ModuleBase
from scapy.all import IP, UDP, DNS, DNSQR, send
import base64
import time
import random


class DNSPayloadGenerator(ModuleBase):
    """
    DNS Tunneling & Data Exfiltration Test Payload Generator.
    Generates encoded, high-entropy DNS queries to test detection rules,
    validate SOC alert pipelines, and verify exfiltration sentinels safely.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET_DNS": {"value": "127.0.0.1", "required": True, "desc": "Target DNS server or gateway IP"},
            "DOMAIN": {"value": "tunnel.lab.local", "required": True, "desc": "Base domain suffix"},
            "COUNT": {"value": "10", "required": True, "desc": "Number of test tunneling queries to emit"},
            "INTERVAL": {"value": "0.3", "required": False, "desc": "Interval between queries in seconds"},
        }

    def run(self):
        target = self.options["TARGET_DNS"]["value"]
        domain = self.options["DOMAIN"]["value"]
        count = int(self.options["COUNT"]["value"])
        interval = float(self.options["INTERVAL"]["value"] or 0.3)

        print(f"[*] Emitting {count} simulated DNS tunneling test payloads to {target} ({domain})...")
        try:
            for i in range(1, count + 1):
                # Generate high-entropy chunk
                rand_bytes = bytes([random.randint(0, 255) for _ in range(24)])
                encoded_chunk = base64.b32encode(rand_bytes).decode("ascii").lower().rstrip("=")
                qname = f"{encoded_chunk}.chunk{i}.{domain}"

                pkt = IP(dst=target) / UDP(sport=random.randint(1024, 65535), dport=53) / DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
                send(pkt, verbose=0)
                print(f"  [>] Sent TXT probe: {qname}")
                time.sleep(interval)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] DNS test generation cancelled.")
            return

        print(f"[+] DNS payload emission complete.")
