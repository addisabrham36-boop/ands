from core.module_base import ModuleBase
from scapy.all import IP, UDP, DNS, DNSQR, send
import time
import random
import string


class DGATestPayloadGenerator(ModuleBase):
    """
    Synthetic DGA Domain Query Generator.
    Generates high-entropy pseudo-random domain queries to validate DGA malware
    detection rules and DNS sentinels in safe lab environments.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "DNS_SERVER": {"value": "127.0.0.1", "required": True, "desc": "Target DNS server IP"},
            "COUNT": {"value": "5", "required": True, "desc": "Number of DGA queries to emit"},
            "TLD": {"value": "com", "required": False, "desc": "Top-level domain suffix"},
        }

    def _generate_random_domain(self, length=16, tld="com") -> str:
        consonants = "bcdfghjklmnpqrstvwxyz"
        stem = "".join(random.choice(consonants) for _ in range(length))
        return f"{stem}.{tld}"

    def run(self):
        dns_server = self.options["DNS_SERVER"]["value"]
        count = int(self.options["COUNT"]["value"])
        tld = self.options["TLD"]["value"] or "com"

        print(f"[*] Emitting {count} synthetic DGA domain queries to {dns_server}:53...")

        try:
            for i in range(1, count + 1):
                dga_name = self._generate_random_domain(length=random.randint(14, 20), tld=tld)
                pkt = IP(dst=dns_server) / UDP(sport=random.randint(40000, 60000), dport=53) / DNS(rd=1, qd=DNSQR(qname=dga_name))
                send(pkt, verbose=0)
                print(f"  [>] Transmitted DGA query [{i}/{count}]: {dga_name}")
                time.sleep(0.3)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] DGA generation stopped.")
            return

        print(f"[+] DGA test query emission complete.")
