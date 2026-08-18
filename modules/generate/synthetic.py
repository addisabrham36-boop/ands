from core.module_base import ModuleBase
from scapy.all import IP, TCP, ICMP, send
import time
import random


class SyntheticTraffic(ModuleBase):
    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "", "required": True, "desc": "Destination IP for synthetic traffic (e.g. 192.168.56.101)"},
            "TYPE": {"value": "normal", "required": True, "desc": "normal | portscan | flood"},
            "DURATION": {"value": "10", "required": True, "desc": "Duration in seconds"},
        }

    def _send_normal(self, target, duration):
        print(f"[*] Sending normal-looking traffic to {target} for {duration}s...")
        end = time.time() + duration
        while time.time() < end:
            send(IP(dst=target) / ICMP(), verbose=0)
            time.sleep(random.uniform(0.3, 0.8))

    def _send_portscan(self, target, duration):
        print(f"[*] Simulating a port scan against {target} for {duration}s...")
        end = time.time() + duration
        port = 1
        while time.time() < end and port <= 1000:
            send(IP(dst=target) / TCP(dport=port, flags="S"), verbose=0)
            port += random.randint(1, 5)
            time.sleep(0.02)

    def _send_flood(self, target, duration):
        print(f"[*] Simulating a SYN flood burst against {target} for {duration}s...")
        end = time.time() + duration
        while time.time() < end:
            send(IP(dst=target) / TCP(dport=80, flags="S"), verbose=0)

    def run(self):
        target = self.options["TARGET"]["value"]
        traffic_type = self.options["TYPE"]["value"]
        duration = int(self.options["DURATION"]["value"])

        if not target:
            print("[-] TARGET is required.")
            return

        try:
            if traffic_type == "normal":
                self._send_normal(target, duration)
            elif traffic_type == "portscan":
                self._send_portscan(target, duration)
            elif traffic_type == "flood":
                self._send_flood(target, duration)
            else:
                print(f"[-] Unknown TYPE: {traffic_type}. Use normal | portscan | flood.")
                return
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo to send raw packets.")
            return
        except OSError as e:
            print(f"[-] Network error: {e}")
            return
        except KeyboardInterrupt:
            print("\n[*] Synthetic traffic interrupted by user.")
            return

        print(f"[+] Synthetic traffic complete.")
        