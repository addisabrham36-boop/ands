from core.module_base import ModuleBase
from scapy.all import IP, TCP, UDP, ICMP, send
import time
import random


class SyntheticTraffic(ModuleBase):
    """
    Multi-Vector Synthetic Traffic & Attack Simulation Engine.
    Generates controlled normal, port scan, SYN flood, UDP burst, or ICMP spike traffic
    for testing detection modules, alert thresholds, and dashboard telemetry in labs.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": session.get_global("TARGET", "127.0.0.1"), "required": True, "desc": "Destination IP for simulation traffic"},
            "TYPE": {"value": "normal", "required": True, "desc": "normal | portscan | synflood | udpflood | icmpspike"},
            "DURATION": {"value": "10", "required": True, "desc": "Simulation duration in seconds"},
            "RATE": {"value": "50", "required": False, "desc": "Approximate packets per second for floods"},
        }

    def _send_normal(self, target, duration):
        print(f"[*] Simulating realistic background network traffic to {target} for {duration}s...")
        end = time.time() + duration
        while time.time() < end:
            choice = random.random()
            if choice < 0.6:
                # HTTP/TLS packet simulation
                send(IP(dst=target) / TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443]), flags="PA") / b"GET / HTTP/1.1\r\nHost: test.local\r\n\r\n", verbose=0)
            elif choice < 0.8:
                # DNS query simulation
                send(IP(dst=target) / UDP(sport=random.randint(1024, 65535), dport=53) / b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", verbose=0)
            else:
                # Ping
                send(IP(dst=target) / ICMP(), verbose=0)
            time.sleep(random.uniform(0.05, 0.2))

    def _send_portscan(self, target, duration):
        print(f"[*] Simulating a multi-port reconnaissance scan against {target}...")
        end = time.time() + duration
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        for port in ports:
            if time.time() >= end:
                break
            send(IP(dst=target) / TCP(dport=port, flags="S"), verbose=0)
            time.sleep(0.05)

    def _send_synflood(self, target, duration, rate):
        print(f"[*] Simulating high-velocity SYN flood burst against {target} for {duration}s...")
        end = time.time() + duration
        delay = 1.0 / max(1, rate)
        while time.time() < end:
            sport = random.randint(1024, 65535)
            send(IP(dst=target) / TCP(sport=sport, dport=80, flags="S"), verbose=0)
            time.sleep(delay)

    def _send_udpflood(self, target, duration, rate):
        print(f"[*] Simulating UDP flood burst against {target} for {duration}s...")
        end = time.time() + duration
        delay = 1.0 / max(1, rate)
        while time.time() < end:
            dport = random.randint(1024, 65535)
            send(IP(dst=target) / UDP(dport=dport) / (b"X" * 128), verbose=0)
            time.sleep(delay)

    def _send_icmpspike(self, target, duration):
        print(f"[*] Simulating high-rate ICMP spike against {target} for {duration}s...")
        end = time.time() + duration
        while time.time() < end:
            send(IP(dst=target) / ICMP() / (b"ANDS_ICMP_SPIKE_" * 4), verbose=0)
            time.sleep(0.02)

    def run(self):
        target = self.options["TARGET"]["value"] or self.session.get_global("TARGET", "127.0.0.1")
        traffic_type = self.options["TYPE"]["value"].lower().strip()
        duration = int(self.options["DURATION"]["value"])
        rate = int(self.options["RATE"]["value"] or 50)

        try:
            if traffic_type == "normal":
                self._send_normal(target, duration)
            elif traffic_type == "portscan":
                self._send_portscan(target, duration)
            elif traffic_type in ("flood", "synflood"):
                self._send_synflood(target, duration, rate)
            elif traffic_type == "udpflood":
                self._send_udpflood(target, duration, rate)
            elif traffic_type == "icmpspike":
                self._send_icmpspike(target, duration)
            else:
                print(f"[-] Unknown TYPE: {traffic_type}. Use normal | portscan | synflood | udpflood | icmpspike.")
                return
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo to transmit raw packets.")
            return
        except KeyboardInterrupt:
            print("\n[*] Synthetic generation stopped by user.")
            return

        print(f"[+] Synthetic traffic simulation complete.")