from core.module_base import ModuleBase
from scapy.all import IP, UDP, Raw, send
import time


class SSDPProbePayloadGenerator(ModuleBase):
    """
    SSDP M-SEARCH Discovery Probe Simulator.
    Emits UPnP M-SEARCH discovery query packets to test SSDP reflection sentinels.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET_IP": {"value": "239.255.255.250", "required": True, "desc": "Target SSDP multicast or server IP"},
            "COUNT": {"value": "4", "required": True, "desc": "Number of test probes to send"},
            "INTERVAL": {"value": "0.5", "required": False, "desc": "Interval in seconds between probes"},
        }

    def run(self):
        target = self.options["TARGET_IP"]["value"]
        count = int(self.options["COUNT"]["value"])
        interval = float(self.options["INTERVAL"]["value"] or 0.5)

        print(f"[*] Emitting {count} test SSDP M-SEARCH probes to {target}:1900...")
        ssdp_data = (
            b"M-SEARCH * HTTP/1.1\r\n"
            b"HOST: 239.255.255.250:1900\r\n"
            b"MAN: \"ssdp:discover\"\r\n"
            b"MX: 2\r\n"
            b"ST: ssdp:all\r\n\r\n"
        )

        try:
            for i in range(1, count + 1):
                pkt = IP(dst=target) / UDP(sport=55190, dport=1900) / Raw(load=ssdp_data)
                send(pkt, verbose=0)
                print(f"  [>] Sent SSDP M-SEARCH probe [{i}/{count}] to {target}")
                time.sleep(interval)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SSDP generation interrupted.")
            return

        print(f"[+] SSDP test probes transmitted successfully.")
