from core.module_base import ModuleBase
from scapy.all import IP, UDP, Raw, send
import time


class SNMPTestPayloadGenerator(ModuleBase):
    """
    SNMP Community String Test Query Generator.
    Emits controlled SNMP GET requests testing community strings ('public', 'private')
    to validate SNMP reconnaissance sentinels in safe laboratory settings.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target SNMP agent IP"},
            "COMMUNITY": {"value": "public,private,cisco", "required": True, "desc": "Comma-separated community strings to test"},
            "INTERVAL": {"value": "0.3", "required": False, "desc": "Interval between queries in seconds"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        comm_str = self.options["COMMUNITY"]["value"]
        communities = [c.strip() for c in comm_str.split(",") if c.strip()]
        interval = float(self.options["INTERVAL"]["value"] or 0.3)

        print(f"[*] Emitting test SNMP queries to {target}:161 for {communities}...")
        try:
            for comm in communities:
                snmp_bytes = b"\x30\x29\x02\x01\x00\x04" + bytes([len(comm)]) + comm.encode() + b"\xa0\x1c\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
                pkt = IP(dst=target) / UDP(sport=50161, dport=161) / Raw(load=snmp_bytes)
                send(pkt, verbose=0)
                print(f"  [>] Sent SNMP GET query with community '{comm}'")
                time.sleep(interval)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SNMP test query generation stopped.")
            return

        print(f"[+] SNMP test payload emission completed.")
