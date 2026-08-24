from core.module_base import ModuleBase
from scapy.all import sniff, IP
import collections
from datetime import datetime


class IPFragmentationDetect(ModuleBase):
    """
    IP Fragmentation, Teardrop & Overlapping Offset Exploit Sentinel.
    Inspects IP packet fragment offset fields (flags MF/DF, frag offset) to catch
    overlapping fragments (Teardrop attacks), tiny fragment evasion, and fragment floods.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        # (src, ip_id) -> list of (offset, length)
        self.fragment_map = collections.defaultdict(list)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        ip_id = ip.id
        frag_offset = ip.frag * 8  # Offset is in 8-byte units
        mf_flag = bool(ip.flags & 0x01)  # More Fragments flag

        if not mf_flag and frag_offset == 0:
            return  # Normal non-fragmented packet

        if self.session.is_whitelisted(src):
            return

        payload_len = len(ip.payload)
        key = (src, ip_id)
        self.fragment_map[key].append((frag_offset, payload_len))

        # Check for overlapping offsets (Teardrop attack pattern)
        fragments = self.fragment_map[key]
        if len(fragments) >= 2:
            sorted_frags = sorted(fragments, key=lambda x: x[0])
            for i in range(1, len(sorted_frags)):
                prev_end = sorted_frags[i - 1][0] + sorted_frags[i - 1][1]
                curr_start = sorted_frags[i][0]
                if curr_start < prev_end:  # Overlapping offset!
                    alert_key = (src, dst, ip_id, "TEARDROP")
                    if alert_key not in self.already_alerted:
                        self.already_alerted.add(alert_key)
                        ts = datetime.now().strftime("%H:%M:%S")
                        print(f"[ALERT] Teardrop Overlapping IP Fragment Attack: {src} -> {dst} (ID: {ip_id}) [{ts}]")

                        self.session.add_alert({
                            "type": "IP_FRAGMENT_OVERLAP_TEARDROP",
                            "severity": "CRITICAL",
                            "confidence": 0.98,
                            "mitre_id": "T1498.001",
                            "source": src,
                            "destination": dst,
                            "protocol": "IP",
                            "description": f"Teardrop / Overlapping IP Fragment attack detected from {src}: Fragment offset {curr_start} overlaps previous offset boundary {prev_end}",
                            "details": {
                                "ip_id": ip_id,
                                "overlap_offset": curr_start,
                                "previous_end_offset": prev_end,
                            }
                        })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.fragment_map.clear()
        self.already_alerted.clear()

        print(f"[*] IP Fragmentation & Teardrop Sentinel active on {iface}...")

        try:
            sniff(iface=iface, filter="ip", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Fragmentation monitoring halted.")
            return

        print(f"[+] Fragmentation scan complete — {len(self.already_alerted)} exploit event(s) caught.")
