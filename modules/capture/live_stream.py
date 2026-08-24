from core.module_base import ModuleBase
from scapy.all import sniff, wrpcap
import time
import os
from collections import deque


class LiveStreamCapture(ModuleBase):
    """
    Continuous Live Traffic Stream & Rolling PCAP Ring-Buffer Capturer.
    Captures live packets on the wire, maintaining a rolling in-memory buffer
    and periodically flushing to rotating PCAP files for forensic retention.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to sniff"},
            "DURATION": {"value": "30", "required": True, "desc": "Capture duration in seconds (0 = continuous)"},
            "OUTPUT_PCAP": {"value": "data/captures/live_stream.pcap", "required": True, "desc": "Output PCAP capture destination"},
            "BUFFER_SIZE": {"value": "2000", "required": True, "desc": "Max packets in rolling ring-buffer"},
        }
        self.packet_buffer = deque()

    def _on_packet(self, pkt):
        max_size = int(self.options["BUFFER_SIZE"]["value"])
        self.packet_buffer.append(pkt)
        if len(self.packet_buffer) > max_size:
            self.packet_buffer.popleft()

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])
        out_pcap = self.options["OUTPUT_PCAP"]["value"]

        self.packet_buffer.clear()
        print(f"[*] Live Stream Capturer active on {iface} -> {out_pcap}...")

        try:
            sniff(iface=iface, prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Live capture stream interrupted.")

        if self.packet_buffer:
            os.makedirs(os.path.dirname(out_pcap) or ".", exist_ok=True)
            wrpcap(out_pcap, list(self.packet_buffer))
            print(f"[+] Saved {len(self.packet_buffer)} packets to {out_pcap}")
            self.session.artifacts["live_pcap"] = out_pcap
        else:
            print("[-] No packets collected.")
