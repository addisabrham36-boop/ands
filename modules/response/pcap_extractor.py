from core.module_base import ModuleBase
from scapy.all import rdpcap, wrpcap, IP
import os


class PCAPExtractor(ModuleBase):
    """
    Forensic PCAP Slice & Incident Evidence Extractor.
    Extracts targeted packet streams from master capture files based on
    attacker IP, destination port, or time window for Wireshark inspection.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "SOURCE_PCAP": {"value": "data/captures/live_stream.pcap", "required": True, "desc": "Input master PCAP file"},
            "FILTER_IP": {"value": "", "required": False, "desc": "Extract packets containing this IP"},
            "FILTER_PORT": {"value": "", "required": False, "desc": "Extract packets containing this Port"},
            "OUTPUT_SLICE": {"value": "data/captures/forensic_slice.pcap", "required": True, "desc": "Destination path for sliced PCAP"},
        }

    def run(self):
        src_pcap = self.options["SOURCE_PCAP"]["value"]
        filter_ip = self.options["FILTER_IP"]["value"].strip()
        filter_port_str = self.options["FILTER_PORT"]["value"].strip()
        filter_port = int(filter_port_str) if filter_port_str else None
        out_slice = self.options["OUTPUT_SLICE"]["value"]

        if not os.path.exists(src_pcap):
            print(f"[-] Source PCAP file not found: {src_pcap}")
            return

        try:
            print(f"[*] Reading master capture {src_pcap}...")
            packets = rdpcap(src_pcap)
            print(f"[+] Loaded {len(packets)} packets. Extracting forensic slice...")

            extracted = []
            for pkt in packets:
                match = True
                if filter_ip and pkt.haslayer(IP):
                    if pkt[IP].src != filter_ip and pkt[IP].dst != filter_ip:
                        match = False

                if filter_port and match:
                    port_match = False
                    if pkt.haslayer("TCP"):
                        if pkt["TCP"].sport == filter_port or pkt["TCP"].dport == filter_port:
                            port_match = True
                    elif pkt.haslayer("UDP"):
                        if pkt["UDP"].sport == filter_port or pkt["UDP"].dport == filter_port:
                            port_match = True
                    if not port_match:
                        match = False

                if match:
                    extracted.append(pkt)

            if extracted:
                os.makedirs(os.path.dirname(out_slice) or ".", exist_ok=True)
                wrpcap(out_slice, extracted)
                print(f"[+] Extracted {len(extracted)} matching forensic packet(s) to {out_slice}")
                self.session.artifacts["forensic_pcap"] = out_slice
            else:
                print("[-] No packets matched the specified criteria.")

        except Exception as e:
            print(f"[-] PCAP Extraction error: {e}")
