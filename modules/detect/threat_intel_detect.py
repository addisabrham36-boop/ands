from core.module_base import ModuleBase
from scapy.all import sniff, IP
import os
from datetime import datetime


class ThreatIntelDetect(ModuleBase):
    """
    Threat Intelligence & IOC Blacklist Matching Sentinel.
    Correlates active network flows in real-time against malicious IP feeds,
    known C2 infrastructure, and compromised threat actor nodes.
    """

    DEFAULT_IOC_LIST = {
        "198.51.100.42", "203.0.113.195", "185.220.101.5", "194.26.29.112",
        "45.154.255.88", "193.142.146.35", "185.180.143.12", "146.70.157.39"
    }

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "IOC_FILE": {"value": "", "required": False, "desc": "Path to text file containing blacklisted IP addresses (one per line)"},
            "BLACKLIST_IPS": {"value": "198.51.100.42,203.0.113.195,185.220.101.5", "required": False, "desc": "Comma-separated list of IOC IPs"},
        }
        self.active_iocs = set(self.DEFAULT_IOC_LIST)
        self.already_alerted = set()

    def _load_iocs(self):
        self.active_iocs = set(self.DEFAULT_IOC_LIST)
        
        # Load from option string
        custom_ips = self.options["BLACKLIST_IPS"]["value"]
        if custom_ips:
            for ip in custom_ips.split(","):
                ip = ip.strip()
                if ip:
                    self.active_iocs.add(ip)

        # Load from file if given
        ioc_file = self.options["IOC_FILE"]["value"]
        if ioc_file and os.path.exists(ioc_file):
            try:
                with open(ioc_file) as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.active_iocs.add(line)
            except Exception as e:
                print(f"[-] Error reading IOC file {ioc_file}: {e}")

    def _on_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        matched_ip = None
        role = ""

        if src in self.active_iocs:
            matched_ip = src
            role = "SOURCE"
        elif dst in self.active_iocs:
            matched_ip = dst
            role = "DESTINATION"

        if matched_ip and (src, dst) not in self.already_alerted:
            self.already_alerted.add((src, dst))
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"[ALERT] Threat Intel Match! {matched_ip} ({role}) active in flow {src} -> {dst} [{ts}]")

            self.session.add_alert({
                "type": "THREAT_INTEL_IOC_MATCH",
                "severity": "CRITICAL",
                "confidence": 0.99,
                "mitre_id": "T1071",
                "source": src,
                "destination": dst,
                "protocol": "IP",
                "description": f"Known malicious IP address detected: {matched_ip} is cataloged in Threat Intelligence IOC feeds",
                "details": {
                    "matched_ioc": matched_ip,
                    "matched_role": role,
                    "source_ip": src,
                    "destination_ip": dst,
                }
            })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])
        self._load_iocs()

        self.already_alerted.clear()
        print(f"[*] Threat Intel Sentinel active on {iface} (tracking {len(self.active_iocs)} IOC indicators)...")

        try:
            sniff(iface=iface, filter="ip", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Threat intel monitoring stopped.")
            return

        print(f"[+] Threat Intel scan finished — {len(self.already_alerted)} IOC match(es) detected.")
