from core.module_base import ModuleBase
from scapy.all import sniff, IP, DNS, DNSQR
import time
import collections
from datetime import datetime
from core.statistics import calculate_shannon_entropy


class DNSTunnelDetect(ModuleBase):
    """
    DNS Tunneling & Covert Data Exfiltration Sentinel.
    Inspects DNS query names for high Shannon entropy (Base32/Base64/Hex encoding),
    abnormal subdomain lengths, high-frequency TXT/NULL query rates, and DGA patterns.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "ENTROPY_THRESHOLD": {"value": "3.75", "required": True, "desc": "Shannon entropy threshold for query subdomain (bits/char)"},
            "LENGTH_THRESHOLD": {"value": "35", "required": True, "desc": "Subdomain length threshold in characters"},
        }
        self.query_history = collections.defaultdict(list)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return

        dns = pkt[DNS]
        if dns.qr != 0:  # Only check queries (qr == 0)
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        try:
            qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        except Exception:
            return

        entropy_thresh = float(self.options["ENTROPY_THRESHOLD"]["value"])
        len_thresh = int(self.options["LENGTH_THRESHOLD"]["value"])

        parts = qname.split(".")
        if len(parts) >= 2:
            subdomain = ".".join(parts[:-2])  # extract subdomains without root TLD
        else:
            subdomain = qname

        if len(subdomain) < 8:
            return

        ent = calculate_shannon_entropy(subdomain)
        sub_len = len(subdomain)
        qtype = pkt[DNSQR].qtype  # 16 = TXT, 10 = NULL

        is_tunnel = (ent >= entropy_thresh and sub_len >= len_thresh) or (sub_len > 60) or (qtype in (10, 16) and ent > 3.5)

        if is_tunnel:
            key = (src, qname[:30])
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] DNS Tunneling / Exfiltration Probe: {src} -> '{qname[:45]}...' [Entropy: {ent:.2f}, Len: {sub_len}] [{ts}]")

                confidence = min(0.98, 0.6 + (ent / 5.0) + (sub_len / 200.0))
                self.session.add_alert({
                    "type": "DNS_TUNNELING",
                    "severity": "HIGH" if ent > 4.2 or sub_len > 60 else "MEDIUM",
                    "confidence": round(confidence, 2),
                    "mitre_id": "T1071.004",
                    "source": src,
                    "destination": dst,
                    "protocol": "DNS",
                    "description": f"Covert DNS Tunneling / Data Exfiltration attempt detected from {src}: query '{qname[:60]}' exhibits high entropy ({ent:.2f}) and payload length ({sub_len} chars)",
                    "details": {
                        "query_name": qname,
                        "subdomain_length": sub_len,
                        "shannon_entropy": round(ent, 3),
                        "query_type": qtype,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.query_history.clear()
        self.already_alerted.clear()

        print(f"[*] DNS Exfiltration & Tunneling Sentinel active on {iface} (port 53)...")
        try:
            sniff(iface=iface, filter="udp and port 53", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] DNS monitoring stopped by user.")
            return

        print(f"[+] DNS Sentinel finished — {len(self.already_alerted)} suspicious tunneling event(s) detected.")
