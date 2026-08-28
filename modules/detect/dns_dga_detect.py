from core.module_base import ModuleBase
from scapy.all import sniff, IP, UDP, DNS, DNSQR
import math
import collections
from datetime import datetime


class DGADomainDetect(ModuleBase):
    """
    Domain Generation Algorithm (DGA) Malware Sentinel.
    Analyzes live DNS query strings for DGA indicators including high Shannon
    entropy, abnormal consonant-to-vowel ratios, and random subdomains.
    """

    VOWELS = set("aeiou")

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "ENTROPY_THRESHOLD": {"value": "3.5", "required": True, "desc": "Shannon entropy cutoff for flagged domains"},
        }
        self.already_alerted = set()

    def _entropy(self, s: str) -> float:
        if not s:
            return 0.0
        counts = collections.Counter(s)
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        parts = qname.split(".")
        if len(parts) < 2:
            return

        domain_stem = parts[0]
        if len(domain_stem) < 8:
            return

        # Calculate metrics
        entropy_val = self._entropy(domain_stem)
        consonants = sum(1 for c in domain_stem if c.isalpha() and c.lower() not in self.VOWELS)
        vowels = sum(1 for c in domain_stem if c.isalpha() and c.lower() in self.VOWELS)
        ratio = (consonants / vowels) if vowels > 0 else float(consonants)

        thresh = float(self.options["ENTROPY_THRESHOLD"]["value"])

        if (entropy_val >= thresh and len(domain_stem) >= 12) or (ratio >= 5.0 and len(domain_stem) >= 10):
            if qname not in self.already_alerted:
                self.already_alerted.add(qname)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] DGA Domain Query: {src} -> {qname} (Entropy: {entropy_val:.2f}) [{ts}]")

                self.session.add_alert({
                    "type": "DGA_MALWARE_DOMAIN",
                    "severity": "HIGH",
                    "confidence": min(0.98, 0.6 + (entropy_val / 6.0)),
                    "mitre_id": "T1568.002",
                    "source": src,
                    "destination": dst,
                    "protocol": "DNS",
                    "description": f"Potential Domain Generation Algorithm (DGA) query detected: '{qname}' (Entropy: {entropy_val:.2f}, Consonant/Vowel Ratio: {ratio:.1f})",
                    "details": {
                        "queried_domain": qname,
                        "entropy": round(entropy_val, 2),
                        "consonant_ratio": round(ratio, 2),
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] DGA Malware Sentinel active on {iface} (port 53)...")

        try:
            sniff(iface=iface, filter="udp and port 53", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] DGA monitoring stopped.")
            return

        print(f"[+] DGA Sentinel finished — {len(self.already_alerted)} suspicious domain(s) flagged.")
