from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime


class SSLTLSAudit(ModuleBase):
    """
    SSL/TLS Protocol & Cryptographic Security Auditor.
    Passively audits TLS Client and Server Hello handshakes, identifying
    deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) and insecure configurations.
    """

    TLS_VERSIONS = {
        0x0200: ("SSLv2", "CRITICAL", "T1557"),
        0x0300: ("SSLv3 (POODLE vulnerable)", "CRITICAL", "T1557"),
        0x0301: ("TLS 1.0 (Deprecated)", "HIGH", "T1557"),
        0x0302: ("TLS 1.1 (Deprecated)", "MEDIUM", "T1557"),
        0x0303: ("TLS 1.2", "INFO", ""),
        0x0304: ("TLS 1.3", "INFO", ""),
    }

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        tcp = pkt[TCP]

        if tcp.dport != 443 and tcp.sport != 443:
            return

        raw = bytes(pkt[Raw].load)
        if len(raw) < 5:
            return

        # Check TLS Record Layer (Content Type 22 = Handshake)
        if raw[0] == 22:
            version_bytes = int.from_bytes(raw[1:3], "big")
            
            if version_bytes in self.TLS_VERSIONS:
                ver_name, severity, mitre_id = self.TLS_VERSIONS[version_bytes]
                
                if severity in ("CRITICAL", "HIGH", "MEDIUM"):
                    key = (src, dst, version_bytes)
                    if key not in self.already_alerted:
                        self.already_alerted.add(key)
                        ts = datetime.now().strftime("%H:%M:%S")
                        print(f"[AUDIT ALERT] Insecure TLS Handshake: {src} -> {dst} (Version: {ver_name}) [{ts}]")

                        self.session.add_alert({
                            "type": "DEPRECATED_TLS_VERSION",
                            "severity": severity,
                            "confidence": 0.98,
                            "mitre_id": mitre_id or "T1557",
                            "source": src,
                            "destination": dst,
                            "protocol": "TLS",
                            "description": f"Insecure / Deprecated TLS protocol version ({ver_name}) observed between {src} and {dst}",
                            "details": {
                                "tls_version_hex": hex(version_bytes),
                                "version_name": ver_name,
                                "port": tcp.dport,
                            }
                        })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] SSL/TLS Cryptographic Compliance Auditor active on {iface} (port 443)...")

        try:
            sniff(iface=iface, filter="tcp and port 443", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] TLS audit stopped.")
            return

        print(f"[+] TLS audit complete — {len(self.already_alerted)} deprecated protocol finding(s) discovered.")
