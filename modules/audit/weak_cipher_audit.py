from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
from datetime import datetime


class WeakCipherAudit(ModuleBase):
    """
    Weak TLS Cipher Suite & Cryptographic Vulnerability Auditor.
    Inspects TLS ClientHello and ServerHello handshakes for dangerous or broken
    ciphers (RC4, 3DES, DES, EXPORT, NULL, MD5) vulnerable to SWEET32 / BEAST.
    """

    WEAK_CIPHER_BYTES = [
        (b"\x00\x04", "TLS_RSA_WITH_RC4_128_MD5"),
        (b"\x00\x05", "TLS_RSA_WITH_RC4_128_SHA"),
        (b"\x00\x0a", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
        (b"\x00\x03", "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
        (b"\x00\x01", "TLS_RSA_WITH_NULL_MD5"),
        (b"\x00\x02", "TLS_RSA_WITH_NULL_SHA"),
    ]

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Audit duration in seconds"},
        }
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        raw = bytes(pkt[Raw].load)
        # Check TLS Handshake magic 0x16 0x03
        if len(raw) > 5 and raw[0] == 0x16 and raw[1] == 0x03:
            for cipher_bytes, cipher_name in self.WEAK_CIPHER_BYTES:
                if cipher_bytes in raw:
                    key = (src, dst, cipher_name)
                    if key not in self.already_alerted:
                        self.already_alerted.add(key)
                        ts = datetime.now().strftime("%H:%M:%S")
                        print(f"[AUDIT ALERT] Weak TLS Cipher Negotiated: {src} -> {dst} ({cipher_name}) [{ts}]")

                        self.session.add_alert({
                            "type": "WEAK_TLS_CIPHER_USAGE",
                            "severity": "HIGH",
                            "confidence": 0.95,
                            "mitre_id": "T1557",
                            "source": src,
                            "destination": dst,
                            "protocol": "TLS",
                            "description": f"Broken/Deprecated TLS cipher suite '{cipher_name}' negotiated between {src} and {dst} (vulnerable to SWEET32/BEAST)",
                            "details": {
                                "cipher_suite": cipher_name,
                            }
                        })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Weak TLS Cipher Suite Auditor active on {iface} (port 443)...")

        try:
            sniff(iface=iface, filter="tcp and port 443", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Cipher audit stopped.")
            return

        print(f"[+] Weak Cipher Audit complete — {len(self.already_alerted)} vulnerable cipher(s) caught.")
