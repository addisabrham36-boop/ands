from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import base64
import re
from datetime import datetime


class CleartextCredsAudit(ModuleBase):
    """
    Passive Cleartext Credential & Authentication Leak Auditor.
    Inspects unencrypted network payloads (HTTP Basic Auth, FTP, Telnet,
    POP3, IMAP, SMTP) to detect transmitted plaintext passwords and API keys.
    """

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
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport

        if self.session.is_whitelisted(src):
            return

        payload = bytes(pkt[Raw].load)
        try:
            text = payload.decode("utf-8", errors="ignore")
        except Exception:
            return

        found_proto = None
        user_info = None

        # 1. HTTP Basic Authorization: Basic <base64>
        if "Authorization: Basic " in text:
            match = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text)
            if match:
                try:
                    decoded = base64.b64decode(match.group(1)).decode("utf-8", errors="ignore")
                    found_proto = "HTTP_BASIC_AUTH"
                    user_info = decoded
                except Exception:
                    pass

        # 2. FTP: USER / PASS
        elif dport == 21:
            if text.startswith("USER ") or text.startswith("PASS "):
                found_proto = "FTP"
                user_info = text.strip()

        # 3. POP3 / IMAP: USER / PASS / LOGIN
        elif dport in (110, 143):
            if any(text.upper().startswith(p) for p in ("USER ", "PASS ", "LOGIN ", "AUTH ")):
                found_proto = "POP3_IMAP"
                user_info = text.strip()

        # 4. Telnet (Port 23) or SMTP (Port 25)
        elif dport in (23, 25) and any(kw in text.lower() for kw in ("password:", "login:", "auth login")):
            found_proto = "TELNET_SMTP"
            user_info = text.strip()

        if found_proto and user_info:
            # Mask password part for privacy if formatted as user:pass
            masked_info = user_info
            if ":" in user_info:
                u, p = user_info.split(":", 1)
                masked_info = f"{u}:{'*' * len(p)}"

            key = (src, found_proto, dst, masked_info)
            if key not in self.already_alerted:
                self.already_alerted.add(key)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[AUDIT ALERT] Plaintext Credential Leak [{found_proto}]: {src} -> {dst} ({masked_info}) [{ts}]")

                self.session.add_alert({
                    "type": "CLEARTEXT_CREDENTIAL_EXPOSURE",
                    "severity": "CRITICAL",
                    "confidence": 0.98,
                    "mitre_id": "T1552",
                    "source": src,
                    "destination": dst,
                    "protocol": found_proto,
                    "description": f"Unencrypted credential transmission exposed on the wire from {src} to {dst} via {found_proto}: '{masked_info}'",
                    "details": {
                        "protocol_service": found_proto,
                        "credential_snippet": masked_info,
                        "destination_port": dport,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.already_alerted.clear()
        print(f"[*] Plaintext Credential Auditor active on {iface} (HTTP/FTP/Telnet/POP3/IMAP)...")
        bpf = "tcp and (port 80 or port 8080 or port 21 or port 23 or port 25 or port 110 or port 143)"

        try:
            sniff(iface=iface, filter=bpf, prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Credential auditor stopped.")
            return

        print(f"[+] Credential audit completed — {len(self.already_alerted)} unencrypted credential finding(s).")
