from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import collections
from datetime import datetime


class SSHBruteforceDetect(ModuleBase):
    """
    SSH Credential Brute-Force & Hammering Sentinel.
    Monitors TCP port 22 for rapid new connection bursts, banner exchanges,
    and authentication hammering patterns.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "THRESHOLD": {"value": "6", "required": True, "desc": "Connection attempts per source to trigger alert"},
        }
        self.attempts = collections.defaultdict(list)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]

        if tcp.dport != 22 and tcp.sport != 22:
            return

        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        # Check for new SYN connection initiation
        if tcp.flags == 0x02 and tcp.dport == 22:  # SYN
            now = datetime.now()
            self.attempts[src].append((now, dst))
            thresh = int(self.options["THRESHOLD"]["value"])

            # Filter attempts in last 30 seconds
            recent = [t for t in self.attempts[src] if (now - t[0]).total_seconds() <= 30]
            self.attempts[src] = recent

            if len(recent) >= thresh:
                key = (src, dst, "SSH_BRUTE")
                if key not in self.already_alerted:
                    self.already_alerted.add(key)
                    ts = now.strftime("%H:%M:%S")
                    print(f"[ALERT] SSH Brute-Force Hammering: {src} -> {dst}:22 ({len(recent)} attempts) [{ts}]")

                    self.session.add_alert({
                        "type": "SSH_AUTHENTICATION_HAMMERING",
                        "severity": "HIGH",
                        "confidence": 0.95,
                        "mitre_id": "T1110.001",
                        "source": src,
                        "destination": dst,
                        "protocol": "SSH",
                        "description": f"Rapid SSH authentication / connection hammering from {src} against {dst} ({len(recent)} attempts in 30s)",
                        "details": {
                            "attempt_count": len(recent),
                            "target_port": 22,
                        }
                    })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.attempts.clear()
        self.already_alerted.clear()
        print(f"[*] SSH Brute-Force Sentinel active on {iface} (port 22)...")

        try:
            sniff(iface=iface, filter="tcp and port 22", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] SSH monitoring stopped.")
            return

        print(f"[+] SSH Sentinel finished — {len(self.already_alerted)} brute-force incident(s) flagged.")
