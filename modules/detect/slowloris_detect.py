from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP, Raw
import time
import collections
from datetime import datetime


class SlowlorisDetect(ModuleBase):
    """
    Slowloris & Slow HTTP DoS Attack Sentinel.
    Detects low-and-slow HTTP connection starvation where attackers open many
    concurrent persistent connections, trickling partial HTTP headers to exhaust server workers.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "CONCURRENT_THRESHOLD": {"value": "15", "required": True, "desc": "Simultaneous partial HTTP connections from single IP"},
            "PORTS": {"value": "80,8080,443", "required": True, "desc": "HTTP web server ports"},
        }
        # (src_ip, sport, dst_ip, dport) -> {"start": timestamp, "last_packet": timestamp, "has_double_crlf": bool}
        self.open_sockets = {}
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        tcp = pkt[TCP]
        src = ip.src
        dst = ip.dst
        sport = tcp.sport
        dport = tcp.dport
        flags = int(tcp.flags)

        if self.session.is_whitelisted(src):
            return

        sock_key = (src, sport, dst, dport)
        now = time.time()

        # Connection termination (FIN or RST)
        if flags & 0x01 or flags & 0x04:
            if sock_key in self.open_sockets:
                del self.open_sockets[sock_key]
            return

        # SYN packet (new socket)
        if flags == 0x02:
            self.open_sockets[sock_key] = {"start": now, "last": now, "complete": False}
            return

        if sock_key in self.open_sockets:
            self.open_sockets[sock_key]["last"] = now
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if b"\r\n\r\n" in payload:
                    self.open_sockets[sock_key]["complete"] = True

        thresh = int(self.options["CONCURRENT_THRESHOLD"]["value"])
        # Count incomplete sockets per src IP
        incomplete_by_src = collections.defaultdict(int)
        for (s_ip, _, d_ip, _), meta in list(self.open_sockets.items()):
            # Connection open for > 5s without finishing header
            if not meta["complete"] and (now - meta["start"]) >= 5.0:
                incomplete_by_src[s_ip] += 1

        for s_ip, count in incomplete_by_src.items():
            if count >= thresh and s_ip not in self.already_alerted:
                self.already_alerted.add(s_ip)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[ALERT] Slowloris DoS Attack: {s_ip} holding {count} incomplete HTTP connections! [{ts}]")

                self.session.add_alert({
                    "type": "SLOWLORIS_DOS",
                    "severity": "CRITICAL",
                    "confidence": 0.95,
                    "mitre_id": "T1499.003",
                    "source": s_ip,
                    "destination": f"PORT_{dport}",
                    "protocol": "HTTP",
                    "description": f"Slowloris Slow-HTTP Connection Exhaustion DoS detected from {s_ip}: holding {count} uncompleted HTTP request streams open simultaneously",
                    "details": {
                        "partial_connections_count": count,
                        "threshold": thresh,
                    }
                })

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])

        self.open_sockets.clear()
        self.already_alerted.clear()

        print(f"[*] Slowloris DoS Sentinel active on {iface}...")
        try:
            sniff(iface=iface, filter="tcp and (port 80 or port 8080 or port 443)", prn=self._on_packet, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Slowloris monitoring stopped.")
            return

        print(f"[+] Slowloris Sentinel complete — {len(self.already_alerted)} slow-rate DoS source(s) detected.")
