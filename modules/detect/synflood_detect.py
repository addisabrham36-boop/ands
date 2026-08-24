from core.module_base import ModuleBase
from scapy.all import sniff, IP, TCP
import time
import collections
from datetime import datetime


class SYNFloodDetect(ModuleBase):
    """
    High-Performance TCP SYN Flood & Half-Open Connection Exhaustion Detector.
    Monitors SYN-to-ACK ratios and tracks uncompleted TCP handshakes in real-time.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "INTERFACE": {"value": session.get_global("INTERFACE", "enp1s0"), "required": True, "desc": "Network interface to monitor"},
            "DURATION": {"value": "30", "required": True, "desc": "Monitoring duration in seconds (0 = continuous)"},
            "SYN_THRESHOLD": {"value": "50", "required": True, "desc": "Half-open SYN packets per window to trigger alert"},
            "RATIO_THRESHOLD": {"value": "5.0", "required": True, "desc": "SYN-to-ACK ratio threshold indicating asymmetric flooding"},
            "WINDOW": {"value": "5", "required": True, "desc": "Evaluation window in seconds"},
        }
        self.syn_count = collections.defaultdict(int)
        self.ack_count = collections.defaultdict(int)
        self.already_alerted = set()

    def _on_packet(self, pkt):
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst

        if self.session.is_whitelisted(src):
            return

        tcp = pkt[TCP]
        flags = int(tcp.flags)

        # Pure SYN (no ACK)
        if flags == 0x02:
            self.syn_count[(src, dst)] += 1
        elif flags & 0x10:  # ACK
            self.ack_count[(src, dst)] += 1

    def run(self):
        iface = self.options["INTERFACE"]["value"] or self.session.get_global("INTERFACE", "enp1s0")
        duration = int(self.options["DURATION"]["value"])
        syn_thresh = int(self.options["SYN_THRESHOLD"]["value"])
        ratio_thresh = float(self.options["RATIO_THRESHOLD"]["value"])
        window = float(self.options["WINDOW"]["value"])

        self.syn_count.clear()
        self.ack_count.clear()
        self.already_alerted.clear()

        print(f"[*] SYN Flood Sentinel active on {iface} (threshold: {syn_thresh} SYNs/window, ratio >= {ratio_thresh})...")
        start_time = time.time()
        next_eval = start_time + window
        alerts_recorded = 0

        def stop_filter(pkt):
            nonlocal next_eval, alerts_recorded
            now = time.time()
            if duration > 0 and (now - start_time) >= duration:
                return True

            if now >= next_eval:
                next_eval = now + window
                for (src, dst), syns in list(self.syn_count.items()):
                    acks = self.ack_count.get((src, dst), 0)
                    ratio = (syns / (acks + 1))
                    
                    if syns >= syn_thresh and ratio >= ratio_thresh and (src, dst) not in self.already_alerted:
                        self.already_alerted.add((src, dst))
                        alerts_recorded += 1
                        ts = datetime.now().strftime("%H:%M:%S")
                        print(f"[ALERT] SYN Flood from {src} -> {dst}! SYNs: {syns} | ACKs: {acks} | Ratio: {ratio:.1f}x [{ts}]")
                        
                        self.session.add_alert({
                            "type": "SYN_FLOOD",
                            "severity": "CRITICAL" if syns > 200 else "HIGH",
                            "confidence": min(0.99, 0.7 + (syns / (syn_thresh * 4))),
                            "mitre_id": "T1498.001",
                            "source": src,
                            "destination": dst,
                            "protocol": "TCP",
                            "description": f"TCP SYN Flood / Half-Open Denial of Service attack detected from {src} against {dst}: {syns} SYNs in {window}s (SYN/ACK ratio {ratio:.1f})",
                            "details": {
                                "syn_count": syns,
                                "ack_count": acks,
                                "syn_ack_ratio": round(ratio, 2),
                                "window_seconds": window,
                            }
                        })
                # Reset counters for the next window
                self.syn_count.clear()
                self.ack_count.clear()
            return False

        try:
            sniff(iface=iface, filter="tcp", prn=self._on_packet, stop_filter=stop_filter, timeout=duration if duration > 0 else None, store=0)
        except PermissionError:
            print("[-] Permission denied. Run ANDS with sudo.")
            return
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user.")
            return

        print(f"[+] SYN Flood scan ended — {alerts_recorded} flooding attack(s) identified.")
