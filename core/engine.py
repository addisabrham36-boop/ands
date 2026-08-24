import time
import threading
import collections
from typing import Dict, List, Any, Optional, Callable
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw
from core.session import Session
from core.statistics import zscore, median_absolute_deviation, modified_zscore, exponential_moving_average


class LiveEngine:
    """
    Continuous, multi-threaded Live Packet Ingestion & Detection Coordinator.
    Feeds parsed packets into registered detection engines, updates real-time
    telemetry, and computes rolling statistical baselines without duplicating sniffers.
    """

    def __init__(self, session: Session):
        self.session = session
        self.interface = session.get_global("INTERFACE", "enp1s0")
        self.bpf_filter = ""
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stats_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        
        # Performance & telemetry counters
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = 0.0
        self.current_window_packets = 0
        self.current_window_bytes = 0
        
        # Sliding rate history for anomaly detection (last 60 windows of 1-sec each)
        self.rate_history: collections.deque = collections.deque(maxlen=60)
        self.baseline_mean = 10.0
        self.baseline_stdev = 2.0
        self.baseline_median = 10.0
        self.baseline_mad = 2.0
        
        # Handshake & connection state tracking for false-positive reduction
        # key: (src_ip, src_port, dst_ip, dst_port) -> state: "SYN_SENT", "ESTABLISHED", "CLOSED"
        self.tcp_sessions: Dict[tuple, Dict[str, Any]] = {}
        
        # Registered packet handler callbacks
        self.handlers: List[Callable[[Any], None]] = []

    def register_handler(self, handler: Callable[[Any], None]):
        with self._lock:
            if handler not in self.handlers:
                self.handlers.append(handler)

    def unregister_handler(self, handler: Callable[[Any], None]):
        with self._lock:
            if handler in self.handlers:
                self.handlers.remove(handler)

    def _process_packet(self, pkt):
        if not self._running:
            return

        with self._lock:
            self.total_packets += 1
            pkt_len = len(pkt)
            self.total_bytes += pkt_len
            self.current_window_packets += 1
            self.current_window_bytes += pkt_len

        # Fast protocol classification & inventory learning
        src_ip = None
        dst_ip = None
        proto_name = "OTHER"

        if pkt.haslayer(ARP):
            proto_name = "ARP"
            arp = pkt[ARP]
            src_ip = arp.psrc
            dst_ip = arp.pdst
            if arp.op == 2:  # is-at (reply)
                self.session.record_host(src_ip, mac=arp.hwsrc, proto="ARP")

        elif pkt.haslayer(IP):
            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            
            # Simple passive OS hint from TTL
            ttl = ip.ttl
            os_hint = "Linux/Unix" if ttl <= 64 else ("Windows" if ttl <= 128 else "Solaris/Cisco")

            if pkt.haslayer(TCP):
                proto_name = "TCP"
                tcp = pkt[TCP]
                sport, dport = tcp.sport, tcp.dport
                flags = tcp.flags
                
                # Check application layer ports
                if dport == 80 or sport == 80:
                    proto_name = "HTTP"
                elif dport == 443 or sport == 443:
                    proto_name = "TLS"
                elif dport == 22 or sport == 22:
                    proto_name = "SSH"
                elif dport == 53 or sport == 53:
                    proto_name = "DNS"

                # State tracking: SYN without ACK
                if flags & 0x02 and not (flags & 0x10):  # SYN
                    self.tcp_sessions[(src_ip, sport, dst_ip, dport)] = {"state": "SYN_SENT", "time": time.time()}
                elif flags & 0x12 == 0x12:  # SYN-ACK
                    pair = (dst_ip, dport, src_ip, sport)
                    if pair in self.tcp_sessions:
                        self.tcp_sessions[pair]["state"] = "SYN_ACK"
                elif flags & 0x10:  # ACK
                    pair = (src_ip, sport, dst_ip, dport)
                    if pair in self.tcp_sessions and self.tcp_sessions[pair]["state"] == "SYN_ACK":
                        self.tcp_sessions[pair]["state"] = "ESTABLISHED"

                self.session.record_host(src_ip, os_hint=os_hint, port=sport, proto=proto_name)
                self.session.record_host(dst_ip, port=dport, proto=proto_name)

            elif pkt.haslayer(UDP):
                proto_name = "UDP"
                udp = pkt[UDP]
                if udp.dport == 53 or udp.sport == 53 or pkt.haslayer(DNS):
                    proto_name = "DNS"
                elif udp.dport in (67, 68) or udp.sport in (67, 68):
                    proto_name = "DHCP"
                self.session.record_host(src_ip, os_hint=os_hint, port=udp.sport, proto=proto_name)
                self.session.record_host(dst_ip, port=udp.dport, proto=proto_name)

            elif pkt.haslayer(ICMP):
                proto_name = "ICMP"
                self.session.record_host(src_ip, os_hint=os_hint, proto="ICMP")
                self.session.record_host(dst_ip, proto="ICMP")

        self.session.increment_protocol(proto_name)

        # Dispatch packet to registered detection handler callbacks
        with self._lock:
            handlers_copy = list(self.handlers)
        for h in handlers_copy:
            try:
                h(pkt)
            except Exception:
                pass

    def _telemetry_loop(self):
        """Calculates 1-second rolling statistical rates and computes adaptive z-score & MAD."""
        while self._running:
            time.sleep(1.0)
            with self._lock:
                pps = float(self.current_window_packets)
                bps = float(self.current_window_bytes * 8)
                self.current_window_packets = 0
                self.current_window_bytes = 0
                self.rate_history.append(pps)
                history_list = list(self.rate_history)

            # Clean expired half-open TCP states (> 30s)
            now = time.time()
            with self._lock:
                expired = [k for k, v in self.tcp_sessions.items() if now - v.get("time", now) > 30]
                for k in expired:
                    del self.tcp_sessions[k]

            # Compute statistical metrics
            z = 0.0
            if len(history_list) >= 5:
                med, mad = median_absolute_deviation(history_list)
                self.baseline_median = exponential_moving_average(self.baseline_median, med, alpha=0.15)
                self.baseline_mad = max(0.5, exponential_moving_average(self.baseline_mad, max(mad, 1.0), alpha=0.15))
                z = modified_zscore(pps, self.baseline_median, self.baseline_mad)
                
                # Check for live volumetric spike anomaly
                if z >= 3.8 and pps > 50:
                    self.session.add_alert({
                        "type": "TRAFFIC_SPIKE_ANOMALY",
                        "severity": "HIGH",
                        "confidence": min(0.99, 0.5 + (z / 10.0)),
                        "mitre_id": "T1498",
                        "protocol": "IP",
                        "source": "NETWORK_SUBNET",
                        "destination": "ALL",
                        "description": f"Real-time volumetric traffic spike detected: {pps:.1f} pkt/s (Modified Z-Score: {z:.2f})",
                        "details": {"current_pps": pps, "baseline_median": self.baseline_median, "modified_zscore": z}
                    })

            self.session.record_traffic_point(pps=pps, bps=bps, zscore_val=z)

    def _sniff_loop(self):
        try:
            sniff(
                iface=self.interface if self.interface else None,
                filter=self.bpf_filter if self.bpf_filter else None,
                prn=self._process_packet,
                stop_filter=lambda p: not self._running,
                store=0
            )
        except Exception as e:
            self._running = False

    def start(self, interface: Optional[str] = None, bpf_filter: str = ""):
        if self._running:
            return True
        if interface:
            self.interface = interface
            self.session.set_global("INTERFACE", interface)
        self.bpf_filter = bpf_filter
        self._running = True
        self.start_time = time.time()
        self.total_packets = 0
        self.total_bytes = 0

        self._thread = threading.Thread(target=self._sniff_loop, daemon=True, name="ANDS-Sniffer")
        self._thread.start()

        self._stats_thread = threading.Thread(target=self._telemetry_loop, daemon=True, name="ANDS-Telemetry")
        self._stats_thread.start()
        return True

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        if self._stats_thread and self._stats_thread.is_alive():
            self._stats_thread.join(timeout=1.0)

    def is_running(self) -> bool:
        return self._running

    def get_stats(self) -> Dict[str, Any]:
        uptime = time.time() - self.start_time if self._running else 0.0
        pps = (self.total_packets / uptime) if uptime > 0 else 0.0
        kbps = ((self.total_bytes * 8 / 1024.0) / uptime) if uptime > 0 else 0.0
        return {
            "running": self._running,
            "interface": self.interface,
            "uptime_seconds": round(uptime, 1),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "current_pps": round(pps, 1),
            "current_kbps": round(kbps, 1),
            "baseline_median_pps": round(self.baseline_median, 1),
            "alerts_count": len(self.session.alert_history),
            "hosts_discovered": len(self.session.network_inventory),
        }
