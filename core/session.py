import json
import time
import uuid
import threading
from typing import Dict, List, Any, Optional, Callable


class Session:
    """
    Central, thread-safe session state shared across CLI modules,
    the live packet detection engine, and the Web/Desktop SOC dashboard.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self.globals: Dict[str, str] = {
            "TARGET": "",
            "INTERFACE": "enp1s0",
            "ALERT_OUT": "logs/alerts.jsonl",
            "CONFIDENCE_THRESHOLD": "0.5",
            "WHITELIST": "127.0.0.1,::1",
        }
        self.alert_history: List[Dict[str, Any]] = []
        self.artifacts: Dict[str, str] = {}
        
        # Asset / host inventory discovered passively
        self.network_inventory: Dict[str, Dict[str, Any]] = {}
        
        # Whitelisted and Banned IP registries
        self.whitelist: set = {"127.0.0.1", "::1"}
        self.banned_ips: set = set()
        
        # Real-time traffic metrics ring buffer
        self.traffic_history: List[Dict[str, Any]] = []
        self.protocol_stats: Dict[str, int] = {
            "TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0,
            "DNS": 0, "HTTP": 0, "TLS": 0, "SSH": 0, "OTHER": 0
        }
        
        # Event subscribers (for live SSE/WebSocket broadcast)
        self._listeners: List[Callable[[str, Dict[str, Any]], None]] = []

    def register_listener(self, callback: Callable[[str, Dict[str, Any]], None]):
        with self._lock:
            if callback not in self._listeners:
                self._listeners.append(callback)

    def unregister_listener(self, callback: Callable[[str, Dict[str, Any]], None]):
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)

    def _notify(self, event_type: str, data: Dict[str, Any]):
        with self._lock:
            listeners = list(self._listeners)
        for cb in listeners:
            try:
                cb(event_type, data)
            except Exception:
                pass

    def set_global(self, key: str, value: str):
        with self._lock:
            key_upper = key.upper()
            self.globals[key_upper] = value
            if key_upper == "WHITELIST":
                self.whitelist = {ip.strip() for ip in value.split(",") if ip.strip()}

    def get_global(self, key: str, default: str = "") -> str:
        with self._lock:
            return self.globals.get(key.upper(), default)

    def is_whitelisted(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        with self._lock:
            return ip in self.whitelist or ip in ("127.0.0.1", "::1", "0.0.0.0")

    def add_whitelist(self, ip: str):
        with self._lock:
            self.whitelist.add(ip.strip())
            self.globals["WHITELIST"] = ",".join(sorted(self.whitelist))

    def remove_whitelist(self, ip: str):
        with self._lock:
            self.whitelist.discard(ip.strip())
            self.globals["WHITELIST"] = ",".join(sorted(self.whitelist))

    def add_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adds an alert to session history, enriches with metadata,
        writes to log file, and notifies live streaming subscribers.
        """
        src = alert.get("source") or alert.get("src_ip")
        if src and self.is_whitelisted(src):
            # Suppress whitelisted sources to reduce false positives
            return {}

        with self._lock:
            alert_id = alert.get("id") or str(uuid.uuid4())[:8]
            timestamp = alert.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")
            epoch = alert.get("epoch") or time.time()
            
            enriched = {
                "id": alert_id,
                "timestamp": timestamp,
                "epoch": epoch,
                "type": alert.get("type", "UNKNOWN_ANOMALY"),
                "severity": alert.get("severity", "MEDIUM"),
                "confidence": float(alert.get("confidence", 0.75)),
                "mitre_id": alert.get("mitre_id", "T1046"),
                "source": src or "N/A",
                "destination": alert.get("destination") or alert.get("dst_ip", "N/A"),
                "protocol": alert.get("protocol", "IP"),
                "description": alert.get("description", ""),
                "details": alert.get("details", {}),
            }
            # Copy over any extra fields
            for k, v in alert.items():
                if k not in enriched:
                    enriched[k] = v

            self.alert_history.append(enriched)
            
            # Update host alert counter in inventory
            if src and src != "N/A":
                if src in self.network_inventory:
                    self.network_inventory[src]["alerts"] = self.network_inventory[src].get("alerts", 0) + 1

            # Persist to disk if configured
            alert_out = self.get_global("ALERT_OUT", "logs/alerts.jsonl")
            if alert_out:
                try:
                    import os
                    os.makedirs(os.path.dirname(alert_out) or ".", exist_ok=True)
                    with open(alert_out, "a") as f:
                        f.write(json.dumps(enriched) + "\n")
                except Exception:
                    pass

        self._notify("alert", enriched)
        return enriched

    def get_alerts(self, limit: int = 100, severity: Optional[str] = None, alert_type: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            res = self.alert_history
            if severity:
                res = [a for a in res if a.get("severity") == severity.upper()]
            if alert_type:
                res = [a for a in res if a.get("type") == alert_type.upper()]
            return list(res[-limit:])

    def clear_alerts(self):
        with self._lock:
            self.alert_history = []
        self._notify("clear_alerts", {})

    def record_host(self, ip: str, mac: str = "", vendor: str = "", os_hint: str = "", port: Optional[int] = None, proto: str = ""):
        """Updates passive network device inventory."""
        if not ip or ip in ("0.0.0.0", "255.255.255.255"):
            return
        with self._lock:
            if ip not in self.network_inventory:
                self.network_inventory[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": vendor,
                    "os_hint": os_hint,
                    "first_seen": time.strftime("%H:%M:%S"),
                    "last_seen": time.strftime("%H:%M:%S"),
                    "ports": set(),
                    "protocols": set(),
                    "alerts": 0,
                }
            entry = self.network_inventory[ip]
            entry["last_seen"] = time.strftime("%H:%M:%S")
            if mac and not entry["mac"]:
                entry["mac"] = mac
            if vendor and not entry["vendor"]:
                entry["vendor"] = vendor
            if os_hint and not entry["os_hint"]:
                entry["os_hint"] = os_hint
            if port:
                entry["ports"].add(port)
            if proto:
                entry["protocols"].add(proto)

    def get_inventory(self) -> List[Dict[str, Any]]:
        with self._lock:
            output = []
            for ip, data in self.network_inventory.items():
                output.append({
                    "ip": data["ip"],
                    "mac": data["mac"],
                    "vendor": data["vendor"],
                    "os_hint": data["os_hint"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                    "ports": sorted(list(data["ports"])),
                    "protocols": sorted(list(data["protocols"])),
                    "alerts": data["alerts"],
                })
            return sorted(output, key=lambda x: x["alerts"], reverse=True)

    def record_traffic_point(self, pps: float, bps: float, zscore_val: float = 0.0, top_proto: str = "TCP"):
        point = {
            "timestamp": time.strftime("%H:%M:%S"),
            "epoch": time.time(),
            "pps": round(pps, 2),
            "bps": round(bps, 2),
            "kbps": round(bps / 1024.0, 2),
            "zscore": round(zscore_val, 2),
            "top_proto": top_proto,
        }
        with self._lock:
            self.traffic_history.append(point)
            if len(self.traffic_history) > 120:
                self.traffic_history.pop(0)
        self._notify("traffic", point)

    def increment_protocol(self, proto: str):
        with self._lock:
            proto_upper = proto.upper()
            if proto_upper in self.protocol_stats:
                self.protocol_stats[proto_upper] += 1
            else:
                self.protocol_stats["OTHER"] += 1