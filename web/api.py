import json
import time
import io
import contextlib
from typing import Dict, Any
from core.session import Session
from core.engine import LiveEngine
from core.module_loader import load_all_modules


class APIHandler:
    """Handles REST API requests from the SOC Dashboard frontend."""

    def __init__(self, session: Session, engine: LiveEngine):
        self.session = session
        self.engine = engine
        self.modules = load_all_modules()

    def get_stats(self) -> Dict[str, Any]:
        engine_stats = self.engine.get_stats()
        alerts = self.session.alert_history
        crit = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high = sum(1 for a in alerts if a.get("severity") == "HIGH")
        med = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
        
        return {
            "engine": engine_stats,
            "threat_summary": {
                "total_alerts": len(alerts),
                "critical": crit,
                "high": high,
                "medium": med,
                "low": len(alerts) - (crit + high + med),
            },
            "protocol_stats": self.session.protocol_stats,
            "whitelist": sorted(list(self.session.whitelist)),
            "banned_ips": sorted(list(self.session.banned_ips)),
            "traffic_points": list(self.session.traffic_history[-30:]),
        }

    def get_alerts(self, severity: str = "", limit: int = 100) -> Dict[str, Any]:
        alerts = self.session.get_alerts(limit=limit, severity=severity or None)
        return {"alerts": alerts, "count": len(alerts)}

    def clear_alerts(self) -> Dict[str, Any]:
        self.session.clear_alerts()
        return {"success": True, "message": "Alert history cleared"}

    def get_inventory(self) -> Dict[str, Any]:
        inventory = self.session.get_inventory()
        return {"hosts": inventory, "count": len(inventory)}

    def get_modules(self) -> Dict[str, Any]:
        catalog = {}
        for key, cls in sorted(self.modules.items()):
            # Filter duplicate aliases in list
            if key.endswith("_detect") or key.endswith("_audit") or key.endswith("_payload") or key.endswith("_anomaly"):
                continue
            cat = key.split("/")[0] if "/" in key else "custom"
            dummy = cls(self.session)
            catalog.setdefault(cat, []).append({
                "path": key,
                "name": key.split("/")[-1],
                "doc": (cls.__doc__ or "").strip(),
                "options": dummy.options,
            })
        return {"categories": catalog, "total_modules": len(self.modules)}

    def run_module(self, path: str, options: Dict[str, str]) -> Dict[str, Any]:
        if path not in self.modules:
            return {"success": False, "error": f"Unknown module: {path}"}

        mod_cls = self.modules[path]
        instance = mod_cls(self.session)

        # Apply options
        for k, v in options.items():
            instance.set_option(k, str(v))

        missing = instance.missing_required()
        if missing:
            return {"success": False, "error": f"Missing required options: {', '.join(missing)}"}

        stdout_buf = io.StringIO()
        start = time.time()
        error_msg = None

        with contextlib.redirect_stdout(stdout_buf), contextlib.redirect_stderr(stdout_buf):
            try:
                instance.run()
            except Exception as e:
                error_msg = str(e)
                print(f"[-] Execution error: {e}")

        elapsed = round(time.time() - start, 2)
        output_text = stdout_buf.getvalue()

        return {
            "success": error_msg is None,
            "module": path,
            "elapsed_seconds": elapsed,
            "output": output_text,
            "error": error_msg,
            "artifacts": self.session.artifacts,
        }

    def toggle_live(self, action: str, interface: str = "") -> Dict[str, Any]:
        if action == "start":
            iface = interface or self.session.get_global("INTERFACE", "enp1s0")
            self.engine.start(interface=iface)
            return {"success": True, "running": True, "interface": iface}
        elif action == "stop":
            self.engine.stop()
            return {"success": True, "running": False}
        return {"success": False, "error": "Invalid action"}

    def firewall_action(self, action: str, ip: str) -> Dict[str, Any]:
        from modules.response.iptables_block import IPTablesBlock
        mod = IPTablesBlock(self.session)
        if action == "block":
            ok = mod.block_ip(ip)
            return {"success": ok, "ip": ip, "banned_ips": sorted(list(self.session.banned_ips))}
        elif action == "unblock":
            ok = mod.unblock_ip(ip)
            return {"success": ok, "ip": ip, "banned_ips": sorted(list(self.session.banned_ips))}
        return {"success": False, "error": "Invalid action"}

    def update_whitelist(self, action: str, ip: str) -> Dict[str, Any]:
        if action == "add":
            self.session.add_whitelist(ip)
        elif action == "remove":
            self.session.remove_whitelist(ip)
        return {"success": True, "whitelist": sorted(list(self.session.whitelist))}
