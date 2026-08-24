from core.module_base import ModuleBase
import json
import os
import time


class JSONExport(ModuleBase):
    """
    SIEM & SOC Threat Feed Exporter.
    Exports session alerts and inventory telemetry to JSONL, Common Event Format (CEF),
    or Syslog-ready records for Splunk, Elastic SIEM, Wazuh, and QRadar ingestion.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "FORMAT": {"value": "jsonl", "required": True, "desc": "jsonl | json | cef"},
            "OUTPUT": {"value": "reports/alerts_siem.jsonl", "required": True, "desc": "Destination file path"},
        }

    def _to_cef(self, alert: dict) -> str:
        # CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
        vendor = "ANDS"
        product = "ANDS-Sentinel"
        version = "2.0"
        class_id = alert.get("mitre_id", "T1046")
        name = alert.get("type", "SecurityAlert")
        sev_map = {"CRITICAL": "10", "HIGH": "7", "MEDIUM": "5", "LOW": "3", "INFO": "1"}
        sev = sev_map.get(alert.get("severity", "MEDIUM"), "5")
        ext = f"src={alert.get('source', '')} dst={alert.get('destination', '')} proto={alert.get('protocol', '')} msg={alert.get('description', '')}"
        return f"CEF:0|{vendor}|{product}|{version}|{class_id}|{name}|{sev}|{ext}"

    def run(self):
        fmt = self.options["FORMAT"]["value"].lower().strip()
        out_path = self.options["OUTPUT"]["value"]
        alerts = self.session.alert_history

        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)

        if fmt == "json":
            with open(out_path, "w") as f:
                json.dump(alerts, f, indent=2)
        elif fmt == "cef":
            with open(out_path, "w") as f:
                for a in alerts:
                    f.write(self._to_cef(a) + "\n")
        else:  # jsonl
            with open(out_path, "w") as f:
                for a in alerts:
                    f.write(json.dumps(a) + "\n")

        print(f"[+] Exported {len(alerts)} alert(s) in {fmt.upper()} format to {out_path}")
        self.session.artifacts["siem_export"] = out_path
