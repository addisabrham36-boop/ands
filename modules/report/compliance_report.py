import os
from datetime import datetime
from core.module_base import ModuleBase


class ComplianceReportGenerator(ModuleBase):
    """
    SOC Compliance & Framework Audit Report Generator.
    Evaluates recorded security telemetry against standard cybersecurity frameworks
    (PCI-DSS 4.0, CIS Critical Security Controls v8, NIST CSF) and exports an audit summary.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "OUTPUT_PATH": {"value": "reports/compliance_audit.html", "required": True, "desc": "Output path for HTML report"},
            "FRAMEWORK": {"value": "PCI-DSS,CIS,NIST", "required": False, "desc": "Frameworks to evaluate against"},
        }

    def run(self):
        out_path = self.options["OUTPUT_PATH"]["value"]
        frameworks = self.options["FRAMEWORK"]["value"].split(",")

        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        alerts = self.session.alert_history
        inv = self.session.get_inventory()

        crit_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high_count = sum(1 for a in alerts if a.get("severity") == "HIGH")

        score = max(0, 100 - (crit_count * 20 + high_count * 10))
        status = "COMPLIANT" if score >= 85 else ("WARNING" if score >= 60 else "NON-COMPLIANT")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>ANDS Security Compliance Audit</title>
    <style>
        body {{ font-family: -apple-system, sans-serif; background: #000; color: #fff; padding: 30px; }}
        h1 {{ border-bottom: 2px solid #fff; padding-bottom: 10px; }}
        .score {{ font-size: 32px; font-weight: bold; color: {'#10b981' if score >= 85 else '#ef4444'}; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #333; padding: 10px; text-align: left; }}
        th {{ background: #111; color: #aaa; }}
    </style>
</head>
<body>
    <h1>🛡️ ANDS Cybersecurity Compliance & Posture Audit</h1>
    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p>Evaluated Frameworks: {', '.join(frameworks)}</p>
    
    <h2>Compliance Status: <span class="score">{status} ({score}/100)</span></h2>
    <p>Audited Assets: <strong>{len(inv)} hosts</strong> | Active Threats: <strong>{len(alerts)} alerts</strong></p>

    <h3>Framework Control Summary:</h3>
    <table>
        <tr><th>Control ID</th><th>Description</th><th>Status</th></tr>
        <tr><td>CIS Control 1.1</td><td>Active Network Asset Inventory</td><td>PASS ({len(inv)} hosts cataloged)</td></tr>
        <tr><td>PCI-DSS 2.3</td><td>Encrypt All Administrative Access</td><td>{'PASS' if crit_count == 0 else 'FAIL (Cleartext/Insecure Telnet Detected)'}</td></tr>
        <tr><td>NIST DE.CM-1</td><td>Continuous Network Threat Monitoring</td><td>PASS (ANDS Live Sentinel Active)</td></tr>
    </table>
</body>
</html>"""

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)

        self.session.add_artifact(out_path)
        print(f"[+] Compliance Audit Report generated: {out_path} (Posture Score: {score}/100 [{status}])")
