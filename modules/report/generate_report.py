from core.module_base import ModuleBase
import os
import time
from datetime import datetime


class ReportGenerator(ModuleBase):
    """
    Executive SOC Incident & Security Audit Report Generator.
    Produces comprehensive HTML and PDF audit summaries with MITRE ATT&CK
    matrix mappings, severity breakdowns, threat timelines, and mitigation advice.
    """

    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "FORMAT": {"value": "html", "required": True, "desc": "html | pdf | both"},
            "OUTPUT_HTML": {"value": "reports/report.html", "required": False, "desc": "Output HTML report path"},
            "OUTPUT_PDF": {"value": "reports/report.pdf", "required": False, "desc": "Output PDF report path"},
        }

    def _generate_html(self, output_path: str):
        alerts = self.session.alert_history
        inventory = self.session.get_inventory()

        crit_count = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        high_count = sum(1 for a in alerts if a.get("severity") == "HIGH")
        med_count = sum(1 for a in alerts if a.get("severity") == "MEDIUM")
        low_count = sum(1 for a in alerts if a.get("severity") in ("LOW", "INFO"))

        rows_html = ""
        for a in alerts:
            sev = a.get("severity", "MEDIUM")
            badge_color = "#ef4444" if sev == "CRITICAL" else ("#f97316" if sev == "HIGH" else ("#eab308" if sev == "MEDIUM" else "#3b82f6"))
            rows_html += f"""
            <tr>
                <td><strong>{a.get('timestamp', '')}</strong></td>
                <td><span style="background:{badge_color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">{sev}</span></td>
                <td><code>{a.get('type', '')}</code></td>
                <td><span style="background:#1e293b;color:#38bdf8;padding:2px 6px;border-radius:4px;font-size:11px;">{a.get('mitre_id', 'N/A')}</span></td>
                <td><strong>{a.get('source', 'N/A')}</strong></td>
                <td>{a.get('destination', 'N/A')}</td>
                <td>{a.get('description', '')}</td>
                <td>{int(a.get('confidence', 0.75)*100)}%</td>
            </tr>
            """

        inv_html = ""
        for h in inventory:
            ports = ",".join(str(p) for p in h["ports"][:5]) or "None"
            inv_html += f"""
            <tr>
                <td><strong>{h['ip']}</strong></td>
                <td>{h['mac'] or 'N/A'}</td>
                <td>{h['vendor'] or 'Unknown'}</td>
                <td>{h['os_hint'] or 'Unknown'}</td>
                <td><code>{ports}</code></td>
                <td><strong style="color:{'#ef4444' if h['alerts'] > 0 else '#22c55e'}">{h['alerts']}</strong></td>
            </tr>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ANDS Security Audit & SOC Incident Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 30px; line-height: 1.5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 30px; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 25px; }}
        .title {{ font-size: 24px; font-weight: 800; color: #38bdf8; letter-spacing: -0.5px; }}
        .subtitle {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }}
        .card {{ background: #0f172a; padding: 18px; border-radius: 8px; border-left: 4px solid #38bdf8; }}
        .card.crit {{ border-left-color: #ef4444; }}
        .card.high {{ border-left-color: #f97316; }}
        .card.med {{ border-left-color: #eab308; }}
        .card.low {{ border-left-color: #3b82f6; }}
        .card-num {{ font-size: 28px; font-weight: 800; }}
        .card-label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase; font-weight: 600; }}
        h2 {{ font-size: 18px; color: #e2e8f0; border-bottom: 1px solid #334155; padding-bottom: 8px; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
        th {{ background: #0f172a; color: #94a3b8; text-align: left; padding: 10px 12px; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #334155; }}
        tr:hover td {{ background: rgba(56, 189, 248, 0.05); }}
        code {{ font-family: 'JetBrains Mono', Consolas, Monaco, monospace; color: #38bdf8; }}
        .footer {{ margin-top: 40px; padding-top: 15px; border-top: 1px solid #334155; font-size: 12px; color: #64748b; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="title">🛡️ ANDS SOC Incident & Threat Audit Report</div>
                <div class="subtitle">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Environment: Arch Linux Engine</div>
            </div>
            <div style="text-align:right;">
                <span style="background:rgba(56,189,248,0.1);color:#38bdf8;padding:6px 12px;border-radius:20px;font-size:12px;font-weight:700;border:1px solid rgba(56,189,248,0.3)">ANDS v2.0 SOC AUDITOR</span>
            </div>
        </div>

        <div class="grid">
            <div class="card crit">
                <div class="card-label">Critical Threats</div>
                <div class="card-num" style="color:#ef4444;">{crit_count}</div>
            </div>
            <div class="card high">
                <div class="card-label">High Severity</div>
                <div class="card-num" style="color:#f97316;">{high_count}</div>
            </div>
            <div class="card med">
                <div class="card-label">Medium Severity</div>
                <div class="card-num" style="color:#eab308;">{med_count}</div>
            </div>
            <div class="card low">
                <div class="card-label">Active Discovered Assets</div>
                <div class="card-num" style="color:#38bdf8;">{len(inventory)}</div>
            </div>
        </div>

        <h2>🚨 Detected Threat Findings & Security Anomalies ({len(alerts)})</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Severity</th>
                    <th>Alert Type</th>
                    <th>MITRE ATT&CK</th>
                    <th>Attacker / Source</th>
                    <th>Target</th>
                    <th>Description</th>
                    <th>Confidence</th>
                </tr>
            </thead>
            <tbody>
                {rows_html if rows_html else '<tr><td colspan="8" style="text-align:center;color:#64748b;padding:20px;">No alerts detected during this session.</td></tr>'}
            </tbody>
        </table>

        <h2>🗺️ Network Asset Inventory & Passive Discovery ({len(inventory)})</h2>
        <table>
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Hardware Vendor</th>
                    <th>OS Fingerprint</th>
                    <th>Active Ports</th>
                    <th>Alert Count</th>
                </tr>
            </thead>
            <tbody>
                {inv_html if inv_html else '<tr><td colspan="6" style="text-align:center;color:#64748b;padding:20px;">No network assets mapped yet.</td></tr>'}
            </tbody>
        </table>

        <div class="footer">
            ANDS (Anomaly-based Network Detection System) — Cyber Defense & Auditing Suite | Bahir Dar University / INSA
        </div>
    </div>
</body>
</html>"""

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w") as f:
            f.write(html_content)
        print(f"[+] HTML Report generated: {output_path}")
        self.session.artifacts["html_report"] = output_path

    def _generate_pdf(self, output_path: str):
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors

            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            alerts = self.session.alert_history
            doc = SimpleDocTemplate(output_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []

            story.append(Paragraph("ANDS SOC Incident & Security Audit Report", styles["Title"]))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
            story.append(Spacer(1, 14))

            story.append(Paragraph("Executive Summary", styles["Heading2"]))
            story.append(Paragraph(f"A total of {len(alerts)} security threat alert(s) and {len(self.session.network_inventory)} active assets were recorded.", styles["Normal"]))
            story.append(Spacer(1, 12))

            if alerts:
                story.append(Paragraph("Threat Incident Findings", styles["Heading2"]))
                table_data = [["Severity", "Type", "MITRE", "Source", "Target", "Confidence"]]
                for a in alerts:
                    table_data.append([
                        a.get("severity", "MED"),
                        a.get("type", ""),
                        a.get("mitre_id", "N/A"),
                        a.get("source", "")[:18],
                        a.get("destination", "")[:18],
                        f"{int(a.get('confidence', 0.75)*100)}%",
                    ])

                t = Table(table_data, colWidths=[65, 110, 60, 110, 110, 65])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]))
                story.append(t)

            doc.build(story)
            print(f"[+] PDF Report generated: {output_path}")
            self.session.artifacts["pdf_report"] = output_path
        except Exception as e:
            print(f"[-] PDF generation error: {e}")

    def run(self):
        fmt = self.options["FORMAT"]["value"].lower().strip()
        html_path = self.options["OUTPUT_HTML"]["value"] or "reports/report.html"
        pdf_path = self.options["OUTPUT_PDF"]["value"] or "reports/report.pdf"

        if fmt in ("html", "both"):
            self._generate_html(html_path)
        if fmt in ("pdf", "both"):
            self._generate_pdf(pdf_path)