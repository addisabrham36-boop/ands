from core.module_base import ModuleBase
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import os
from datetime import datetime


class ReportGenerator(ModuleBase):
    def __init__(self, session):
        super().__init__(session)
        self.options = {
            "OUTPUT": {"value": "reports/report.pdf", "required": True, "desc": "Output PDF path"},
        }

    def run(self):
        output = self.options["OUTPUT"]["value"]
        os.makedirs(os.path.dirname(output), exist_ok=True)

        alerts = self.session.alert_history
        doc = SimpleDocTemplate(output, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("ANDS Security Report", styles["Title"]))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        story.append(Paragraph(
            f"{len(alerts)} alert(s) detected during this session.", styles["Normal"]
        ))
        story.append(Spacer(1, 12))

        if alerts:
            story.append(Paragraph("Findings", styles["Heading2"]))
            table_data = [["Type", "Source/Window", "Detail"]]
            for a in alerts:
                if a["type"] == "PORT_SCAN":
                    table_data.append(["PORT_SCAN", a.get("source", ""), f"{a.get('port_count', '')} ports"])
                elif a["type"] == "ANOMALY":
                    table_data.append(["ANOMALY", f"window {a.get('window', '')}", f"z={a.get('zscore', '')}"])
                else:
                    table_data.append([a["type"], "", str(a)])

            t = Table(table_data, colWidths=[100, 150, 200])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]))
            story.append(t)
        else:
            story.append(Paragraph("No alerts recorded this session.", styles["Normal"]))

        doc.build(story)
        print(f"[+] Report saved to {output}")
        self.session.artifacts["report"] = output