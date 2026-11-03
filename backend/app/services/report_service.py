import io
import csv
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

from app.database.models import SecurityEvent


class NumberedCanvas(canvas.Canvas):
    """Canvas that computes total page count dynamically for 'Page X of Y' footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running header (on pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, letter[1] - 36, "CyberShield NIDPS — SOC Incident & Telemetry Report")
            self.drawRightString(letter[0] - 54, letter[1] - 36, "CONFIDENTIAL / SOC INTERNAL")
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(54, letter[1] - 42, letter[0] - 54, letter[1] - 42)

        # Running footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(letter[0] - 54, 32, page_str)
        self.drawString(54, 32, f"CyberShield Security Platform • Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
        self.setStrokeColor(colors.HexColor("#E2E8F0"))
        self.setLineWidth(0.5)
        self.line(54, 44, letter[0] - 54, 44)

        self.restoreState()


class ReportService:
    """Generates formatted CSV datasets and executive-level PDF forensic audit reports."""

    @staticmethod
    def generate_csv(events: List[SecurityEvent]) -> str:
        """Export security incidents as standardized CSV format."""
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

        # Header
        writer.writerow([
            "Event ID",
            "Timestamp UTC",
            "Attack Type",
            "Severity",
            "Risk Score",
            "Source IP",
            "Destination IP",
            "Destination Port",
            "Detection Method",
            "Action Taken",
            "Status",
            "Evidence Summary"
        ])

        for ev in events:
            # Flatten or summarize evidence
            evidence_summary = ""
            try:
                ev_data = json.loads(ev.evidence_json) if ev.evidence_json else {}
                if isinstance(ev_data, dict):
                    parts = []
                    for k, v in ev_data.items():
                        if k not in ["action_details", "flow_features"]:
                            parts.append(f"{k}={v}")
                    evidence_summary = "; ".join(parts[:5])
            except Exception:
                evidence_summary = str(ev.evidence_json)[:100]

            writer.writerow([
                ev.id,
                ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if ev.timestamp else "",
                ev.attack_type,
                ev.severity,
                f"{ev.risk_score:.1f}",
                ev.source_ip,
                ev.destination_ip or "",
                ev.destination_port or "",
                ev.detection_method,
                ev.action_taken,
                ev.status,
                evidence_summary
            ])

        return output.getvalue()

    @staticmethod
    def _build_styles():
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            name="ReportTitle",
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0F172A"),
        ))
        styles.add(ParagraphStyle(
            name="ReportSubtitle",
            fontName="Helvetica",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#64748B"),
        ))
        styles.add(ParagraphStyle(
            name="SectionHeading",
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=16,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=14,
            spaceAfter=6,
        ))
        styles.add(ParagraphStyle(
            name="MetaLabel",
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#475569"),
        ))
        styles.add(ParagraphStyle(
            name="MetaValue",
            fontName="Helvetica",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#0F172A"),
        ))
        styles.add(ParagraphStyle(
            name="TableHead",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.white,
        ))
        styles.add(ParagraphStyle(
            name="TableCell",
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#1E293B"),
        ))
        styles.add(ParagraphStyle(
            name="TableCellBold",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0F172A"),
        ))
        styles.add(ParagraphStyle(
            name="KpiValue",
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0F172A"),
            alignment=1,  # Center
        ))
        styles.add(ParagraphStyle(
            name="KpiLabel",
            fontName="Helvetica",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748B"),
            alignment=1,  # Center
        ))
        return styles

    @classmethod
    def generate_executive_pdf(
        cls,
        events: List[SecurityEvent],
        stats: Dict[str, Any],
        prevention_mode: str = "OBSERVE"
    ) -> bytes:
        """Generate a comprehensive multi-page SOC Executive Incident Report in PDF format."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        styles = cls._build_styles()
        story = []

        # 1. Header Banner
        header_table = Table(
            [
                [
                    Paragraph("CyberShield SOC", styles["ReportTitle"]),
                    Paragraph("CONFIDENTIAL<br/><font color='#64748B'>SECURITY OPERATIONS REPORT</font>", styles["ReportSubtitle"])
                ]
            ],
            colWidths=[300, 204]
        )
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 4))
        story.append(Paragraph("Intrusion Detection, Threat Scoring & Defense Telemetry Dossier", styles["ReportSubtitle"]))
        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0EA5E9"), spaceAfter=14))

        # 2. Executive Metadata Box
        now_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        meta_data = [
            [
                Paragraph("Report Scope:", styles["MetaLabel"]),
                Paragraph(f"{len(events)} security events evaluated", styles["MetaValue"]),
                Paragraph("Generated Timestamp:", styles["MetaLabel"]),
                Paragraph(now_utc, styles["MetaValue"]),
            ],
            [
                Paragraph("Defense Mode:", styles["MetaLabel"]),
                Paragraph(f"<b>{prevention_mode}</b>", styles["MetaValue"]),
                Paragraph("Classification:", styles["MetaLabel"]),
                Paragraph("TLP:AMBER / SOC RESTRICTED", styles["MetaValue"]),
            ]
        ]
        meta_table = Table(meta_data, colWidths=[95, 155, 115, 139])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # 3. KPI Summary Cards
        critical_count = sum(1 for e in events if e.severity == "CRITICAL")
        high_count = sum(1 for e in events if e.severity == "HIGH")
        medium_count = sum(1 for e in events if e.severity == "MEDIUM")
        blocked_count = sum(1 for e in events if "BLOCK" in (e.action_taken or ""))

        kpi_data = [
            [
                Paragraph(f"<font color='#0EA5E9'>{len(events)}</font>", styles["KpiValue"]),
                Paragraph(f"<font color='#EF4444'>{critical_count}</font>", styles["KpiValue"]),
                Paragraph(f"<font color='#F97316'>{high_count}</font>", styles["KpiValue"]),
                Paragraph(f"<font color='#EAB308'>{medium_count}</font>", styles["KpiValue"]),
                Paragraph(f"<font color='#10B981'>{blocked_count}</font>", styles["KpiValue"]),
            ],
            [
                Paragraph("TOTAL EVENTS", styles["KpiLabel"]),
                Paragraph("CRITICAL SEV", styles["KpiLabel"]),
                Paragraph("HIGH SEV", styles["KpiLabel"]),
                Paragraph("MEDIUM SEV", styles["KpiLabel"]),
                Paragraph("ACTIONS BLOCKED", styles["KpiLabel"]),
            ]
        ]
        kpi_table = Table(kpi_data, colWidths=[100, 100, 100, 100, 104])
        kpi_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 2),
            ("TOPPADDING", (0, 1), (-1, 1), 0),
            ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 14))

        # 4. Attack Distribution Summary Table
        story.append(Paragraph("Threat Category Breakdown", styles["SectionHeading"]))

        attack_counts: Dict[str, int] = {}
        for ev in events:
            attack_counts[ev.attack_type] = attack_counts.get(ev.attack_type, 0) + 1

        dist_data = [
            [
                Paragraph("Threat Category", styles["TableHead"]),
                Paragraph("Incident Count", styles["TableHead"]),
                Paragraph("Percentage of Total", styles["TableHead"]),
                Paragraph("Primary Detection Engine", styles["TableHead"]),
            ]
        ]
        total_ev = max(1, len(events))
        for atype, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True):
            pct = (count / total_ev) * 100.0
            engine = "ML Random Forest" if "ML" in atype or atype in ["DOS_DDOS"] else "Heuristic Rule / Window"
            dist_data.append([
                Paragraph(f"<b>{atype.replace('_', ' ')}</b>", styles["TableCellBold"]),
                Paragraph(f"{count:,}", styles["TableCell"]),
                Paragraph(f"{pct:.1f}%", styles["TableCell"]),
                Paragraph(engine, styles["TableCell"]),
            ])

        dist_table = Table(dist_data, colWidths=[180, 90, 104, 130])
        dist_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(dist_table)
        story.append(Spacer(1, 14))

        # 5. Incident Chronological Ledger
        story.append(Paragraph("Forensic Incident Ledger (Recent Incidents)", styles["SectionHeading"]))

        incidents_data = [
            [
                Paragraph("Timestamp", styles["TableHead"]),
                Paragraph("Threat Type", styles["TableHead"]),
                Paragraph("Source IP", styles["TableHead"]),
                Paragraph("Target", styles["TableHead"]),
                Paragraph("Sev", styles["TableHead"]),
                Paragraph("Score", styles["TableHead"]),
                Paragraph("Action", styles["TableHead"]),
            ]
        ]

        # Show up to 40 most recent
        for ev in events[:40]:
            target_str = f"{ev.destination_ip or '-'}:{ev.destination_port or '-'}"
            sev_color = {
                "CRITICAL": "#DC2626",
                "HIGH": "#EA580C",
                "MEDIUM": "#D97706",
                "LOW": "#2563EB",
                "INFO": "#64748B"
            }.get(ev.severity, "#0F172A")

            incidents_data.append([
                Paragraph(ev.timestamp.strftime("%m-%d %H:%M:%S") if ev.timestamp else "", styles["TableCell"]),
                Paragraph(f"<b>{ev.attack_type[:18]}</b>", styles["TableCell"]),
                Paragraph(f"<font color='#0284C7'>{ev.source_ip}</font>", styles["TableCell"]),
                Paragraph(target_str, styles["TableCell"]),
                Paragraph(f"<font color='{sev_color}'><b>{ev.severity[:4]}</b></font>", styles["TableCell"]),
                Paragraph(f"{ev.risk_score:.0f}", styles["TableCellBold"]),
                Paragraph(ev.action_taken or "NONE", styles["TableCell"]),
            ])

        inc_table = Table(incidents_data, colWidths=[75, 115, 95, 85, 40, 38, 56])
        inc_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(inc_table)
        story.append(Spacer(1, 14))

        # 6. SOC Analyst Notes / Sign-Off
        notes_box = [
            [
                Paragraph("<b>SOC Governance & Methodology Note:</b><br/>"
                          "Threat scoring is computed using calibrated mathematical bounds and Random Forest flow inference "
                          "trained on CIC-IDS2017 intrusion telemetry. Actions executed under active policy engine "
                          "governance with automated IP mitigation logging.", styles["TableCell"])
            ]
        ]
        notes_table = Table(notes_box, colWidths=[504])
        notes_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(KeepTogether(notes_table))

        # Build document
        doc.build(story, canvasmaker=NumberedCanvas)
        buffer.seek(0)
        return buffer.getvalue()

    @classmethod
    def generate_single_incident_pdf(cls, event: SecurityEvent) -> bytes:
        """Generate a detailed 1-2 page Forensic Incident Dossier for a specific alert."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            leftMargin=54,
            rightMargin=54,
            topMargin=54,
            bottomMargin=54,
        )

        styles = cls._build_styles()
        story = []

        # 1. Header
        header_table = Table(
            [
                [
                    Paragraph("CyberShield SOC", styles["ReportTitle"]),
                    Paragraph("INCIDENT FORENSIC DOSSIER<br/><font color='#64748B'>CASE: " + event.id[:8] + "</font>", styles["ReportSubtitle"])
                ]
            ],
            colWidths=[300, 204]
        )
        header_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ]))
        story.append(header_table)
        story.append(Spacer(1, 6))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#EF4444" if event.severity in ["HIGH", "CRITICAL"] else "#0EA5E9"), spaceAfter=14))

        # 2. Key Attributes Grid
        sev_color = {
            "CRITICAL": "#DC2626",
            "HIGH": "#EA580C",
            "MEDIUM": "#D97706",
            "LOW": "#2563EB",
            "INFO": "#64748B"
        }.get(event.severity, "#0F172A")

        summary_data = [
            [
                Paragraph("Incident ID:", styles["MetaLabel"]),
                Paragraph(f"<font name='Courier'>{event.id}</font>", styles["MetaValue"]),
                Paragraph("Timestamp:", styles["MetaLabel"]),
                Paragraph(event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if event.timestamp else "", styles["MetaValue"]),
            ],
            [
                Paragraph("Attack Type:", styles["MetaLabel"]),
                Paragraph(f"<b>{event.attack_type.replace('_', ' ')}</b>", styles["MetaValue"]),
                Paragraph("Severity:", styles["MetaLabel"]),
                Paragraph(f"<font color='{sev_color}'><b>{event.severity}</b></font>", styles["MetaValue"]),
            ],
            [
                Paragraph("Attacker Source:", styles["MetaLabel"]),
                Paragraph(f"<font color='#0284C7'><b>{event.source_ip}</b></font>", styles["MetaValue"]),
                Paragraph("Calculated Risk:", styles["MetaLabel"]),
                Paragraph(f"<b>{event.risk_score:.1f} / 100</b>", styles["MetaValue"]),
            ],
            [
                Paragraph("Victim Target:", styles["MetaLabel"]),
                Paragraph(f"{event.destination_ip or 'Local Host'}:{event.destination_port or '-'}", styles["MetaValue"]),
                Paragraph("Action Enacted:", styles["MetaLabel"]),
                Paragraph(f"<b>{event.action_taken}</b>", styles["MetaValue"]),
            ],
            [
                Paragraph("Detection Pipeline:", styles["MetaLabel"]),
                Paragraph(event.detection_method, styles["MetaValue"]),
                Paragraph("Status:", styles["MetaLabel"]),
                Paragraph(event.status, styles["MetaValue"]),
            ]
        ]
        sum_table = Table(summary_data, colWidths=[105, 150, 105, 144])
        sum_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(sum_table)
        story.append(Spacer(1, 16))

        # 3. Technical Evidence & Flow Telemetry
        story.append(Paragraph("Forensic Evidence & Threat Indicators", styles["SectionHeading"]))

        evidence_rows = [
            [
                Paragraph("Attribute / Metric", styles["TableHead"]),
                Paragraph("Observed Telemetry Value", styles["TableHead"])
            ]
        ]

        try:
            ev_data = json.loads(event.evidence_json) if event.evidence_json else {}
            if isinstance(ev_data, dict):
                for k, v in ev_data.items():
                    if k == "flow_features" and isinstance(v, dict):
                        for fk, fv in v.items():
                            evidence_rows.append([
                                Paragraph(f"Flow Feature • {fk}", styles["TableCellBold"]),
                                Paragraph(str(fv), styles["TableCell"])
                            ])
                    elif k == "action_details" and isinstance(v, dict):
                        evidence_rows.append([
                            Paragraph("Prevention Details", styles["TableCellBold"]),
                            Paragraph(json.dumps(v), styles["TableCell"])
                        ])
                    elif k == "score_breakdown" and isinstance(v, dict):
                        breakdown_str = ", ".join(f"{bk}: {bv}" for bk, bv in v.items())
                        evidence_rows.append([
                            Paragraph("Score Breakdown", styles["TableCellBold"]),
                            Paragraph(breakdown_str, styles["TableCell"])
                        ])
                    else:
                        evidence_rows.append([
                            Paragraph(str(k), styles["TableCellBold"]),
                            Paragraph(str(v), styles["TableCell"])
                        ])
        except Exception:
            evidence_rows.append([
                Paragraph("Raw Evidence Payload", styles["TableCellBold"]),
                Paragraph(str(event.evidence_json), styles["TableCell"])
            ])

        ev_table = Table(evidence_rows, colWidths=[200, 304])
        ev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(ev_table)
        story.append(Spacer(1, 16))

        # 4. Analyst Signature / Chain of Custody
        sign_data = [
            [
                Paragraph("<b>Investigating Analyst:</b> CyberShield Autonomous SOC Agent", styles["TableCell"]),
                Paragraph("<b>Review Status:</b> Verified Alert", styles["TableCell"]),
            ],
            [
                Paragraph("<b>Recommended Next Step:</b> Maintain IP reputation tracking & update IOC catalog", styles["TableCell"]),
                Paragraph("<b>TLP Level:</b> AMBER", styles["TableCell"]),
            ]
        ]
        sign_table = Table(sign_data, colWidths=[252, 252])
        sign_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(KeepTogether(sign_table))

        doc.build(story, canvasmaker=NumberedCanvas)
        buffer.seek(0)
        return buffer.getvalue()


report_service = ReportService()
