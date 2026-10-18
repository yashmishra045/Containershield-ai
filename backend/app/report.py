"""
report.py
Generates a PDF security report for a completed scan using ReportLab.
"""

import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


# ============================================================
# SEVERITY COLORS
# ============================================================

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#b91c1c"),
    "HIGH": colors.HexColor("#dc2626"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#65a30d"),
    "NEGLIGIBLE": colors.HexColor("#6b7280"),
    "UNKNOWN": colors.HexColor("#6b7280"),
}


# ============================================================
# PDF REPORT GENERATOR
# ============================================================

def generate_pdf_report(
    scan,
    vulnerabilities,
    secrets,
    sbom_components
) -> bytes:

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=1.5 * cm,
        bottomMargin=1.5 * cm,
        leftMargin=1.2 * cm,
        rightMargin=1.2 * cm,
        title="ContainerShield AI Security Report",
        author="ContainerShield AI",
    )

    styles = getSampleStyleSheet()

    # --------------------------------------------------------
    # Styles
    # --------------------------------------------------------

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#111827"),
        spaceAfter=8,
    )

    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#111827"),
        spaceBefore=12,
        spaceAfter=7,
    )

    normal_style = ParagraphStyle(
        "NormalReport",
        parent=styles["Normal"],
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#111827"),
    )

    table_style = ParagraphStyle(
        "TableText",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        alignment=TA_LEFT,
        textColor=colors.HexColor("#111827"),
        wordWrap="CJK",
    )

    table_header_style = ParagraphStyle(
        "TableHeader",
        parent=table_style,
        fontSize=7,
        leading=9,
        textColor=colors.white,
    )

    # --------------------------------------------------------
    # Helper functions
    # --------------------------------------------------------

    def p(value, style=table_style):
        """
        Convert any value into a ReportLab Paragraph.
        Paragraphs automatically wrap long text inside cells.
        """
        if value is None or value == "":
            value = "-"
        return Paragraph(str(value), style)

    def severity_paragraph(severity):
        """
        Create a colored severity label.
        """
        severity = str(severity or "UNKNOWN").upper()

        severity_style = ParagraphStyle(
            f"Severity_{severity}",
            parent=table_style,
            textColor=SEVERITY_COLORS.get(
                severity,
                colors.HexColor("#111827")
            ),
            fontName="Helvetica-Bold",
        )

        return Paragraph(severity, severity_style)

    # ========================================================
    # DOCUMENT CONTENT
    # ========================================================

    elements = []

    # --------------------------------------------------------
    # Title
    # --------------------------------------------------------

    elements.append(
        Paragraph(
            "ContainerShield AI — Security Report",
            title_style
        )
    )

    elements.append(Spacer(1, 4))

    # --------------------------------------------------------
    # Scan Information
    # --------------------------------------------------------

    scan_info = [
        ["Image", str(getattr(scan, "image_name", "-"))],
        ["Scan ID", str(getattr(scan, "id", "-"))],
        ["Status", str(getattr(scan, "status", "-"))],
        [
            "Risk Score",
            f"{getattr(scan, 'risk_score', 0)} / 100"
        ],
        ["Scanned At", str(getattr(scan, "created_at", "-"))],
    ]

    scan_info_data = []

    for key, value in scan_info:
        scan_info_data.append([
            p(key, ParagraphStyle(
                "InfoKey",
                parent=table_style,
                fontName="Helvetica-Bold",
            )),
            p(value),
        ])

    scan_info_table = Table(
        scan_info_data,
        colWidths=[3.0 * cm, 14.0 * cm],
    )

    scan_info_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e5e7eb")),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9ca3af")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )

    elements.append(scan_info_table)
    elements.append(Spacer(1, 12))

    # ========================================================
    # VULNERABILITY SUMMARY
    # ========================================================

    elements.append(
        Paragraph(
            "Vulnerability Summary",
            heading_style
        )
    )

    sev_counts = {}

    for v in vulnerabilities:
        severity = str(
            getattr(v, "severity", "UNKNOWN") or "UNKNOWN"
        ).upper()

        sev_counts[severity] = sev_counts.get(severity, 0) + 1

    severity_order = [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "NEGLIGIBLE",
        "UNKNOWN",
    ]

    summary_data = [
        [
            p("Severity", table_header_style),
            p("Count", table_header_style),
        ]
    ]

    for severity in severity_order:
        if severity in sev_counts:
            summary_data.append([
                severity_paragraph(severity),
                p(sev_counts[severity]),
            ])

    if not sev_counts:
        summary_data.append([
            p("None found"),
            p("0"),
        ])

    summary_table = Table(
        summary_data,
        colWidths=[7 * cm, 4 * cm],
        repeatRows=1,
    )

    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#9ca3af")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ])
    )

    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # ========================================================
    # VULNERABILITY DETAILS
    # ========================================================

    elements.append(
        Paragraph(
            "Vulnerability Details",
            heading_style
        )
    )

    vuln_data = [[
        p("CVE ID", table_header_style),
        p("Package", table_header_style),
        p("Installed", table_header_style),
        p("Fixed", table_header_style),
        p("Severity", table_header_style),
        p("Tool", table_header_style),
    ]]

    # Keep PDF reasonably sized
    vulnerability_limit = 500

    for v in vulnerabilities[:vulnerability_limit]:

        vuln_data.append([
            p(getattr(v, "cve_id", "-")),
            p(getattr(v, "package", "-")),
            p(getattr(v, "installed_version", "-")),
            p(getattr(v, "fixed_version", "-")),
            severity_paragraph(
                getattr(v, "severity", "UNKNOWN")
            ),
            p(getattr(v, "source_tool", "-")),
        ])

    # --------------------------------------------------------
    # IMPORTANT:
    # Wider Installed / Fixed columns prevent overflow.
    # Paragraphs allow automatic text wrapping.
    # --------------------------------------------------------

    vuln_table = Table(
        vuln_data,
        colWidths=[
            3.0 * cm,   # CVE
            3.0 * cm,   # Package
            3.2 * cm,   # Installed
            2.8 * cm,   # Fixed
            2.1 * cm,   # Severity
            1.5 * cm,   # Tool
        ],
        repeatRows=1,
    )

    vuln_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),

            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9ca3af")),

            ("VALIGN", (0, 0), (-1, -1), "TOP"),

            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),

            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#f8fafc"),
            ]),
        ])
    )

    elements.append(vuln_table)
    elements.append(Spacer(1, 12))

    # ========================================================
    # EXPOSED SECRETS
    # ========================================================

    elements.append(
        Paragraph(
            "Exposed Secrets",
            heading_style
        )
    )

    if secrets:

        secret_data = [[
            p("File Path", table_header_style),
            p("Rule", table_header_style),
            p("Match (redacted)", table_header_style),
        ]]

        for s in secrets[:100]:

            secret_data.append([
                p(getattr(s, "file_path", "-")),
                p(getattr(s, "rule_id", "-")),
                p(getattr(s, "match_snippet", "-")),
            ])

        secret_table = Table(
            secret_data,
            colWidths=[
                7.0 * cm,
                4.0 * cm,
                5.0 * cm,
            ],
            repeatRows=1,
        )

        secret_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9ca3af")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),

                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),

                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                    colors.white,
                    colors.HexColor("#f8fafc"),
                ]),
            ])
        )

        elements.append(secret_table)

    else:

        elements.append(
            Paragraph(
                "No secrets detected.",
                normal_style
            )
        )

    elements.append(Spacer(1, 12))

    # ========================================================
    # SBOM
    # ========================================================

    elements.append(
        Paragraph(
            f"SBOM ({len(sbom_components)} components)",
            heading_style
        )
    )

    elements.append(
        Paragraph(
            "Top 30 components are shown below. "
            "The complete SBOM is available through the scan API.",
            normal_style
        )
    )

    elements.append(Spacer(1, 5))

    sbom_data = [[
        p("Component", table_header_style),
        p("Version", table_header_style),
        p("Type", table_header_style),
    ]]

    for c in sbom_components[:30]:

        sbom_data.append([
            p(getattr(c, "component_name", "-")),
            p(getattr(c, "version", "-")),
            p(getattr(c, "component_type", "-")),
        ])

    sbom_table = Table(
        sbom_data,
        colWidths=[
            8.0 * cm,
            5.0 * cm,
            3.0 * cm,
        ],
        repeatRows=1,
    )

    sbom_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#9ca3af")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),

            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),

            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [
                colors.white,
                colors.HexColor("#f8fafc"),
            ]),
        ])
    )

    elements.append(sbom_table)

    # ========================================================
    # BUILD PDF
    # ========================================================

    doc.build(elements)

    buffer.seek(0)

    return buffer.read()