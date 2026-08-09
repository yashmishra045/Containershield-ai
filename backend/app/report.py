"""
report.py
Generates a PDF security report for a completed scan using ReportLab.
"""
import io
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH": colors.HexColor("#dc2626"),
    "MEDIUM": colors.HexColor("#d97706"),
    "LOW": colors.HexColor("#65a30d"),
    "UNKNOWN": colors.HexColor("#6b7280"),
}


def generate_pdf_report(scan, vulnerabilities, secrets, sbom_components) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=1.8 * cm, rightMargin=1.8 * cm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#111827")
    )
    heading_style = ParagraphStyle(
        "HeadingStyle", parent=styles["Heading2"], spaceBefore=14, spaceAfter=6
    )

    elements = []
    elements.append(Paragraph("ContainerShield AI — Security Report", title_style))
    elements.append(Spacer(1, 6))
    elements.append(Paragraph(f"<b>Image:</b> {scan.image_name}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Scan ID:</b> {scan.id}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Status:</b> {scan.status}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Risk Score:</b> {scan.risk_score} / 100", styles["Normal"]))
    elements.append(Paragraph(f"<b>Scanned at:</b> {scan.created_at}", styles["Normal"]))
    elements.append(Spacer(1, 10))

    # --- Vulnerability summary ---
    elements.append(Paragraph("Vulnerability Summary", heading_style))
    sev_counts = {}
    for v in vulnerabilities:
        sev_counts[v.severity] = sev_counts.get(v.severity, 0) + 1
    summary_data = [["Severity", "Count"]] + [[k, str(v)] for k, v in sev_counts.items()] or [["None found", "0"]]
    summary_table = Table(summary_data, colWidths=[6 * cm, 4 * cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # --- Vulnerability details ---
    elements.append(Paragraph("Vulnerability Details", heading_style))
    vuln_data = [["CVE ID", "Package", "Installed", "Fixed", "Severity", "Tool"]]
    for v in vulnerabilities[:200]:  # cap to keep PDF manageable
        vuln_data.append([
            v.cve_id, v.package, v.installed_version or "-",
            v.fixed_version or "-", v.severity, v.source_tool
        ])
    vuln_table = Table(vuln_data, colWidths=[3.2 * cm, 3.2 * cm, 2.3 * cm, 2.3 * cm, 2.2 * cm, 1.8 * cm])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, v in enumerate(vulnerabilities[:200], start=1):
        color = SEVERITY_COLORS.get(v.severity, colors.black)
        style_cmds.append(("TEXTCOLOR", (4, i), (4, i), color))
    vuln_table.setStyle(TableStyle(style_cmds))
    elements.append(vuln_table)
    elements.append(Spacer(1, 10))

    # --- Secrets ---
    elements.append(Paragraph("Exposed Secrets", heading_style))
    if secrets:
        secret_data = [["File Path", "Rule", "Match (redacted)"]]
        for s in secrets[:100]:
            secret_data.append([s.file_path, s.rule_id, s.match_snippet])
        secret_table = Table(secret_data, colWidths=[7 * cm, 4 * cm, 4 * cm])
        secret_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ]))
        elements.append(secret_table)
    else:
        elements.append(Paragraph("No secrets detected.", styles["Normal"]))
    elements.append(Spacer(1, 10))

    # --- SBOM ---
    elements.append(Paragraph(f"SBOM ({len(sbom_components)} components)", heading_style))
    elements.append(Paragraph(
        "Full component list is available via the /scan/{id} API endpoint. "
        "Top 30 components shown below.", styles["Normal"]
    ))
    sbom_data = [["Component", "Version", "Type"]]
    for c in sbom_components[:30]:
        sbom_data.append([c.component_name, c.version or "-", c.component_type or "-"])
    sbom_table = Table(sbom_data, colWidths=[7 * cm, 4 * cm, 4 * cm])
    sbom_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
    ]))
    elements.append(sbom_table)

    doc.build(elements)
    buffer.seek(0)
    return buffer.read()
