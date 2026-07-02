"""PDF Export service for security scan reports."""
from io import BytesIO
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from datetime import datetime

from app.models import Scan


class PDFReportGenerator:
    """Generate PDF reports for security scans."""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()
    
    def _add_custom_styles(self):
        """Add custom styles for the PDF."""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#0066cc'),
            spaceAfter=30,
            alignment=1
        ))
        
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#0066cc'),
            spaceAfter=12,
            spaceBefore=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Heading3'],
            fontSize=11,
            textColor=colors.HexColor('#0066cc'),
            spaceAfter=6
        ))
    
    def generate(self, scan: Scan) -> BytesIO:
        """Generate a PDF report for a scan."""
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []
        
        # Title
        story.append(Paragraph("Reporte de Seguridad OWASP", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.1 * inch))
        
        # Summary info
        summary_data = [
            ["Número de Reporte:", f"#{scan.id}"],
            ["Fecha de Análisis:", scan.created_at.strftime("%d/%m/%Y %H:%M:%S")],
            ["Tipo de Objetivo:", scan.target_type.upper()],
            ["Puntuación de Seguridad:", f"{scan.score}/100"],
            ["Total de Hallazgos:", str(len(scan.findings))],
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e5e7eb')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3 * inch))
        
        # Findings
        if scan.findings:
            story.append(Paragraph("Vulnerabilidades Detectadas", self.styles['SectionTitle']))
            story.append(Spacer(1, 0.1 * inch))
            
            for idx, finding in enumerate(scan.findings, 1):
                # Finding header
                severity_color = {
                    'high': '#dc2626',
                    'medium': '#d97706',
                    'low': '#16a34a'
                }.get(finding.severity, '#000000')
                
                story.append(Paragraph(
                    f"{idx}. {finding.rule_id} - {finding.title}",
                    self.styles['FindingTitle']
                ))
                
                # Severity and penalty
                severity_text = f"<b>Severidad:</b> {finding.severity.upper()} | <b>Penalización:</b> -{finding.penalty} pts"
                story.append(Paragraph(severity_text, self.styles['Normal']))
                story.append(Spacer(1, 0.05 * inch))
                
                # Description
                story.append(Paragraph(f"<b>Descripción:</b>", self.styles['Normal']))
                story.append(Paragraph(finding.description, self.styles['Normal']))
                story.append(Spacer(1, 0.1 * inch))
                
                # Evidence
                if finding.evidence:
                    story.append(Paragraph(f"<b>Evidencia:</b>", self.styles['Normal']))
                    evidence_text = finding.evidence.replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(f"<font face='Courier'>{evidence_text}</font>", self.styles['Normal']))
                    story.append(Spacer(1, 0.1 * inch))
                
                # Remediation
                if finding.remediation:
                    story.append(Paragraph(f"<b>Cómo Solucionar:</b>", self.styles['Normal']))
                    remediation_text = finding.remediation.replace('<', '&lt;').replace('>', '&gt;')
                    story.append(Paragraph(f"<font face='Courier' size='9'>{remediation_text}</font>", self.styles['Normal']))
                
                story.append(Spacer(1, 0.2 * inch))
                if idx < len(scan.findings):
                    story.append(PageBreak())
        else:
            story.append(Paragraph("✓ Sin vulnerabilidades detectadas", self.styles['Normal']))
        
        # Footer
        story.append(Spacer(1, 0.3 * inch))
        story.append(Paragraph(
            f"<i>Reporte generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</i>",
            self.styles['Normal']
        ))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer


def export_scan_to_pdf(scan: Scan) -> BytesIO:
    """Convenience function to export a scan to PDF."""
    generator = PDFReportGenerator()
    return generator.generate(scan)
