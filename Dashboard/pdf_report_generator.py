"""
PDF Report Generator Module

This module contains the generate_pdf_report function for creating professional PDF reports
from vendor risk assessment data. The function generates comprehensive security reports
with modern styling. Branding is configurable through REPORT_BRAND_NAME,
REPORT_BRAND_COLOR and REPORT_LOGO_PATH.
"""

import logging
from io import BytesIO
import datetime
import os
import requests
from PIL import Image as PILImage

# ReportLab imports
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, Image, Flowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Drawing, Circle, String
from reportlab.graphics import renderPDF

# Report branding (override in .env). BRAND_NAME is printed on the title
# page and in the page header unless REPORT_LOGO_PATH points to an image.
BRAND_NAME = os.getenv('REPORT_BRAND_NAME', 'Vendiant')
BRAND_COLOR = os.getenv('REPORT_BRAND_COLOR', '#2563EB')
BRAND_LOGO_PATH = os.getenv('REPORT_LOGO_PATH', '')


def escape_domain_for_pdf(domain):
    """Escape domain text to prevent ReportLab from auto-converting it to a clickable link"""
    if not domain:
        return domain
    # Strip "www." prefix to prevent URL auto-detection
    domain = domain.strip()
    if domain.lower().startswith('www.'):
        domain = domain[4:]  # Remove "www." prefix
    
    # Replace dots with HTML entity &#46; which renders as a dot but prevents URL auto-detection
    # This makes domains appear as plain text without being converted to clickable links
    return domain.replace('.', '&#46;')


class CircleBadge(Flowable):
    """Custom flowable for a perfect circular badge with a letter inside"""
    
    def __init__(self, letter, size, border_color, text_color, border_width=2, filled=False):
        Flowable.__init__(self)
        self.letter = letter
        self.size = size
        self.border_color = border_color
        self.text_color = text_color
        self.border_width = border_width
        self.filled = filled
        self.width = size
        self.height = size
    
    def draw(self):
        """Draw a perfect circle with text centered inside"""
        canvas = self.canv
        
        # Save state
        canvas.saveState()
        
        # Calculate center
        center_x = self.size / 2
        center_y = self.size / 2
        radius = (self.size / 2) - (self.border_width / 2)
        
        if self.filled:
            # Draw filled circle (no border)
            canvas.setFillColor(self.border_color)
            canvas.circle(center_x, center_y, radius, stroke=0, fill=1)
        else:
            # Draw circle outline
            canvas.setStrokeColor(self.border_color)
            canvas.setLineWidth(self.border_width)
            canvas.setFillColor(colors.white)
            canvas.circle(center_x, center_y, radius, stroke=1, fill=1)
        
        # Draw text centered
        canvas.setFillColor(self.text_color)
        # Smaller font size for N/A text
        font_size = self.size * 0.35 if len(self.letter) > 1 else self.size * 0.5
        canvas.setFont('Helvetica-Bold', font_size)
        
        # Center the text
        text_width = canvas.stringWidth(self.letter, 'Helvetica-Bold', font_size)
        text_x = center_x - (text_width / 2)
        text_y = center_y - (self.size * 0.15 if len(self.letter) > 1 else self.size * 0.18)
        
        canvas.drawString(text_x, text_y, self.letter)
        
        # Restore state
        canvas.restoreState()


def generate_pdf_report(report_data):
    """Generate PDF report from report data with enhanced layout matching web report"""
    try:
        # Create a BytesIO buffer to hold the PDF
        buffer = BytesIO()
        
        # Create the PDF document with optimized margins for better content flow
        doc = SimpleDocTemplate(buffer, pagesize=A4, 
                              rightMargin=50, leftMargin=50,
                              topMargin=60, bottomMargin=70)
        
        # Get styles
        styles = getSampleStyleSheet()
        
        # Modern, professional styles inspired by premium reports
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=32,
            spaceAfter=8,
            spaceBefore=5,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1E293B'),
            fontName='Helvetica-Bold',
            leading=38
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Normal'],
            fontSize=13,
            spaceAfter=12,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#64748B'),
            fontName='Helvetica',
            leading=18
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#0F172A'),
            fontName='Helvetica-Bold',
            borderWidth=0,
            borderPadding=0,
            leading=20,
            leftIndent=0
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Normal'],
            fontSize=13,
            spaceAfter=6,
            spaceBefore=8,
            textColor=colors.HexColor('#1F2937'),
            fontName='Helvetica',  # Not bold - regular weight
            leading=16
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=3,
            textColor=colors.HexColor('#475569'),
            fontName='Helvetica',
            leading=14
        )
        
        card_title_style = ParagraphStyle(
            'CardTitle',
            parent=styles['Normal'],
            fontSize=11,
            spaceAfter=2,
            textColor=colors.HexColor('#0F172A'),
            fontName='Helvetica-Bold'
        )
        
        score_style = ParagraphStyle(
            'ScoreStyle',
            parent=styles['Normal'],
            fontSize=24,
            spaceAfter=5,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1E293B'),
            fontName='Helvetica-Bold'
        )
        
        badge_style = ParagraphStyle(
            'BadgeStyle',
            parent=styles['Normal'],
            fontSize=10,
            spaceAfter=3,
            textColor=colors.white,
            fontName='Helvetica-Bold'
        )
        
        # Helper function to create colored boxes
        def create_score_card_table(title, score, max_score, description=""):
            score_color = colors.HexColor('#10B981') if score >= 700 else colors.HexColor('#F59E0B') if score >= 400 else colors.HexColor('#EF4444')
            
            data = [
                [Paragraph(title, card_title_style)],
                [Paragraph(f"{score}/950", score_style)],
                [Paragraph(description, normal_style)] if description else [""]
            ]
            
            table = Table(data, colWidths=[3*inch])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#E5E7EB')),
                ('ROUNDEDCORNERS', [6, 6, 6, 6]),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('LEFTPADDING', (0, 0), (-1, -1), 10),
                ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            return table
        
        # Story to hold all content
        story = []
        
        # Branded title page with optional logo (configurable via environment)
        brand_title_style = ParagraphStyle(
            'Brand',
            parent=title_style,
            textColor=colors.HexColor(BRAND_COLOR)
        )

        try:
            brand_logo = None
            if BRAND_LOGO_PATH and os.path.exists(BRAND_LOGO_PATH):
                try:
                    brand_logo = Image(BRAND_LOGO_PATH, width=2.5*inch, height=0.6*inch, kind='proportional')
                except Exception as logo_err:
                    logging.warning(f"Could not load report logo {BRAND_LOGO_PATH}: {logo_err}")

            if brand_logo:
                story.append(Spacer(1, 0.15*inch))
                logo_table = Table([[brand_logo]], colWidths=[5.5*inch])
                logo_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                story.append(logo_table)
                story.append(Spacer(1, 0.15*inch))
            else:
                story.append(Spacer(1, 0.2*inch))
                story.append(Paragraph(BRAND_NAME, brand_title_style))
        except Exception as e:
            logging.error(f"Could not render report branding: {e}")
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph(BRAND_NAME, brand_title_style))

        story.append(Paragraph("Vendor Risk Assessment Report", subtitle_style))
        story.append(Spacer(1, 0.05*inch))
        story.append(HRFlowable(width="30%", thickness=2, color=colors.HexColor(BRAND_COLOR), spaceBefore=5, spaceAfter=10, hAlign='CENTER'))
        story.append(Paragraph(f"Security Analysis: {report_data['vendor']['name']}", subtitle_style))
        story.append(Spacer(1, 0.15*inch))
        
        # Modern Vendor Information Section with High-Quality Logo
        try:
            logo_element = None
            try:
                # Try multiple logo sources for best quality (Clearbit is blocked)
                logo_urls = [
                    f"https://www.google.com/s2/favicons?domain={report_data['domain']}&sz=256",  # Google Favicons - most reliable
                    f"https://icon.horse/icon/{report_data['domain']}",  # Icon.horse - alternative service
                    f"https://{report_data['domain']}/favicon.ico",  # Direct domain favicon
                    f"https://icons.duckduckgo.com/ip3/{report_data['domain']}.ico",  # DuckDuckGo icons
                    f"https://www.google.com/s2/favicons?domain={report_data['domain']}&sz=128"  # Google Favicons smaller size
                ]
                
                for logo_url in logo_urls:
                    try:
                        response = requests.get(logo_url, timeout=5)
                        if response.status_code == 200 and len(response.content) > 100:
                            logo_data = BytesIO(response.content)
                            # Open with PIL to ensure high quality
                            pil_img = PILImage.open(logo_data)
                            # Convert to RGB if necessary
                            if pil_img.mode in ('RGBA', 'LA', 'P'):
                                background = PILImage.new('RGB', pil_img.size, (255, 255, 255))
                                if pil_img.mode == 'P':
                                    pil_img = pil_img.convert('RGBA')
                                background.paste(pil_img, mask=pil_img.split()[-1] if pil_img.mode in ('RGBA', 'LA') else None)
                                pil_img = background
                            
                            # Save back to BytesIO with high quality
                            img_buffer = BytesIO()
                            pil_img.save(img_buffer, format='PNG', quality=100, optimize=False)
                            img_buffer.seek(0)
                            
                            logo_element = Image(img_buffer, width=36, height=36, kind='proportional')
                            break
                    except:
                        continue
                
                if not logo_element:
                    # Create a simple text placeholder
                    logo_element = Paragraph("", normal_style)
            except:
                logo_element = Paragraph("", normal_style)
            
            # Modern clean info layout - NO BACKGROUND BOX
            info_style = ParagraphStyle(
                'InfoStyle',
                parent=normal_style,
                fontSize=10,
                leading=14,
                textColor=colors.HexColor('#4B5563')
            )
            
            label_style = ParagraphStyle(
                'LabelStyle',
                parent=normal_style,
                fontSize=9,
                textColor=colors.HexColor('#9CA3AF'),
                spaceAfter=2
            )
            
            value_style = ParagraphStyle(
                'ValueStyle',
                parent=normal_style,
                fontSize=11,
                textColor=colors.HexColor('#1F2937'),
                fontName='Helvetica-Bold',
                spaceAfter=8
            )
            
            # Get summary metrics for the header bar
            summary = report_data['summary']
            total_vulnerabilities = summary['total_vulnerabilities']
            categories_with_issues = len([cat for cat, vulns in report_data['vulnerabilities_by_category'].items() if vulns])
            
            # Get active domains count
            try:
                from db_config import DatabaseConnection
                with DatabaseConnection() as db:
                    active_query = "SELECT COUNT(*) as active_count FROM subdomains WHERE status='Active' AND domain = %s"
                    active_result = db.execute_query(active_query, (report_data['domain'],))
                    active_domains_count = active_result[0]['active_count'] if active_result else summary.get('total_subdomains', 0)
            except Exception as e:
                logging.error(f"Error getting active domains count: {e}")
                active_domains_count = summary.get('total_subdomains', 0)
            
            # Create compact layout with logo, vendor info, and metrics all in one row - SMALLER sizes
            vendor_data = [
                [logo_element, 
                 Paragraph(f"<font size=8 color='#9CA3AF'>VENDOR NAME</font><br/><font size=10><b>{report_data['vendor']['name']}</b></font>", value_style),
                 Paragraph(f"<font size=8 color='#9CA3AF'>DOMAIN</font><br/><font size=9><b>{escape_domain_for_pdf(report_data['domain'])}</b></font>", info_style),
                 Paragraph(f"<font size=8 color='#9CA3AF'>REPORT DATE</font><br/><font size=9><b>{report_data['generated_at']}</b></font>", info_style),
                 Paragraph(f"<font size=8 color='#9CA3AF'>TOTAL VULNERABILITIES</font><br/><font size=11><b>{total_vulnerabilities}</b></font>", info_style),
                 Paragraph(f"<font size=8 color='#9CA3AF'>SECURITY CATEGORIES</font><br/><font size=11><b>{categories_with_issues}</b></font>", info_style),
                 Paragraph(f"<font size=8 color='#9CA3AF'>ACTIVE DOMAINS</font><br/><font size=11><b>{active_domains_count}</b></font>", info_style)]
            ]
            
            vendor_table = Table(vendor_data, colWidths=[0.55*inch, 1.25*inch, 1.1*inch, 1.25*inch, 1.15*inch, 1.15*inch, 1.1*inch])
            vendor_table.setStyle(TableStyle([
                # NO BACKGROUND - Clean modern look
                ('VALIGN', (0, 0), (0, 0), 'MIDDLE'),
                ('VALIGN', (1, 0), (-1, 0), 'TOP'),
                ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                ('ALIGN', (1, 0), (-1, 0), 'LEFT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ]))
        except Exception as e:
            logging.error(f"Error creating vendor section: {e}")
            # Simple fallback
            vendor_data = [
                [Paragraph(f"<b>{report_data['vendor']['name']}</b> | {escape_domain_for_pdf(report_data['domain'])} | {report_data['generated_at']}", normal_style)]
            ]
            vendor_table = Table(vendor_data, colWidths=[5.5*inch])
            vendor_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ]))
        
        story.append(vendor_table)
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#E5E7EB'), spaceBefore=10, spaceAfter=15))
        
        # Overall Security Score Card (single section only - no industry average)
        if report_data['selected_sections'].get('securityScores', True):
            story.append(Paragraph("Overall security rating", heading_style))
            story.append(Spacer(1, 0.15*inch))
            
            # Create overall score display
            overall_score = report_data['vendor']['overall_score']
            grade = report_data['vendor']['grade']
            
            # If grade is N/A, calculate it based on score (matching VendorComparison.tsx)
            if grade == 'N/A' or not grade:
                if overall_score >= 801:
                    grade = 'A'
                elif overall_score >= 601:
                    grade = 'B'
                elif overall_score >= 401:
                    grade = 'C'
                elif overall_score >= 201:
                    grade = 'D'
                else:
                    grade = 'F'
            
            # Determine score color and status based on grade (matching VendorComparison.tsx)
            if grade == 'A':  # 801-950
                score_color = colors.HexColor('#22C55E')  # Green - Low Risk
                grade_border_color = colors.HexColor('#22C55E')
                status_text = f"{report_data['vendor']['name']} has a robust security posture and good attack surface management."
            elif grade == 'B':  # 601-800
                score_color = colors.HexColor('#84CC16')  # Light Green
                grade_border_color = colors.HexColor('#84CC16')
                status_text = f"{report_data['vendor']['name']} has a good security posture with minor areas requiring attention."
            elif grade == 'C':  # 401-600
                score_color = colors.HexColor('#F59E0B')  # Yellow
                grade_border_color = colors.HexColor('#F59E0B')
                status_text = f"{report_data['vendor']['name']} has a moderate security posture with some areas requiring attention."
            elif grade == 'D':  # 201-400
                score_color = colors.HexColor('#F97316')  # Orange
                grade_border_color = colors.HexColor('#F97316')
                status_text = f"{report_data['vendor']['name']} has a fair security posture with multiple areas needing improvement."
            else:  # F: 0-200
                score_color = colors.HexColor('#EF4444')  # Red - High Risk
                grade_border_color = colors.HexColor('#EF4444')
                status_text = f"{report_data['vendor']['name']} has security concerns that require immediate attention."
            
            # Styles matching the image exactly - larger size
            score_large_style = ParagraphStyle(
                'ScoreLarge',
                parent=normal_style,
                fontSize=32,  # Larger score
                spaceAfter=0,
                alignment=TA_LEFT,
                textColor=score_color,
                fontName='Helvetica-Bold',
                leading=36
            )
            
            description_style = ParagraphStyle(
                'Description',
                parent=normal_style,
                fontSize=11,
                spaceAfter=0,
                textColor=colors.HexColor('#64748B'),
                fontName='Helvetica',
                leading=16
            )
            
            # Create a PERFECT circular grade badge using custom flowable
            circle_size = 0.55 * inch
            grade_badge = CircleBadge(
                letter=grade,
                size=circle_size,
                border_color=grade_border_color,
                text_color=grade_border_color,
                border_width=2
            )
            
            # Badge and score on the same line (horizontal layout)
            badge_score_data = [[
                grade_badge,
                Paragraph(f"<b>{overall_score}</b> <font size=14 color='#9CA3AF'>/ 950</font>", score_large_style)
            ]]
            
            badge_score_row = Table(badge_score_data, colWidths=[0.7*inch, 4.8*inch])
            badge_score_row.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),  # Vertically center both items
                ('ALIGN', (0, 0), (0, 0), 'LEFT'),
                ('ALIGN', (1, 0), (1, 0), 'LEFT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (0, 0), 12),  # Space between badge and score
                ('RIGHTPADDING', (1, 0), (1, 0), 0),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ]))
            
            # Single section: Main score display (white background) - WIDER BOX
            content_data = [
                [badge_score_row],  # Badge and score together
                [Spacer(1, 0.15*inch)],
                [Paragraph(status_text, description_style)]
            ]
            
            content_section = Table(content_data, colWidths=[6*inch])  # Much wider box
            content_section.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN', (0, 0), (0, 0), 'LEFT'),
                ('ALIGN', (0, 2), (0, 2), 'LEFT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ]))
            
            # Create main container with single section
            main_score_data = [[content_section]]
            main_score_table = Table(main_score_data, colWidths=[6*inch])  # Wider container
            main_score_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor('#E5E7EB')),
                ('ROUNDEDCORNERS', [10, 10, 10, 10]),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 28),
                ('RIGHTPADDING', (0, 0), (-1, -1), 28),
                ('TOPPADDING', (0, 0), (-1, -1), 24),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 24),
            ]))
            
            story.append(KeepTogether(main_score_table))
            story.append(Spacer(1, 0.2*inch))
        
        # Executive Summary removed - metrics now in header bar
        summary = report_data['summary']
        
        # Risk Level Cards (if selected) - MODERN STYLISH CARD-BASED LAYOUT
        if report_data['selected_sections'].get('riskCards', True):
            # Keep heading with cards to prevent orphaned headings
            risk_heading = Paragraph("Risk Level Summary", heading_style)
            
            # Get severity counts
            critical_count = summary['severity_breakdown']['Critical']
            high_count = summary['severity_breakdown']['High']
            medium_count = summary['severity_breakdown']['Medium']
            low_count = summary['severity_breakdown']['Low']
            
            # Card configurations - MODERN STYLING
            card_configs = [
                {
                    'count': critical_count,
                    'label': 'Critical Issues',
                    'count_color': colors.HexColor('#EF4444'),  # Modern red
                    'label_color': colors.HexColor('#EF4444'),
                },
                {
                    'count': high_count,
                    'label': 'High Risk Issues',
                    'count_color': colors.HexColor('#F97316'),  # Modern orange
                    'label_color': colors.HexColor('#F97316'),
                },
                {
                    'count': medium_count,
                    'label': 'Medium Risk Issues',
                    'count_color': colors.HexColor('#F59E0B'),  # Yellow (matching VendorComparison)
                    'label_color': colors.HexColor('#F59E0B'),
                },
                {
                    'count': low_count,
                    'label': 'Low Risk Issues',
                    'count_color': colors.HexColor('#22C55E'),  # Modern green
                    'label_color': colors.HexColor('#22C55E'),
                }
            ]
            
            # Create individual cards - STYLISH AND MODERN
            cards = []
            card_widths = []  # Store individual card widths
            
            for config in card_configs:
                # Dynamically calculate card width based on digit count
                count_str = str(config['count'])
                digit_count = len(count_str)
                
                # Base width for 1-digit: 1.2 inch, add 0.2 inch per extra digit
                if digit_count == 1:
                    card_width = 1.2*inch
                elif digit_count == 2:
                    card_width = 1.4*inch
                else:  # 3+ digits
                    card_width = 1.6*inch
                
                card_widths.append(card_width)
                
                # Count style - bold and modern
                count_style = ParagraphStyle(
                    'CountStyle',
                    parent=normal_style,
                    fontSize=40,
                alignment=TA_CENTER,
                    textColor=config['count_color'],
                    fontName='Helvetica-Bold',
                    leading=44,
                    spaceAfter=6
                )
                
                # Label style - clean and modern
                label_style = ParagraphStyle(
                    'LabelStyle',
                parent=normal_style,
                fontSize=10,
                alignment=TA_CENTER,
                    textColor=config['label_color'],
                    fontName='Helvetica',
                    leading=12
                )
                
                # Card content
                card_data = [
                    [Paragraph(str(config['count']), count_style)],
                    [Paragraph(config['label'], label_style)]
                ]
                
                # Modern card with subtle shadow effect (using border)
                card_table = Table(card_data, colWidths=[card_width], rowHeights=[0.55*inch, 0.45*inch])
                card_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                    ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#D1D5DB')),  # Subtle border
                    ('ROUNDEDCORNERS', [12, 12, 12, 12]),  # More rounded for modern look
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 10),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ]))
            
                cards.append(card_table)
            
            # Create cards with spacers between them for visible gaps
            cards_with_spacing = []
            for i, card in enumerate(cards):
                cards_with_spacing.append(card)
                if i < len(cards) - 1:  # Don't add spacer after last card
                    cards_with_spacing.append(Spacer(0.15*inch, 1*inch))  # Horizontal spacer
            
            # Arrange cards in a row with actual spacing between them - dynamic widths
            col_widths = []
            for i, width in enumerate(card_widths):
                col_widths.append(width)
                if i < len(card_widths) - 1:
                    col_widths.append(0.15*inch)  # Spacer width
            
            cards_row_data = [cards_with_spacing]
            cards_row_table = Table(cards_row_data, colWidths=col_widths)
            cards_row_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                ('TOPPADDING', (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ]))
            
            # Keep heading and cards together on same page
            story.append(KeepTogether([risk_heading, Spacer(1, 0.15*inch), cards_row_table]))
            story.append(Spacer(1, 0.3*inch))
            
            # Add Risk Count by Severity Table
            risk_count_heading = Paragraph("Risk count by Severity and Security Category Scores", heading_style)
            
            # Create risk count table data - nowrap to keep headers in one line
            header_style = ParagraphStyle('TableHeader', parent=normal_style, fontSize=8, fontName='Helvetica-Bold', textColor=colors.HexColor('#6B7280'))
            header_style_center = ParagraphStyle('TableHeaderCenter', parent=normal_style, fontSize=8, fontName='Helvetica-Bold', textColor=colors.HexColor('#6B7280'), alignment=TA_CENTER)
            
            risk_count_data = [
                # Header row - smaller font and nowrap to prevent wrapping
                [
                    Paragraph("<b>Category</b>", header_style),
                    Paragraph("<b>Category&nbsp;rating</b>", header_style_center),  # Non-breaking space
                    Paragraph("<b>Critical</b>", header_style_center),
                    Paragraph("<b>High</b>", header_style_center),
                    Paragraph("<b>Medium</b>", header_style_center),
                    Paragraph("<b>Low</b>", header_style_center)
                ]
            ]
            
            # Process vulnerabilities by category to get counts
            category_risk_counts = {}
            for category, vulnerabilities in report_data['vulnerabilities_by_category'].items():
                category_risk_counts[category] = {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'total': len(vulnerabilities)
                }
                for vuln in vulnerabilities:
                    severity = vuln.get('severity', 'Unknown')
                    if severity in category_risk_counts[category]:
                        category_risk_counts[category][severity] += 1
            
            # Get category scores for ratings
            category_scores = {}
            if 'scores' in report_data:
                for score in report_data['scores']:
                    cat = score.get('score_category', score.get('category', ''))
                    category_scores[cat] = {
                        'score': score.get('score', 0),
                        'grade': score.get('grade', 'N/A')
                    }
            
            # Add data rows for each category
            for category, counts in category_risk_counts.items():
                # Get score info
                score_info = category_scores.get(category, {'score': 0, 'grade': 'N/A'})
                score = score_info['score']
                grade = score_info['grade']
                
                # Determine grade color - matching VendorComparison.tsx
                # If grade is N/A, calculate it based on score
                if grade == 'N/A' or not grade:
                    if score >= 801:
                        grade = 'A'
                    elif score >= 601:
                        grade = 'B'
                    elif score >= 401:
                        grade = 'C'
                    elif score >= 201:
                        grade = 'D'
                    else:
                        grade = 'F'
                
                grade_colors = {
                    'A': colors.HexColor('#22C55E'),  # Green - Low Risk (801-950)
                    'B': colors.HexColor('#84CC16'),  # Light Green (601-800)
                    'C': colors.HexColor('#F59E0B'),  # Yellow (401-600)
                    'D': colors.HexColor('#F97316'),  # Orange (201-400)
                    'F': colors.HexColor('#EF4444')   # Red - High Risk (0-200)
                }
                grade_color = grade_colors.get(grade, colors.HexColor('#6B7280'))
                
                # Create much smaller outlined circle badge (not filled)
                circle_size = 0.24*inch  # Much smaller circle
                grade_badge = CircleBadge(
                    letter=grade,
                    size=circle_size,
                    border_color=grade_color,
                    text_color=grade_color,  # Text color matches border
                    border_width=1.5,
                    filled=False  # Outline only, not filled
                )
                
                # Create rating cell with badge and much smaller score
                rating_content = Table([[grade_badge, Paragraph(f"{score}", ParagraphStyle('ScoreText', parent=normal_style, fontSize=9, fontName='Helvetica', textColor=colors.HexColor('#1F2937')))]], 
                                      colWidths=[0.27*inch, 0.45*inch])
                rating_content.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('ALIGN', (0, 0), (0, 0), 'CENTER'),
                    ('ALIGN', (1, 0), (1, 0), 'LEFT'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 0),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 0),
                    ('TOPPADDING', (0, 0), (-1, -1), 0),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                ]))
                
                risk_count_data.append([
                    Paragraph(category, ParagraphStyle('CategoryName', parent=normal_style, fontSize=10, textColor=colors.HexColor('#1F2937'))),
                    rating_content,
                    Paragraph(str(counts['Critical']) if counts['Critical'] > 0 else '-', ParagraphStyle('CountText', parent=normal_style, fontSize=10, textColor=colors.HexColor('#1F2937'), alignment=TA_CENTER)),
                    Paragraph(str(counts['High']) if counts['High'] > 0 else '-', ParagraphStyle('CountText', parent=normal_style, fontSize=10, textColor=colors.HexColor('#1F2937'), alignment=TA_CENTER)),
                    Paragraph(str(counts['Medium']) if counts['Medium'] > 0 else '-', ParagraphStyle('CountText', parent=normal_style, fontSize=10, textColor=colors.HexColor('#1F2937'), alignment=TA_CENTER)),
                    Paragraph(str(counts['Low']) if counts['Low'] > 0 else '-', ParagraphStyle('CountText', parent=normal_style, fontSize=10, textColor=colors.HexColor('#1F2937'), alignment=TA_CENTER))
                ])
            
            # Create the risk count table - wider rating column to prevent header wrap
            risk_count_table = Table(risk_count_data, colWidths=[1.9*inch, 1.4*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
            risk_count_table.setStyle(TableStyle([
                # Header row
                ('BACKGROUND', (0, 0), (-1, 0), colors.white),
                ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor('#E5E7EB')),
                ('TOPPADDING', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                
                # Data rows
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('LINEBELOW', (0, 1), (-1, -1), 0.5, colors.HexColor('#F3F4F6')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('ALIGN', (2, 0), (-1, -1), 'CENTER'),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 1), (-1, -1), 14),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 14),
            ]))
            
            # Keep heading and table together on same page
            story.append(KeepTogether([risk_count_heading, Spacer(1, 0.15*inch), risk_count_table]))
            story.append(Spacer(1, 0.2*inch))
        
        # AI Analyst Insights (if selected)
        if report_data['selected_sections'].get('aiInsights', True):
            # Keep heading with content to prevent orphaned headings
            ai_insights_heading = Paragraph("AI Analyst Insights", heading_style)
            
            # Generate AI insights for this vendor
            try:
                # Prepare data for AI analysis
                vendor_name = report_data['vendor']['name']
                overall_score = report_data['vendor']['overall_score']
                grade = report_data['vendor']['grade']
                
                # Vulnerability summary
                total_vulnerabilities = report_data['summary']['total_vulnerabilities']
                severity_breakdown = report_data['summary']['severity_breakdown']
                critical_count = severity_breakdown.get('Critical', 0)
                high_count = severity_breakdown.get('High', 0)
                
                # Score breakdown by category
                score_summary = {}
                for score_item in report_data['scores']:
                    category = score_item.get('score_category', score_item.get('category', 'Unknown'))
                    score = score_item.get('score', 0)
                    score_summary[category] = score
                
                subdomains_count = report_data['summary']['total_subdomains']
                
                # Try to generate AI insights
                try:
                    # Import AI functions from app_new.py
                    from routes.ai_insights_routes import get_ai_client_config, parse_ai_response, generate_template_insights, extract_response_text
                    
                    client, model_name = get_ai_client_config()
                    
                    # Create prompt for AI analysis
                    prompt = f"""
                    Analyze the security posture of {vendor_name} (domain: {report_data['domain']}) based on the following data:
                    
                    Overall Security Score: {overall_score}/950 (Grade: {grade})
                    Total Vulnerabilities: {total_vulnerabilities}
                    Critical Issues: {critical_count}
                    High Severity Issues: {high_count}
                    Medium Issues: {severity_breakdown.get('Medium', 0)}
                    Low Issues: {severity_breakdown.get('Low', 0)}
                    Subdomains Analyzed: {subdomains_count}
                    
                    Security Category Scores: {score_summary}
                    
                    Please provide analysis in the following format:
                    
                    VENDOR_OVERVIEW: A concise 2-3 sentence overview of the vendor's business focus and what they do.
                    
                    SECURITY_POSTURE: Write a comprehensive security analysis in flowing paragraph format. Focus on overall security maturity, key strengths, critical vulnerabilities, and business risk implications.
                    
                    NEXT_STEPS: Provide 4-6 specific, actionable security recommendations prioritized by importance and impact.
                    """
                    
                    response = client.responses.create(
                        model=model_name,
                        instructions="You are a cybersecurity expert analyst providing detailed security assessments for vendor risk management.",
                        input=prompt,
                        tools=[{"type": "web_search"}],
                        temperature=0.2,
                        max_output_tokens=1500,
                    )
                    ai_response = extract_response_text(response)
                    
                    # Parse the AI response
                    vendor_overview, security_posture, next_steps = parse_ai_response(
                        ai_response, vendor_name, overall_score, grade, 
                        total_vulnerabilities, critical_count, high_count
                    )
                    
                except Exception as ai_error:
                    logging.warning(f"AI generation failed, using template fallback: {ai_error}")
                    # Fallback to template-based insights
                    insights = generate_template_insights(vendor_name, report_data['domain'], overall_score, grade, 
                                                        total_vulnerabilities, severity_breakdown, 
                                                        score_summary, subdomains_count)
                    vendor_overview = insights.get('vendor_overview', '')
                    security_posture = insights.get('overall_security_posture', '')
                    next_steps = insights.get('next_steps', [])
                
                # Add AI insights to PDF without boxes - using KeepTogether to prevent orphaned headings
                # Add main AI heading first
                story.append(ai_insights_heading)
                
                if vendor_overview:
                    # Convert **text** to bold HTML with Helvetica-Bold
                    import re
                    vendor_overview_formatted = re.sub(r'\*\*(.*?)\*\*', r'<b><font face="Helvetica-Bold">\1</font></b>', vendor_overview)
                    vendor_section = [
                        Paragraph("AI-Powered Vendor Overview", subheading_style),
                        Paragraph(vendor_overview_formatted, normal_style),
                        Spacer(1, 0.1*inch)
                    ]
                    story.append(KeepTogether(vendor_section))
                
                if security_posture:
                    # Convert **text** to bold HTML with Helvetica-Bold
                    import re
                    security_posture_formatted = re.sub(r'\*\*(.*?)\*\*', r'<b><font face="Helvetica-Bold">\1</font></b>', security_posture)
                    security_section = [
                        Paragraph("Security Posture Analysis", subheading_style),
                        Paragraph(security_posture_formatted, normal_style),
                        Spacer(1, 0.1*inch)
                    ]
                    story.append(KeepTogether(security_section))
                
                if next_steps:
                    # Build next steps section
                    next_steps_content = [Paragraph("AI-Recommended Next Steps", subheading_style)]
                    
                    # Create simple numbered list without boxes, with bold formatting
                    import re
                    for i, step in enumerate(next_steps[:6], 1):
                        step_formatted = re.sub(r'\*\*(.*?)\*\*', r'<b><font face="Helvetica-Bold">\1</font></b>', step)
                        next_steps_content.append(Paragraph(f"<b>{i}.</b> {step_formatted}", normal_style))
                    
                    next_steps_content.append(Spacer(1, 0.1*inch))
                    story.append(KeepTogether(next_steps_content))
                
            except Exception as e:
                logging.error(f"Error generating AI insights for PDF: {e}")
                story.append(Paragraph("AI insights are temporarily unavailable.", normal_style))
        
        # Security Category Scores (if selected) - Enhanced Card Layout
        # Security Category Scores section removed
        
        # Security Categories Analysis (if selected)
        if report_data['selected_sections'].get('securityAnalysis', True):
            # Keep main heading with first content to prevent orphaned headings
            analysis_heading = Paragraph("Security Categories Analysis", heading_style)
            
            # Get filters for security analysis
            analysis_filters = report_data.get('section_filters', {}).get('securityAnalysis', {})
            
            # Category mapping for filtering
            category_mapping = {
                'dns': ['DNS', 'dns', 'DNS Security'],
                'domainReputation': ['Domain Reputation', 'domain_reputation', 'reputation'],
                'email': ['Email', 'email', 'Email Security'],
                'encryption': ['Encryption', 'encryption', 'SSL/TLS'],
                'network': ['Network', 'network', 'Network Security'],
                'website': ['Website', 'website', 'Web Security', 'Header Vulnerabilities']
            }
            
            categories_included = 0
            
            # Add main heading before any content
            story.append(analysis_heading)
            
            for category, vulnerabilities in report_data['vulnerabilities_by_category'].items():
                # Check if this category should be included based on filters
                include_category = True
                if any(analysis_filters.values()):  # If any filters are selected
                    include_category = False
                    for filter_key, filter_selected in analysis_filters.items():
                        if filter_selected and category.lower() in [cat.lower() for cat in category_mapping.get(filter_key, [])]:
                            include_category = True
                            break
                
                if include_category:
                    categories_included += 1
                    
                    # Create category header - keep with first severity section
                    category_header = Paragraph(f"{category} Security Analysis", subheading_style)
                    
                    if vulnerabilities:
                        # Group by severity
                        severity_groups = {}
                        for vuln in vulnerabilities:
                            severity = vuln.get('severity', 'Unknown')
                            if severity not in severity_groups:
                                severity_groups[severity] = []
                            severity_groups[severity].append(vuln)
                        
                        # Track if this is the first severity section to add category header
                        first_severity = True
                        
                        # Professional vulnerability tables by severity
                        for severity in ['Critical', 'High', 'Medium', 'Low']:
                            if severity in severity_groups:
                                vulns = severity_groups[severity]
                                
                                # Severity colors and backgrounds - matching reference design
                                severity_configs = {
                                    'Critical': {'color': colors.HexColor('#991B1B'), 'bg': colors.HexColor('#FEE2E2'), 'icon': '🔴'},
                                    'High': {'color': colors.HexColor('#C2410C'), 'bg': colors.HexColor('#FFEDD5'), 'icon': '🟠'},
                                    'Medium': {'color': colors.HexColor('#CA8A04'), 'bg': colors.HexColor('#FEF3C7'), 'icon': '🟡'},
                                    'Low': {'color': colors.HexColor('#65A30D'), 'bg': colors.HexColor('#D9F99D'), 'icon': '🟢'}
                                }
                                
                                config = severity_configs.get(severity, {'color': colors.HexColor('#6B7280'), 'bg': colors.HexColor('#F3F4F6'), 'icon': '⚪'})
                                
                                # Severity header style - smaller than category, aligned with table
                                severity_header_style = ParagraphStyle(
                                    'SeverityHeader',
                                    parent=normal_style,
                                    fontSize=11,  # Smaller than category (13pt)
                                    textColor=colors.HexColor('#1F2937'),
                                    fontName='Helvetica',  # NOT BOLD
                                    spaceAfter=6,
                                    spaceBefore=0,
                                    alignment=TA_LEFT
                                )
                                
                                # Create layout exactly matching reference image - FLOWING SECTIONS
                                vuln_sections = []
                                
                                # Section header styles matching reference - smaller text
                                section_header_style = ParagraphStyle('SectionHeader',
                                    parent=normal_style,
                                    fontSize=9,
                                    fontName='Helvetica-Bold',
                                    textColor=colors.HexColor('#6B7280'),
                                    spaceAfter=0,
                                    leading=11
                                )
                                
                                risk_title_style = ParagraphStyle('VulnTitle',
                                    parent=normal_style,
                                    fontSize=10,
                                    fontName='Helvetica-Bold',
                                    textColor=colors.HexColor('#1F2937'),
                                    spaceAfter=0,
                                    spaceBefore=0,
                                    leading=14
                                )
                                
                                content_text_style = ParagraphStyle('ContentText',
                                    parent=normal_style,
                                    fontSize=10,
                                    textColor=colors.HexColor('#374151'),
                                    leading=14,
                                    alignment=TA_LEFT
                                )
                                
                                # Create header row with column labels
                                header_data = [[
                                    Paragraph("<b>Risk</b>", section_header_style),
                                    Paragraph("<b>Affected</b>", section_header_style),
                                    Paragraph("<b>Overview</b>", section_header_style)
                                ]]
                                
                                # Wider columns to prevent header text wrapping - with left padding to match text
                                header_table = Table(header_data, colWidths=[1.45*inch, 0.95*inch, 4.6*inch])
                                header_table.setStyle(TableStyle([
                                    ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                    ('LEFTPADDING', (0, 0), (0, -1), 12),  # Left padding on first column to align with text
                                    ('LEFTPADDING', (1, 0), (-1, -1), 0),  # No padding on other columns
                                    ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                                    ('LINEBELOW', (0, 0), (-1, -1), 1.5, colors.HexColor('#D1D5DB'))  # Thicker, darker line
                                ]))
                                
                                vuln_sections.append(header_table)
                                
                                # Add vulnerabilities in flowing layout
                                for vuln in vulns[:8]:
                                    title = vuln.get('title', vuln.get('vulnerability', 'Unknown Issue'))
                                    desc = vuln.get('description', 'No description available')
                                    subdomain = vuln.get('subdomain', vuln.get('domain', 'Unknown'))
                                    
                                    # Create row for each vulnerability
                                    vuln_row = [[
                                        Paragraph(f"<b>{title}</b>", risk_title_style),
                                        Paragraph(f"{escape_domain_for_pdf(subdomain)}", content_text_style),
                                        Paragraph(desc, content_text_style)
                                    ]]
                                    
                                    # Match header column widths with same left padding
                                    vuln_row_table = Table(vuln_row, colWidths=[1.45*inch, 0.95*inch, 4.6*inch])
                                    vuln_row_table.setStyle(TableStyle([
                                        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
                                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                                        ('LEFTPADDING', (0, 0), (0, -1), 12),  # Left padding on first column to match header
                                        ('LEFTPADDING', (1, 0), (-1, -1), 0),  # No padding on other columns
                                        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                                        ('TOPPADDING', (0, 0), (-1, -1), 10),
                                        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                                        ('LINEBELOW', (0, 0), (-1, -1), 1, colors.HexColor('#E5E7EB'))  # Thicker line
                                    ]))
                                    
                                    vuln_sections.append(vuln_row_table)
                                
                                # Combine all sections in a container
                                vuln_display_table = KeepTogether(vuln_sections)
                                
                                # Severity color mapping - using HTML colored squares and text
                                severity_colors = {
                                    'Critical': '#DC2626',  # Red
                                    'High': '#F97316',      # Orange
                                    'Medium': '#FBBF24',    # Yellow
                                    'Low': '#FBBF24'        # Yellow (same as Medium)
                                }
                                severity_color = severity_colors.get(severity, '#6B7280')
                                severity_color_box = f'<font color="{severity_color}">■</font>'
                                
                                # Create severity header style with matching color
                                colored_severity_header_style = ParagraphStyle(
                                    'ColoredSeverityHeader',
                                    parent=normal_style,
                                    fontSize=11,
                                    textColor=colors.HexColor(severity_color),
                                    fontName='Helvetica'
                                )
                                
                                # Keep header and table together to prevent orphaned headers
                                # Add colored square before text with matching text color
                                severity_section_content = [
                                    Paragraph(f"{severity_color_box} {severity} Severity — {len(vulns)} Issue{'s' if len(vulns) != 1 else ''} Identified", colored_severity_header_style),
                                    Spacer(1, 0.08*inch),  # Small spacing between header and table
                                    vuln_display_table
                                ]
                                
                                # Add additional count text to the group if needed
                                if len(vulns) > 8:
                                    more_text = f"+ {len(vulns) - 8} additional {severity.lower()} severity finding{'s' if len(vulns) - 8 != 1 else ''} not shown"
                                    severity_section_content.append(Paragraph(f"<i>{more_text}</i>", 
                                        ParagraphStyle('MoreText', parent=normal_style, fontSize=9, textColor=colors.HexColor('#64748B'), leftIndent=10)))
                                
                                # Keep heading + entire table together on same page
                                # For first severity, include category header too
                                if first_severity:
                                    full_section = [
                                        category_header,  # Category header
                                        Spacer(1, 0.05*inch),
                                        severity_section_content[0],  # Severity header
                                        severity_section_content[1],  # Spacer
                                    ] + vuln_sections  # All table items
                                    first_severity = False
                                else:
                                    full_section = [
                                        severity_section_content[0],  # Severity header
                                        severity_section_content[1],  # Spacer
                                    ] + vuln_sections  # All table items
                                
                                story.append(KeepTogether(full_section))
                                story.append(Spacer(1, 0.15*inch))  # Spacing between severity sections
                    
                    story.append(Spacer(1, 0.25*inch))  # Spacing between categories
            
            if categories_included == 0:
                story.append(Paragraph("No security analysis available for selected categories.", normal_style))
        
        # Security Incidents (if selected) - Detailed Layout
        if report_data['selected_sections'].get('securityIncidents', True) and report_data.get('incidents', {}).get('incidents'):
            story.append(Spacer(1, 0.1*inch))
            # Keep heading with content to prevent orphaned headings
            incidents_heading = Paragraph("Incidents and news", heading_style)
            
            incidents = report_data['incidents']['incidents'][:8]  # Show fewer with detailed layout
            
            # Severity icon mapping
            severity_icons = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }
            
            # Create detailed incidents table matching second image
            incidents_data = [[
                Paragraph("<b>Date</b>", ParagraphStyle('HeaderSmall', parent=normal_style, fontSize=9, fontName='Helvetica-Bold', textColor=colors.HexColor('#6B7280'))),
                Paragraph("<b>Sev. Type</b>", ParagraphStyle('HeaderSmall', parent=normal_style, fontSize=9, fontName='Helvetica-Bold', textColor=colors.HexColor('#6B7280'))),
                Paragraph("<b>Summary</b>", ParagraphStyle('HeaderSmall', parent=normal_style, fontSize=9, fontName='Helvetica-Bold', textColor=colors.HexColor('#6B7280'))),
                Paragraph("<b>Tags</b>", ParagraphStyle('HeaderSmall', parent=normal_style, fontSize=9, fontName='Helvetica-Bold', textColor=colors.HexColor('#6B7280')))
            ]]
            
            for incident in incidents:
                date = incident.get('date', 'Unknown')
                title = incident.get('title', 'No title')
                description = incident.get('description', '')
                severity = incident.get('severity', 'Unknown')
                tags = incident.get('tags', ['Incident'])
                
                # Get severity icon
                severity_icon = severity_icons.get(severity, '⚪')
                
                # Format severity with icon (no "Incident" text, just icon)
                severity_text = f"{severity_icon}"
                
                # Create summary with title and description
                summary_text = f"<b>{title}</b><br/><br/>{description[:200]}..." if len(description) > 200 else f"<b>{title}</b><br/><br/>{description}"
                
                # Format tags
                if isinstance(tags, list):
                    tags_text = tags[0] if tags else 'Incident'
                else:
                    tags_text = str(tags)
                
                incidents_data.append([
                    Paragraph(date, ParagraphStyle('DateText', parent=normal_style, fontSize=9, textColor=colors.HexColor('#374151'))),
                    Paragraph(severity_text, ParagraphStyle('SevText', parent=normal_style, fontSize=9, textColor=colors.HexColor('#374151'))),
                    Paragraph(summary_text, ParagraphStyle('SummaryText', parent=normal_style, fontSize=9, textColor=colors.HexColor('#374151'), leading=14)),
                    Paragraph(tags_text, ParagraphStyle('TagText', parent=normal_style, fontSize=8, textColor=colors.HexColor('#6B7280'), alignment=TA_CENTER))
                ])
            
            if len(incidents_data) > 1:
                incidents_table = Table(incidents_data, colWidths=[0.8*inch, 0.8*inch, 3.5*inch, 1.2*inch])
                incidents_table.setStyle(TableStyle([
                    # Header styling
                    ('BACKGROUND', (0, 0), (-1, 0), colors.white),
                    ('LINEBELOW', (0, 0), (-1, 0), 1, colors.HexColor('#E5E7EB')),
                    ('TOPPADDING', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    
                    # Data rows
                    ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                    ('LINEBELOW', (0, 1), (-1, -1), 0.5, colors.HexColor('#F3F4F6')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ALIGN', (0, 1), (0, -1), 'LEFT'),
                    ('ALIGN', (1, 1), (1, -1), 'LEFT'),
                    ('ALIGN', (2, 1), (2, -1), 'LEFT'),
                    ('ALIGN', (3, 1), (3, -1), 'CENTER'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 12),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 12),
                    ('TOPPADDING', (0, 1), (-1, -1), 16),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 16),
                ]))
                # Keep heading with table to prevent orphaned headings
                story.append(KeepTogether([incidents_heading, Spacer(1, 0.08*inch), incidents_table]))
        
        # Security News (if selected) - Headlines Only
        if report_data['selected_sections'].get('securityNews', True) and report_data.get('incidents', {}).get('news'):
            story.append(Spacer(1, 0.1*inch))
            # Keep heading with content to prevent orphaned headings
            news_heading = Paragraph("Security News & Industry Updates", heading_style)
            
            news_items = report_data['incidents']['news'][:12]
            
            if len(news_items) > 0:
                # Create flowing layout similar to Security Category Analysis
                news_sections = []
                
                # Header row
                header_data = [[
                    Paragraph("Date", ParagraphStyle('NewsHeader', parent=normal_style, fontSize=9, fontName='Helvetica-Bold', textColor=colors.HexColor('#6B7280'))),
                    Paragraph("News Headline", ParagraphStyle('NewsHeader', parent=normal_style, fontSize=9, fontName='Helvetica-Bold', textColor=colors.HexColor('#6B7280')))
                ]]
                
                header_table = Table(header_data, colWidths=[0.9*inch, 5.9*inch])
                header_table.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (0, -1), 12),
                    ('LEFTPADDING', (1, 0), (1, -1), 8),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LINEBELOW', (0, 0), (-1, -1), 1.5, colors.HexColor('#D1D5DB'))
                ]))
                news_sections.append(header_table)
                
                # Individual news rows
                for news in news_items:
                    date = news.get('date', 'Unknown')
                    title = news.get('title', 'No title')
                    
                    # Truncate title if too long
                    if len(title) > 100:
                        title = title[:97] + "..."
                    
                    row_data = [[
                        Paragraph(date, ParagraphStyle('NewsDate', parent=normal_style, fontSize=9, textColor=colors.HexColor('#6B7280'))),
                        Paragraph(f"<b>{title}</b>", ParagraphStyle('NewsTitle', parent=normal_style, fontSize=9, textColor=colors.HexColor('#1F2937')))
                    ]]
                    
                    news_row_table = Table(row_data, colWidths=[0.9*inch, 5.9*inch])
                    news_row_table.setStyle(TableStyle([
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('LEFTPADDING', (0, 0), (0, -1), 12),
                        ('LEFTPADDING', (1, 0), (1, -1), 8),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                        ('TOPPADDING', (0, 0), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                        ('LINEBELOW', (0, 0), (-1, -1), 1, colors.HexColor('#E5E7EB'))
                    ]))
                    
                    news_sections.append(news_row_table)
                
                # Combine all sections and keep heading with content
                news_display = KeepTogether(news_sections)
                story.append(KeepTogether([news_heading, Spacer(1, 0.08*inch), news_display]))
        
        # Footer will be added via page template - no need to add to story
        
        # Build PDF with branded document template
        def add_page_number(canvas, doc):
            """Add branded professional header and footer"""
            canvas.saveState()
            
            # Branded header
            canvas.setFont('Helvetica-Bold', 10)
            canvas.setFillColor(colors.HexColor(BRAND_COLOR))
            canvas.drawString(50, A4[1] - 35, BRAND_NAME)
            
            canvas.setFont('Helvetica', 8)
            canvas.setFillColor(colors.HexColor('#64748B'))
            canvas.drawString(95, A4[1] - 35, "Vendor Risk Assessment")
            
            # Vendor name on right
            canvas.setFont('Helvetica-Bold', 9)
            canvas.setFillColor(colors.HexColor('#1E293B'))
            canvas.drawRightString(A4[0] - 50, A4[1] - 35, f"{report_data['vendor']['name']}")
            
            # Brand accent line
            canvas.setStrokeColor(colors.HexColor(BRAND_COLOR))
            canvas.setLineWidth(1.5)
            canvas.line(50, A4[1] - 42, 150, A4[1] - 42)
            
            # Subtle gray line for rest
            canvas.setStrokeColor(colors.HexColor('#E2E8F0'))
            canvas.setLineWidth(0.5)
            canvas.line(152, A4[1] - 42, A4[0] - 50, A4[1] - 42)
            
            # Professional footer
            canvas.setFont('Helvetica', 7)
            canvas.setFillColor(colors.HexColor('#94A3B8'))
            
            # Left: Confidential with icon
            canvas.drawString(50, 32, "🔒 CONFIDENTIAL & PROPRIETARY")
            
            # Center: Domain (plain text, not clickable)
            # canvas.drawString doesn't auto-detect URLs, so use domain as-is
            canvas.setFont('Helvetica', 8)
            center_text = report_data['domain']
            text_width = canvas.stringWidth(center_text, 'Helvetica', 8)
            canvas.drawString((A4[0] - text_width) / 2, 32, center_text)
            
            # Right: Page number
            page_text = f"Page {doc.page}"
            canvas.setFont('Helvetica', 8)
            canvas.setFillColor(colors.HexColor('#475569'))
            canvas.drawRightString(A4[0] - 50, 32, page_text)
            
            # Footer line
            canvas.setStrokeColor(colors.HexColor('#E2E8F0'))
            canvas.setLineWidth(0.5)
            canvas.line(50, 40, A4[0] - 50, 40)
            
            canvas.restoreState()
        
        doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)
        
        # Get the value of the BytesIO buffer and return it
        pdf_content = buffer.getvalue()
        buffer.close()
        
        return pdf_content
        
    except ImportError as e:
        logging.error(f"ReportLab not installed: {e}")
        # Return a simple text response if ReportLab is not available
        return f"PDF generation requires ReportLab library. Please install it first.\nReport data for {report_data['domain']} is available but cannot be converted to PDF.".encode('utf-8')
    except Exception as e:
        logging.error(f"Error generating PDF: {e}")
        return f"Error generating PDF report: {str(e)}".encode('utf-8')
