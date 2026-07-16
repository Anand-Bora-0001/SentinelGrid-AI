"""
Report Generator for SentinelGrid
Generates CSV reports of attack events
"""
import csv
import logging
import os
from datetime import datetime
from typing import List

logger = logging.getLogger(__name__)


def generate_csv_report(events: List[dict], filename: str = None) -> str:
    """
    Generate CSV report from attack events.
    
    Args:
        events: List of attack event dictionaries
        filename: Output filename (optional)
        
    Returns:
        Path to generated CSV file
    """
    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)
    
    if not filename:
        filename = f"reports/attack_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            if not events:
                csvfile.write("No attack events to report\n")
                return filename
            
            fieldnames = ['id', 'timestamp', 'service', 'source_ip', 'username', 
                         'severity', 'ai_label', 'threat_score', 'command']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for event in events:
                writer.writerow({k: event.get(k, '') for k in fieldnames})
        
        logger.info(f" CSV report generated: {filename}")
        return filename
    
    except Exception as e:
        logger.error(f" Error generating CSV report: {e}")
        raise


def generate_pdf_report(events: List[dict], stats: dict, filename: str = None) -> str:
    """
    Generate a PDF report (fallback to text if reportlab not available).
    
    Args:
        events: List of attack event dictionaries
        stats: Statistics dictionary
        filename: Output filename (optional)
        
    Returns:
        Path to generated report file
    """
    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)
    
    if not filename:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"reports/attack_report_{timestamp}.pdf"
    
    try:
        # Try to generate actual PDF
        return _generate_actual_pdf(events, stats, filename)
    except ImportError:
        # Fallback to text file if PDF libraries not available
        logger.warning("PDF libraries not available, generating text report instead")
        text_filename = filename.replace('.pdf', '.txt')
        return _generate_text_report(events, stats, text_filename)
    except Exception as e:
        logger.error(f" Error generating PDF report: {e}")
        # Fallback to text file
        text_filename = filename.replace('.pdf', '.txt')
        return _generate_text_report(events, stats, text_filename)


def _generate_actual_pdf(events: List[dict], stats: dict, filename: str) -> str:
    """Generate actual PDF using reportlab (if available)"""
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        
        doc = SimpleDocTemplate(filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue
        )
        story.append(Paragraph(" SentinelGrid Security Report", title_style))
        story.append(Spacer(1, 12))
        
        # Metadata
        story.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Paragraph(f"<b>Total Events:</b> {stats.get('total_events', 0)}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        
        # Statistics Table
        stats_data = [['Metric', 'Count']]
        
        # Add service stats
        for service, count in stats.get('events_by_service', {}).items():
            stats_data.append([f"Service: {service}", str(count)])
        
        # Add severity stats
        for severity, count in stats.get('events_by_severity', {}).items():
            stats_data.append([f"Severity: {severity}", str(count)])
        
        # Add AI classification stats
        for label, count in stats.get('ai_labels', {}).items():
            stats_data.append([f"AI Label: {label}", str(count)])
        
        if len(stats_data) > 1:
            stats_table = Table(stats_data)
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(stats_table)
        
        story.append(Spacer(1, 20))
        
        # Recent Events
        story.append(Paragraph("Recent Attack Events (Last 10)", styles['Heading2']))
        
        if events:
            events_data = [['Time', 'Service', 'Source IP', 'Severity', 'Threat Score']]
            
            for event in events[:10]:
                timestamp = event.get('timestamp', '')
                if timestamp:
                    try:
                        # Format timestamp
                        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        formatted_time = dt.strftime('%m/%d %H:%M')
                    except:
                        formatted_time = timestamp[:16]
                else:
                    formatted_time = 'N/A'
                
                events_data.append([
                    formatted_time,
                    event.get('service', 'N/A')[:15],
                    event.get('source_ip', 'N/A'),
                    event.get('severity', 'N/A'),
                    f"{event.get('threat_score', 0):.2f}"
                ])
            
            events_table = Table(events_data)
            events_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
            ]))
            story.append(events_table)
        else:
            story.append(Paragraph("No recent events to display.", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        logger.info(f" PDF report generated: {filename}")
        return filename
        
    except ImportError as e:
        logger.warning(f"PDF generation libraries not available: {e}")
        raise


def _generate_text_report(events: List[dict], stats: dict, filename: str) -> str:
    """
    Generate a text-based report (fallback when PDF not available).
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("SentinelGrid Security Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 70 + "\n")
            f.write(f"Total Attack Events: {stats.get('total_events', 0)}\n\n")
            
            f.write("Events by Service:\n")
            for service, count in stats.get('events_by_service', {}).items():
                f.write(f"  {service}: {count}\n")
            
            f.write("\nEvents by Severity:\n")
            for severity, count in stats.get('events_by_severity', {}).items():
                f.write(f"  {severity}: {count}\n")
            
            f.write("\nAI Classification:\n")
            for label, count in stats.get('ai_labels', {}).items():
                f.write(f"  {label}: {count}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("RECENT ATTACK EVENTS (Last 20)\n")
            f.write("=" * 70 + "\n\n")
            
            for event in events[:20]:
                f.write(f"Event ID: {event.get('id')}\n")
                f.write(f"  Timestamp: {event.get('timestamp')}\n")
                f.write(f"  Service: {event.get('service')}\n")
                f.write(f"  Source IP: {event.get('source_ip')}\n")
                f.write(f"  Username: {event.get('username', 'N/A')}\n")
                f.write(f"  Severity: {event.get('severity')}\n")
                f.write(f"  AI Label: {event.get('ai_label')}\n")
                f.write(f"  Threat Score: {event.get('threat_score')}\n")
                if event.get('command'):
                    f.write(f"  Command: {event.get('command')}\n")
                f.write("\n")
        
        logger.info(f" Text report generated: {filename}")
        return filename
    
    except Exception as e:
        logger.error(f" Error generating text report: {e}")
        raise
