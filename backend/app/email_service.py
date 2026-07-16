"""
Professional Email Service for SentinelGrid
Supports SMTP with TLS, HTML emails, and file attachments
"""
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional
import os
from datetime import datetime
from .config import settings

logger = logging.getLogger(__name__)

class EmailService:
    """Professional email service with SMTP support"""
    
    def __init__(self):
        self.smtp_server = settings.smtp_server
        self.smtp_port = settings.smtp_port
        self.username = settings.smtp_username
        self.password = settings.smtp_password
        self.from_email = settings.smtp_from_email
        self.from_name = settings.smtp_from_name
        self.use_tls = settings.smtp_use_tls
        
    def is_configured(self) -> bool:
        """Check if email service is properly configured"""
        return bool(self.smtp_server and self.username and self.password)
    
    def send_email(
        self,
        to_emails: List[str],
        subject: str,
        html_body: str,
        text_body: Optional[str] = None,
        attachments: Optional[List[str]] = None
    ) -> bool:
        """
        Send email with optional attachments
        
        Args:
            to_emails: List of recipient email addresses
            subject: Email subject
            html_body: HTML email body
            text_body: Plain text email body (optional)
            attachments: List of file paths to attach (optional)
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        if not self.is_configured():
            logger.error("Email service not configured. Check SMTP settings.")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{self.from_name} <{self.from_email}>"
            msg['To'] = ', '.join(to_emails)
            msg['Subject'] = subject
            msg['Date'] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
            
            # Add text body if provided
            if text_body:
                text_part = MIMEText(text_body, 'plain', 'utf-8')
                msg.attach(text_part)
            
            # Add HTML body
            html_part = MIMEText(html_body, 'html', 'utf-8')
            msg.attach(html_part)
            
            # Add attachments if provided
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        self._attach_file(msg, file_path)
                    else:
                        logger.warning(f"Attachment file not found: {file_path}")
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                
                server.login(self.username, self.password)
                server.send_message(msg)
            
            logger.info(f"Email sent successfully to {', '.join(to_emails)}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def _attach_file(self, msg: MIMEMultipart, file_path: str):
        """Attach a file to the email message"""
        try:
            with open(file_path, 'rb') as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            
            filename = os.path.basename(file_path)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {filename}'
            )
            
            msg.attach(part)
            logger.debug(f"Attached file: {filename}")
            
        except Exception as e:
            logger.error(f"Failed to attach file {file_path}: {e}")
    
    def send_alert_email(
        self,
        to_emails: List[str],
        alert_type: str,
        event_data: dict,
        pdf_report_path: Optional[str] = None
    ) -> bool:
        """
        Send security alert email with professional formatting
        
        Args:
            to_emails: List of recipient emails
            alert_type: Type of alert (e.g., "Critical Security Alert")
            event_data: Attack event data
            pdf_report_path: Path to PDF report to attach
            
        Returns:
            bool: True if sent successfully
        """
        subject = f" {alert_type} - SentinelGrid Security Alert"
        
        # Generate HTML email body
        html_body = self._generate_alert_html(alert_type, event_data)
        
        # Generate plain text version
        text_body = self._generate_alert_text(alert_type, event_data)
        
        # Prepare attachments
        attachments = [pdf_report_path] if pdf_report_path else None
        
        return self.send_email(
            to_emails=to_emails,
            subject=subject,
            html_body=html_body,
            text_body=text_body,
            attachments=attachments
        )
    
    def _generate_alert_html(self, alert_type: str, event_data: dict) -> str:
        """Generate professional HTML email for security alerts"""
        severity_colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ea580c',
            'MEDIUM': '#d97706',
            'LOW': '#65a30d'
        }
        
        severity = event_data.get('severity', 'UNKNOWN')
        color = severity_colors.get(severity, '#6b7280')
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SentinelGrid Security Alert</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            
            <!-- Header -->
            <div style="background: linear-gradient(135deg, #0891b2 0%, #0e7490 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
                <h1 style="margin: 0; font-size: 24px;"> SentinelGrid Security</h1>
                <p style="margin: 5px 0 0 0; opacity: 0.9;">Professional Threat Monitoring</p>
            </div>
            
            <!-- Alert Header -->
            <div style="background: {color}; color: white; padding: 15px; text-align: center;">
                <h2 style="margin: 0; font-size: 20px;"> {alert_type}</h2>
                <p style="margin: 5px 0 0 0; font-size: 14px;">Severity: {severity}</p>
            </div>
            
            <!-- Alert Details -->
            <div style="background: #f8fafc; padding: 20px; border-left: 4px solid {color};">
                <h3 style="color: {color}; margin-top: 0;">Attack Details</h3>
                
                <table style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold; width: 30%;">Source IP:</td>
                        <td style="padding: 8px 0;">{event_data.get('source_ip', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Service:</td>
                        <td style="padding: 8px 0;">{event_data.get('service', 'Unknown')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Endpoint:</td>
                        <td style="padding: 8px 0;">{event_data.get('endpoint', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Method:</td>
                        <td style="padding: 8px 0;">{event_data.get('method', 'N/A')}</td>
                    </tr>
                    <tr>
                        <td style="padding: 8px 0; font-weight: bold;">Timestamp:</td>
                        <td style="padding: 8px 0;">{event_data.get('timestamp', 'Unknown')}</td>
                    </tr>
                </table>
                
                {self._generate_location_html(event_data.get('location', {}))}
            </div>
            
            <!-- Recommendations -->
            <div style="background: white; padding: 20px; border: 1px solid #e5e7eb;">
                <h3 style="color: #374151; margin-top: 0;">️ Recommended Actions</h3>
                <ul style="color: #6b7280; padding-left: 20px;">
                    <li>Review the attached security report for detailed analysis</li>
                    <li>Monitor for additional attacks from this IP address</li>
                    <li>Consider blocking the source IP if attacks persist</li>
                    <li>Update security policies and firewall rules as needed</li>
                </ul>
            </div>
            
            <!-- Footer -->
            <div style="background: #f1f5f9; padding: 15px; text-align: center; border-radius: 0 0 8px 8px; font-size: 12px; color: #64748b;">
                <p style="margin: 0;">This alert was generated by SentinelGrid Security Monitoring</p>
                <p style="margin: 5px 0 0 0;">Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
            
        </body>
        </html>
        """
        
        return html
    
    def _generate_location_html(self, location: dict) -> str:
        """Generate location information HTML"""
        if not location:
            return ""
        
        return f"""
        <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #e5e7eb;">
            <h4 style="color: #374151; margin: 0 0 10px 0;"> Geographic Information</h4>
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 4px 0; font-weight: bold; width: 30%;">Country:</td>
                    <td style="padding: 4px 0;">{location.get('flag', '')} {location.get('country', 'Unknown')}</td>
                </tr>
                <tr>
                    <td style="padding: 4px 0; font-weight: bold;">City:</td>
                    <td style="padding: 4px 0;">{location.get('city', 'Unknown')}</td>
                </tr>
                <tr>
                    <td style="padding: 4px 0; font-weight: bold;">ISP:</td>
                    <td style="padding: 4px 0;">{location.get('isp', 'Unknown')}</td>
                </tr>
            </table>
        </div>
        """
    
    def _generate_alert_text(self, alert_type: str, event_data: dict) -> str:
        """Generate plain text version of alert email"""
        location = event_data.get('location', {})
        
        text = f"""
SentinelGrid Security Alert
========================

Alert Type: {alert_type}
Severity: {event_data.get('severity', 'Unknown')}

Attack Details:
--------------
Source IP: {event_data.get('source_ip', 'Unknown')}
Service: {event_data.get('service', 'Unknown')}
Endpoint: {event_data.get('endpoint', 'N/A')}
Method: {event_data.get('method', 'N/A')}
Timestamp: {event_data.get('timestamp', 'Unknown')}

Geographic Information:
----------------------
Country: {location.get('country', 'Unknown')}
City: {location.get('city', 'Unknown')}
ISP: {location.get('isp', 'Unknown')}

Recommended Actions:
-------------------
- Review the attached security report for detailed analysis
- Monitor for additional attacks from this IP address
- Consider blocking the source IP if attacks persist
- Update security policies and firewall rules as needed

This alert was generated by SentinelGrid Security Monitoring
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """
        
        return text.strip()

# Global email service instance
email_service = EmailService()
