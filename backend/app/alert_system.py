"""
SentinelGrid Alert System with Real Email Integration
Handles Telegram and Email notifications with PDF reports
"""
import logging
import requests
import os
from datetime import datetime
from typing import Optional, List
from sqlalchemy.orm import Session
from .config import settings
from .email_service import email_service

logger = logging.getLogger(__name__)

def send_telegram_alert(message: str, db: Session = None, organization_id: int = None) -> bool:
    """Send alert message to Telegram using organization's configuration"""
    try:
        # Try to get configuration from database first
        if db and organization_id:
            from .models import NotificationConfig
            config = db.query(NotificationConfig).filter(
                NotificationConfig.organization_id == organization_id,
                NotificationConfig.telegram_enabled == True
            ).first()
            
            if config and config.telegram_bot_token and config.telegram_chat_id:
                url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
                payload = {
                    'chat_id': config.telegram_chat_id,
                    'text': message,
                    'parse_mode': 'HTML'
                }
                
                response = requests.post(url, json=payload, timeout=10)
                
                if response.ok:
                    logger.info("✅ Telegram alert sent successfully (database config)")
                    return True
                else:
                    logger.error(f"❌ Telegram alert failed: {response.status_code} - {response.text}")
                    return False
    except Exception as e:
        logger.warning(f"Database Telegram config failed: {e}")
    
    # Fallback to global settings
    if not settings.is_telegram_configured:
        logger.warning("Telegram not configured - skipping alert")
        return False
    
    try:
        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
        payload = {
            'chat_id': settings.telegram_chat_id,
            'text': message,
            'parse_mode': 'HTML'
        }
        
        response = requests.post(url, json=payload, timeout=10)
        
        if response.ok:
            logger.info("✅ Telegram alert sent successfully (global config)")
            return True
        else:
            logger.error(f"❌ Telegram alert failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Telegram alert error: {e}")
        return False

def send_telegram_document(file_path: str, caption: str = "", db: Session = None, organization_id: int = None) -> bool:
    """Send document to Telegram using organization's configuration"""
    try:
        # Try to get configuration from database first
        if db and organization_id:
            from .models import NotificationConfig
            config = db.query(NotificationConfig).filter(
                NotificationConfig.organization_id == organization_id,
                NotificationConfig.telegram_enabled == True
            ).first()
            
            if config and config.telegram_bot_token and config.telegram_chat_id:
                if not os.path.exists(file_path):
                    logger.error(f"❌ File not found: {file_path}")
                    return False
                
                url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendDocument"
                
                with open(file_path, 'rb') as file:
                    files = {'document': file}
                    data = {
                        'chat_id': config.telegram_chat_id,
                        'caption': caption
                    }
                    
                    response = requests.post(url, files=files, data=data, timeout=30)
                
                if response.ok:
                    logger.info(f"✅ Telegram document sent: {os.path.basename(file_path)} (database config)")
                    return True
                else:
                    logger.error(f"❌ Telegram document failed: {response.status_code} - {response.text}")
                    return False
    except Exception as e:
        logger.warning(f"Database Telegram document failed: {e}")
    
    # Fallback to global settings
    if not settings.is_telegram_configured:
        logger.warning("Telegram not configured - skipping document")
        return False
    
    if not os.path.exists(file_path):
        logger.error(f"❌ File not found: {file_path}")
        return False
    
    try:
        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendDocument"
        
        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {
                'chat_id': settings.telegram_chat_id,
                'caption': caption
            }
            
            response = requests.post(url, files=files, data=data, timeout=30)
        
        if response.ok:
            logger.info(f"✅ Telegram document sent: {os.path.basename(file_path)} (global config)")
            return True
        else:
            logger.error(f"❌ Telegram document failed: {response.status_code} - {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"❌ Telegram document error: {e}")
        return False

def send_email_alert(
    to_emails: List[str],
    alert_type: str,
    event_data: dict,
    pdf_report_path: Optional[str] = None
) -> bool:
    """
    Send professional email alert with PDF report
    
    Args:
        to_emails: List of recipient email addresses
        alert_type: Type of alert (e.g., "Critical Security Alert")
        event_data: Attack event data
        pdf_report_path: Path to PDF report to attach
        
    Returns:
        bool: True if sent successfully
    """
    if not email_service.is_configured():
        logger.warning("Email service not configured - skipping alert")
        return False
    
    try:
        success = email_service.send_alert_email(
            to_emails=to_emails,
            alert_type=alert_type,
            event_data=event_data,
            pdf_report_path=pdf_report_path
        )
        
        if success:
            logger.info(f"✅ Email alert sent to {', '.join(to_emails)}")
        else:
            logger.error("❌ Failed to send email alert")
        
        return success
        
    except Exception as e:
        logger.error(f"❌ Email alert error: {e}")
        return False

def handle_security_event(event: dict, db: Session = None) -> None:
    """
    Handle incoming attack event and trigger appropriate alerts
    
    Args:
        event: Attack event data dictionary
        db: Database session for getting organization config
    """
    try:
        severity = event.get('severity', 'UNKNOWN')
        source_ip = event.get('source_ip', 'Unknown')
        service = event.get('service', 'Unknown')
        
        logger.info(f"🚨 Processing {severity} alert from {source_ip} on {service}")
        
        # Only alert on MEDIUM, HIGH and CRITICAL events
        if severity not in ['MEDIUM', 'HIGH', 'CRITICAL']:
            logger.debug(f"Skipping alert for {severity} event")
            return
        
        # Generate alert message for Telegram
        alert_message = generate_alert_message(event)
        
        # Check for async vs sync execution
        from .worker import CELERY_AVAILABLE
        from .tasks.alert_tasks import send_telegram_alert_async, send_email_alert_async

        # Send Telegram alert
        organization_id = event.get('organization_id')
        if CELERY_AVAILABLE:
            send_telegram_alert_async.delay(alert_message, organization_id=organization_id)
            telegram_sent = True # Assumed queued
        else:
            telegram_sent = send_telegram_alert(
                alert_message,
                db=db,
                organization_id=organization_id
            )
        
        # Send email alerts (if configured)
        pdf_path = None
        if email_service.is_configured():
            # Try to get recipients from DB
            recipients = []
            if db and organization_id:
                from .models import NotificationConfig
                config = db.query(NotificationConfig).filter(
                    NotificationConfig.organization_id == organization_id,
                    NotificationConfig.email_enabled == True
                ).first()
                if config and config.email_addresses:
                    recipients = config.email_addresses

            if recipients:
                # Generate PDF report for email attachment (sync for now as it's needed for email task)
                try:
                    from .report_generator import generate_pdf_report
                    recent_events = [event]
                    stats = {'total_events': 1, 'events_by_severity': {severity: 1}}
                    pdf_path = generate_pdf_report(recent_events, stats)
                except Exception as e:
                    logger.error(f"Failed to generate PDF report: {e}")

                if CELERY_AVAILABLE:
                    send_email_alert_async.delay(
                        to_emails=recipients,
                        alert_type=f"Critical Security Alert from {source_ip}",
                        event_data=event,
                        pdf_path=pdf_path
                    )
                else:
                    send_email_alert(
                        to_emails=recipients,
                        alert_type=f"Critical Security Alert from {source_ip}",
                        event_data=event,
                        pdf_report_path=pdf_path
                    )
            else:
                logger.info("Email service configured but no recipients specified for automatic alerts")
        
        logger.info(f"✅ Alert processing delegated (Async: {CELERY_AVAILABLE})")
        
    except Exception as e:
        logger.error(f"❌ Error handling attack event: {e}")

def generate_alert_message(event: dict) -> str:
    """Generate formatted alert message for Telegram"""
    severity = event.get('severity', 'UNKNOWN')
    source_ip = event.get('source_ip', 'Unknown')
    service = event.get('service', 'Unknown')
    endpoint = event.get('endpoint', 'N/A')
    timestamp = event.get('timestamp', datetime.now().isoformat())
    location = event.get('location', {})
    
    # Severity emoji mapping
    severity_emojis = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🟢'
    }
    
    emoji = severity_emojis.get(severity, '⚪')
    flag = location.get('flag', '🌍')
    country = location.get('country', 'Unknown')
    city = location.get('city', 'Unknown')
    
    message = f"""
🚨 <b>SentinelGrid Security Alert</b>

{emoji} <b>Severity:</b> {severity}
🎯 <b>Service:</b> {service}
🌐 <b>Source IP:</b> <code>{source_ip}</code>
📍 <b>Location:</b> {flag} {city}, {country}
🔗 <b>Endpoint:</b> {endpoint}
⏰ <b>Time:</b> {timestamp}

🛡️ <b>Threat detected and logged</b>
📊 Check dashboard for details
    """
    
    return message.strip()

# Backward compatibility functions
def format_alert_message(event: dict) -> str:
    """Legacy function - use generate_alert_message instead"""
    return generate_alert_message(event)

def send_comprehensive_alert(event: dict, alert_type: str = "telegram"):
    """Send comprehensive alert with PDF report"""
    try:
        # Generate mini report for this specific event
        mini_report_data = {
            "total_events": 1,
            "events_by_service": {event.get("service", "Unknown"): 1},
            "events_by_severity": {event.get("severity", "Unknown"): 1},
            "ai_labels": {event.get("ai_label", "unknown"): 1}
        }
        
        # Generate PDF report
        from .report_generator import generate_pdf_report
        pdf_path = generate_pdf_report([event], mini_report_data)
        
        if alert_type == "telegram":
            # Send detailed message with PDF
            message = generate_alert_message(event)
            send_telegram_alert(message)
            send_telegram_document(pdf_path, f"Security Alert Report - Event #{event.get('id')}")
        elif alert_type == "email":
            # Send email alert (would need recipient list)
            logger.info("Email alert requested but no recipients specified")
        
        logger.info(f"📄 Comprehensive {alert_type} alert sent with PDF report")
        
    except Exception as e:
        logger.error(f"❌ Failed to send comprehensive alert: {e}")

def send_test_telegram_alert() -> bool:
    """Send test Telegram alert"""
    test_message = f"""
🧪 <b>SentinelGrid Test Alert</b>

✅ <b>System Status:</b> All systems operational
📊 <b>Monitoring:</b> Active
🔔 <b>Alerts:</b> Configured and working
⏰ <b>Test Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This is a test message from SentinelGrid Security Monitoring.
    """
    
    return send_telegram_alert(test_message)

def send_test_email_alert(to_emails: List[str]) -> bool:
    """Send test email alert"""
    test_event = {
        'severity': 'HIGH',
        'source_ip': '192.168.1.100',
        'service': 'TEST',
        'endpoint': '/test-alert',
        'method': 'GET',
        'timestamp': datetime.now().isoformat(),
        'location': {
            'country': 'Test Country',
            'city': 'Test City',
            'flag': '🧪',
            'isp': 'Test ISP'
        }
    }
    
    return send_email_alert(
        to_emails=to_emails,
        alert_type="Test Security Alert",
        event_data=test_event
    )
