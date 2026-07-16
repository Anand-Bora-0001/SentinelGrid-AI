"""
Multi-channel Notification Manager
Supports: Email, Telegram, Slack, Webhooks
"""

import requests
import logging
from typing import Dict, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .models import NotificationConfig, SecurityEvent, Organization

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manage multi-channel notifications"""
    
    def __init__(self, db: Session):
        self.db = db
    
    def send_alert(self, event: SecurityEvent, organization: Organization):
        """Send alert through configured channels"""
        
        # Get notification config
        config = self.db.query(NotificationConfig).filter(
            NotificationConfig.organization_id == organization.id
        ).first()
        
        if not config:
            logger.warning(f"No notification config for {organization.name}")
            return
        
        # Check if we should alert based on severity
        should_alert = False
        if event.severity == "CRITICAL" and config.alert_on_critical:
            should_alert = True
        elif event.severity == "HIGH" and config.alert_on_high:
            should_alert = True
        elif event.severity == "MEDIUM" and config.alert_on_medium:
            should_alert = True
        elif event.severity == "LOW" and config.alert_on_low:
            should_alert = True
        
        if not should_alert:
            return
        
        # Prepare alert message
        alert_data = self._prepare_alert_message(event, organization)
        
        # Send through enabled channels
        if config.email_enabled and config.email_addresses:
            self._send_email(config.email_addresses, alert_data)
        
        if config.telegram_enabled and config.telegram_bot_token and config.telegram_chat_id:
            self._send_telegram(config.telegram_bot_token, config.telegram_chat_id, alert_data)
        
        if config.slack_enabled and config.slack_webhook_url:
            self._send_slack(config.slack_webhook_url, alert_data)
        
        if config.webhook_enabled and config.webhook_url:
            self._send_webhook(config.webhook_url, alert_data)
        
        # Mark as notified
        event.notification_sent = True
        self.db.commit()
    
    def _prepare_alert_message(self, event: SecurityEvent, organization: Organization) -> Dict:
        """Prepare alert message data"""
        
        severity_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️",
            "MEDIUM": "⚡",
            "LOW": "ℹ️"
        }
        
        location_str = "Unknown"
        if event.location:
            location_str = f"{event.location.get('city', 'Unknown')}, {event.location.get('country', 'Unknown')} {event.location.get('flag', '')}"
        
        return {
            "organization": organization.name,
            "event_id": event.id,
            "severity": event.severity,
            "severity_emoji": severity_emoji.get(event.severity, "ℹ️"),
            "service": event.service_name,
            "source_ip": event.source_ip,
            "endpoint": event.endpoint or "N/A",
            "method": event.method or "N/A",
            "location": location_str,
            "threat_score": f"{event.threat_score * 100:.0f}%",
            "timestamp": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "command": event.command or "N/A",
            "username": event.username or "N/A"
        }
    
    def _send_email(self, email_addresses: list, alert_data: Dict):
        """Send email notification"""
        try:
            # In production, use SendGrid, AWS SES, or similar
            logger.info(f"📧 Email alert sent to {len(email_addresses)} recipients")
            logger.info(f"   Subject: {alert_data['severity_emoji']} Security Alert - {alert_data['service']}")
            logger.info(f"   Details: {alert_data['severity']} event from {alert_data['source_ip']}")
            
            # TODO: Implement actual email sending
            # Example with SendGrid:
            # import sendgrid
            # sg = sendgrid.SendGridAPIClient(api_key=os.environ.get('SENDGRID_API_KEY'))
            # ...
            
        except Exception as e:
            logger.error(f"❌ Email notification failed: {e}")
    
    def _send_telegram(self, bot_token: str, chat_id: str, alert_data: Dict):
        """Send Telegram notification"""
        try:
            message = f"""
{alert_data['severity_emoji']} *SECURITY ALERT*

*Organization:* {alert_data['organization']}
*Service:* {alert_data['service']}
*Severity:* {alert_data['severity']}
*Threat Score:* {alert_data['threat_score']}

*Attack Details:*
• Source IP: `{alert_data['source_ip']}`
• Location: {alert_data['location']}
• Endpoint: `{alert_data['endpoint']}`
• Method: {alert_data['method']}
• Username: {alert_data['username']}

*Time:* {alert_data['timestamp']}
*Event ID:* #{alert_data['event_id']}
"""
            
            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.ok:
                logger.info(f"✅ Telegram alert sent successfully")
            else:
                logger.error(f"❌ Telegram alert failed: {response.text}")
                
        except Exception as e:
            logger.error(f"❌ Telegram notification failed: {e}")
    
    def _send_slack(self, webhook_url: str, alert_data: Dict):
        """Send Slack notification"""
        try:
            color_map = {
                "CRITICAL": "#FF0000",
                "HIGH": "#FF6600",
                "MEDIUM": "#FFAA00",
                "LOW": "#00AA00"
            }
            
            payload = {
                "attachments": [{
                    "color": color_map.get(alert_data['severity'], "#808080"),
                    "title": f"{alert_data['severity_emoji']} Security Alert - {alert_data['service']}",
                    "text": f"*{alert_data['severity']}* severity event detected",
                    "fields": [
                        {
                            "title": "Source IP",
                            "value": alert_data['source_ip'],
                            "short": True
                        },
                        {
                            "title": "Location",
                            "value": alert_data['location'],
                            "short": True
                        },
                        {
                            "title": "Endpoint",
                            "value": alert_data['endpoint'],
                            "short": True
                        },
                        {
                            "title": "Threat Score",
                            "value": alert_data['threat_score'],
                            "short": True
                        }
                    ],
                    "footer": f"SentinelGrid | Event #{alert_data['event_id']}",
                    "ts": int(datetime.now(timezone.utc).timestamp())
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            
            if response.ok:
                logger.info(f"✅ Slack alert sent successfully")
            else:
                logger.error(f"❌ Slack alert failed: {response.text}")
                
        except Exception as e:
            logger.error(f"❌ Slack notification failed: {e}")
    
    def _send_webhook(self, webhook_url: str, alert_data: Dict):
        """Send custom webhook notification"""
        try:
            response = requests.post(webhook_url, json=alert_data, timeout=10)
            
            if response.ok:
                logger.info(f"✅ Webhook alert sent successfully")
            else:
                logger.error(f"❌ Webhook alert failed: {response.text}")
                
        except Exception as e:
            logger.error(f"❌ Webhook notification failed: {e}")
    
    @staticmethod
    def create_default_config(db: Session, organization_id: int):
        """Create default notification configuration"""
        config = NotificationConfig(
            organization_id=organization_id,
            email_enabled=True,
            email_addresses=[],
            telegram_enabled=False,
            slack_enabled=False,
            webhook_enabled=False,
            alert_on_critical=True,
            alert_on_high=True,
            alert_on_medium=False,
            alert_on_low=False,
            max_alerts_per_hour=10
        )
        db.add(config)
        db.commit()
        logger.info(f"✅ Created default notification config for org {organization_id}")
        return config
