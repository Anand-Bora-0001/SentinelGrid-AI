"""
Alert testing routes (Telegram + Email).
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
import re
import logging

from ..deps import get_current_user, get_db
from ...config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["Alerts"])

# Simple global storage for saved emails
saved_emails = []


@router.post("/test-telegram")
async def test_telegram_alert(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Send test alert to Telegram with PDF report"""
    try:
        from .events import get_events, get_statistics
        from ...report_generator import generate_pdf_report
        from ...alert_system import send_telegram_alert, send_telegram_document

        events_response = get_events(limit=10, current_user=current_user, db=db)
        stats_response = get_statistics(current_user, db)
        pdf_path = generate_pdf_report(events_response, stats_response)

        alert_message = f"""
 *SentinelGrid Test Alert*

 *System Status:*
• Total Events: {stats_response.get('total_events', 0)}
• Critical Alerts: {stats_response.get('events_by_severity', {}).get('CRITICAL', 0)}

⏰ *Test Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """

        org_id = current_user.get("organization_id")
        message_sent = send_telegram_alert(alert_message, db=db, organization_id=org_id)
        pdf_sent = False
        if message_sent and pdf_path:
            pdf_sent = send_telegram_document(pdf_path, " SentinelGrid Security Report", db=db, organization_id=org_id)

        if message_sent:
            return {"status": "success", "message": "Test alert sent!", "pdf_sent": pdf_sent}
        return {"status": "error", "message": "Failed to send Telegram alert."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Telegram alert failed: {str(e)}")


@router.post("/test-email")
async def test_email_alert(
    request: dict,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Send test email alert with PDF report"""
    try:
        global saved_emails

        email_address = request.get("email_address")
        save_email = request.get("save_email", False)

        if not email_address:
            raise HTTPException(status_code=400, detail="Email address is required")

        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email_address):
            raise HTTPException(status_code=400, detail="Invalid email format")

        if save_email and email_address not in saved_emails:
            saved_emails.append(email_address)

        from .events import get_events, get_statistics
        from ...report_generator import generate_pdf_report

        events_response = get_events(limit=20, current_user=current_user, db=db)
        stats_response = get_statistics(current_user, db)
        pdf_path = generate_pdf_report(events_response, stats_response)

        try:
            from ...email_service import email_service
            if email_service.is_configured():
                test_event = {
                    'severity': 'HIGH', 'source_ip': '192.168.1.100',
                    'service': 'TEST', 'endpoint': '/test-alert',
                    'method': 'GET', 'timestamp': datetime.now().isoformat(),
                    'location': {'country': 'Test Country', 'city': 'Test City', 'flag': '', 'isp': 'Test ISP'}
                }
                email_sent = email_service.send_alert_email(
                    to_emails=[email_address], alert_type="Test Security Alert",
                    event_data=test_event, pdf_report_path=pdf_path
                )
                if email_sent:
                    return {"status": "success", "message": f"Email alert sent to {email_address}!", "pdf_attached": True}
                return {"status": "error", "message": "Failed to send email."}
        except ImportError:
            pass

        return {
            "status": "success",
            "message": f"Email alert simulated for {email_address}!",
            "pdf_attached": True,
            "note": "Configure SMTP in .env for real email sending"
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Email alert failed: {str(e)}")


@router.get("/config")
async def get_alert_config(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get current alert configuration"""
    try:
        from ...models import User, NotificationConfig
        if db:
            user = db.query(User).filter(User.username == current_user["username"]).first()
            if user and hasattr(user, 'organization') and user.organization:
                config = db.query(NotificationConfig).filter(
                    NotificationConfig.organization_id == user.organization_id
                ).first()
                if config:
                    return {
                        "telegram_enabled": config.telegram_enabled,
                        "email_enabled": config.email_enabled,
                        "saved_emails": config.email_addresses or [],
                        "alert_on_critical": config.alert_on_critical,
                        "alert_on_high": config.alert_on_high,
                        "alert_on_medium": config.alert_on_medium,
                        "alert_on_low": config.alert_on_low
                    }
    except Exception as e:
        logger.warning(f"DB alert config failed: {e}")

    return {
        "telegram_enabled": False,
        "email_enabled": len(saved_emails) > 0,
        "saved_emails": saved_emails,
        "alert_on_critical": True,
        "alert_on_high": True,
        "alert_on_medium": False,
        "alert_on_low": False
    }
