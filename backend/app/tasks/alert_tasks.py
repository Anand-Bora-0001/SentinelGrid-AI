"""
Background task: Alert dispatch.
Handles Telegram and email alert delivery asynchronously.
"""
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Celery fallback - runs tasks synchronously
def _task(func=None, **kwargs):
    if func is None:
        return lambda f: f
    return func

CELERY_AVAILABLE = False


@_task(name="send_telegram_alert_async", bind=True, max_retries=3)
def send_telegram_alert_async(self, message: str, organization_id: int = None):
    """Send Telegram alert in background with retry"""
    try:
        from ..alert_system import send_telegram_alert
        from ..database import SessionLocal

        db = SessionLocal()
        try:
            success = send_telegram_alert(message, db=db, organization_id=organization_id)
            if success:
                logger.info(f" Background Telegram alert sent (org: {organization_id})")
            else:
                logger.warning(f"️ Telegram alert failed (org: {organization_id})")
            return {"status": "sent" if success else "failed"}
        finally:
            db.close()

    except Exception as e:
        logger.error(f" Background Telegram alert error: {e}")
        if hasattr(self, 'retry'):
            raise self.retry(exc=e, countdown=30)
        return {"status": "error", "error": str(e)}


@_task(name="send_email_alert_async", bind=True, max_retries=3)
def send_email_alert_async(self, to_emails: list, alert_type: str, event_data: dict, pdf_path: str = None):
    """Send email alert in background with retry"""
    try:
        from ..email_service import email_service

        if not email_service.is_configured():
            logger.info("Email service not configured — skipping background email")
            return {"status": "skipped", "reason": "not_configured"}

        success = email_service.send_alert_email(
            to_emails=to_emails,
            alert_type=alert_type,
            event_data=event_data,
            pdf_report_path=pdf_path
        )

        return {"status": "sent" if success else "failed"}

    except Exception as e:
        logger.error(f" Background email alert error: {e}")
        if hasattr(self, 'retry'):
            raise self.retry(exc=e, countdown=30)
        return {"status": "error", "error": str(e)}
