"""
Background task: Report generation.
Runs async via Celery when available, falls back to synchronous execution.
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


@_task(name="generate_report_async", bind=True, max_retries=2)
def generate_report_async(self, report_format: str, events: list, stats: dict, send_telegram: bool = False, organization_id: int = None):
    """
    Generate report in background.
    Supports: pdf, csv, xlsx
    """
    try:
        logger.info(f"📝 Generating {report_format.upper()} report ({len(events)} events)...")

        from ..report_generator import generate_csv_report, generate_pdf_report
        from ..excel_export import generate_excel_report

        if report_format == "xlsx":
            filepath = generate_excel_report(events, stats)
        elif report_format == "csv":
            filepath = generate_csv_report(events)
        else:
            filepath = generate_pdf_report(events, stats)

        # Send to Telegram if requested
        if send_telegram and filepath:
            try:
                from ..alert_system import send_telegram_document
                from ..database import SessionLocal
                db = SessionLocal()
                try:
                    send_telegram_document(
                        filepath,
                        caption=f"SentinelGrid {report_format.upper()} Report",
                        db=db,
                        organization_id=organization_id
                    )
                finally:
                    db.close()
            except Exception as e:
                logger.warning(f"Telegram send failed in background: {e}")

        logger.info(f"✅ Report generated: {filepath}")
        return {"status": "success", "filepath": filepath, "format": report_format}

    except Exception as e:
        logger.error(f"❌ Report generation failed: {e}")
        if hasattr(self, 'retry'):
            raise self.retry(exc=e, countdown=10)
        return {"status": "error", "error": str(e)}
