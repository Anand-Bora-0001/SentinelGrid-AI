"""
SentinelGrid AI — Health and Status Diagnostics API
"""
from fastapi import APIRouter, Depends
from datetime import datetime
import logging
import psutil
import os
from sqlalchemy.orm import Session
from ..deps import get_db

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Health"])


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """SentinelGrid diagnostics health check"""
    # Database stats
    db_status = "unreachable"
    db_metrics = {}
    try:
        from ...models import SecurityTelemetry, Incident, Asset, Vulnerability
        db_status = "healthy"
        db_metrics = {
            "telemetry_count": db.query(SecurityTelemetry).count(),
            "incident_count": db.query(Incident).count(),
            "asset_count": db.query(Asset).count(),
            "vulnerability_count": db.query(Vulnerability).count(),
            "active_incidents": db.query(Incident).filter(Incident.status.in_(["new", "investigating"])).count(),
        }
    except Exception as e:
        logger.error(f"Health DB query failed: {e}")
        db_status = f"unhealthy: {str(e)}"

    # AI Systems status
    ai_status = {}
    try:
        from ...ai.anomaly_detector import anomaly_detector
        ai_status["anomaly_detector"] = "loaded" if anomaly_detector else "not_loaded"
    except Exception as e:
        ai_status["anomaly_detector"] = f"error: {str(e)}"

    try:
        from ...ai.mitre_engine import mitre_engine
        ai_status["mitre_engine"] = "loaded" if mitre_engine else "not_loaded"
    except Exception as e:
        ai_status["mitre_engine"] = f"error: {str(e)}"

    try:
        from ...ai.threat_rag import threat_rag
        ai_status["threat_rag"] = "loaded" if threat_rag else "not_loaded"
        ai_status["vector_store_initialized"] = threat_rag.db_available
    except Exception as e:
        ai_status["threat_rag"] = f"error: {str(e)}"
        ai_status["vector_store_initialized"] = False

    # System resources
    try:
        process = psutil.Process(os.getpid())
        ram_usage_mb = round(process.memory_info().rss / (1024 * 1024), 2)
        cpu_usage_pct = psutil.cpu_percent(interval=0.1)
    except Exception:
        ram_usage_mb = "unknown"
        cpu_usage_pct = "unknown"

    from ...config import settings

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "service": settings.app_name,
        "version": settings.app_version,
        "timestamp": datetime.utcnow().isoformat(),
        "system_resources": {
            "ram_usage_mb": ram_usage_mb,
            "cpu_usage_pct": cpu_usage_pct,
            "process_id": os.getpid()
        },
        "ai_engines": ai_status,
        "database": {
            "status": db_status,
            "metrics": db_metrics
        },
        "integrations": {
            "telegram": "configured" if settings.is_telegram_configured else "not_configured",
            "email": "configured" if settings.is_email_configured else "not_configured"
        }
    }
