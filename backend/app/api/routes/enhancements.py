"""
Enhancement module routes (threat intelligence, deep learning, analytics, etc.)
These are optional — endpoints return 503 if modules aren't available.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import Dict
import logging

from ..deps import get_current_user, get_admin_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["Enhancements"])

# Enhancement module references (set by main.py during startup)
_modules = {}

def set_enhancement_modules(modules: dict):
    """Called by main.py to inject enhancement module references"""
    _modules.update(modules)


@router.get("/enhancements/status")
async def get_enhancements_status(current_user: dict = Depends(get_current_user)):
    """Get status of all enhancement modules"""
    return {
        "enhancements_available": _modules.get("available", False),
        "modules": {k: bool(v) for k, v in _modules.items() if k != "available"}
    }


@router.get("/threat-intelligence/analyze/{ip}")
async def analyze_ip(ip: str, current_user: dict = Depends(get_current_user)):
    engine = _modules.get("threat_intel_engine")
    if not engine:
        raise HTTPException(status_code=503, detail="Threat intelligence not available")
    try:
        result = await engine.analyze_ip(ip)
        return result.to_dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stream/metrics")
async def get_stream_metrics(current_user: dict = Depends(get_current_user)):
    sp = _modules.get("stream_processor")
    if not sp:
        raise HTTPException(status_code=503, detail="Stream processor not available")
    return await sp.get_current_metrics()


@router.get("/performance/metrics")
async def get_performance_metrics(current_user: dict = Depends(get_current_user)):
    pm = _modules.get("performance_monitor")
    if not pm:
        raise HTTPException(status_code=503, detail="Performance monitor not available")
    return pm.get_current_metrics()


@router.get("/threat-hunting/alerts")
async def get_threat_hunting_alerts(limit: int = 50, current_user: dict = Depends(get_current_user)):
    th = _modules.get("threat_hunter")
    if not th:
        raise HTTPException(status_code=503, detail="Threat hunter not available")
    return th.get_recent_alerts(limit)


@router.post("/deep-learning/predict")
async def deep_learning_predict(event_data: Dict, current_user: dict = Depends(get_current_user)):
    dl = _modules.get("deep_learning_engine")
    if not dl:
        raise HTTPException(status_code=503, detail="Deep learning engine not available")
    return await dl.predict_advanced_threat(event_data)


@router.get("/analytics/insights")
async def get_analytics_insights(
    days_back: int = 30,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    pa = _modules.get("predictive_analytics")
    if not pa:
        raise HTTPException(status_code=503, detail="Predictive analytics not available")
    from .events import get_events
    events = get_events(limit=1000, current_user=current_user, db=db)
    return await pa.generate_insights(events, days_back)


@router.get("/risk-assessment/report")
async def get_risk_assessment(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    ra = _modules.get("risk_assessment")
    if not ra:
        raise HTTPException(status_code=503, detail="Risk assessment not available")
    from .events import get_events
    events = get_events(limit=500, current_user=current_user, db=db)
    return await ra.generate_comprehensive_report(events)


@router.post("/automated-response/configure")
async def configure_automated_response(config: Dict, current_user: dict = Depends(get_admin_user)):
    ar = _modules.get("automated_response")
    if not ar:
        raise HTTPException(status_code=503, detail="Automated response not available")
    success = ar.update_configuration(config)
    return {"status": "success" if success else "failed", "config": config}


@router.get("/cache/stats")
async def get_cache_stats(current_user: dict = Depends(get_admin_user)):
    ic = _modules.get("intelligent_cache")
    if not ic:
        raise HTTPException(status_code=503, detail="Intelligent cache not available")
    return ic.get_statistics()


@router.post("/database/optimize")
async def optimize_database(current_user: dict = Depends(get_admin_user)):
    do = _modules.get("database_optimizer")
    if not do:
        raise HTTPException(status_code=503, detail="Database optimizer not available")
    results = await do.optimize_database()
    return {"status": "success", "results": results}


@router.get("/security-audit/logs")
async def get_audit_logs(limit: int = 100, current_user: dict = Depends(get_admin_user)):
    sal = _modules.get("security_audit_logger")
    if not sal:
        raise HTTPException(status_code=503, detail="Security audit logger not available")
    return sal.get_recent_logs(limit)
