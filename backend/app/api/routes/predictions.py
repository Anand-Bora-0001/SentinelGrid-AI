"""SentinelGrid AI — Prediction API Routes"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone, timedelta
import logging
from ..deps import get_current_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/predictions", tags=["Predictions"])


@router.get("/next-actions")
def predict_next_actions(current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """Predict attacker next steps based on current observations"""
    from ...ai.attack_predictor import attack_predictor
    from ...ai.mitre_engine import mitre_engine
    from ...models import SecurityTelemetry, User
    try:
        user = db.query(User).filter(User.username == current_user["username"]).first()
        events = db.query(SecurityTelemetry).filter(
            SecurityTelemetry.organization_id == user.organization_id,
            SecurityTelemetry.mitre_technique_id.isnot(None)
        ).order_by(SecurityTelemetry.timestamp.desc()).limit(100).all()
        technique_ids = list(set(e.mitre_technique_id for e in events if e.mitre_technique_id))
        stage_info = mitre_engine.identify_attack_stage(technique_ids)
        prediction = attack_predictor.predict_next_actions(technique_ids, stage_info["current_stage"])
        return prediction
    except Exception as e:
        logger.warning(f"Prediction failed: {e}")
        return attack_predictor.predict_next_actions([], "Unknown")


@router.get("/risk-forecast")
def get_risk_forecast(days: int = Query(7, ge=1, le=30), current_user: dict = Depends(get_current_user), db: Session = Depends(get_db)):
    """7-day risk forecast based on event volume trends"""
    from ...ai.attack_predictor import attack_predictor
    from ...models import SecurityTelemetry, User
    try:
        user = db.query(User).filter(User.username == current_user["username"]).first()
        now = datetime.now(timezone.utc)
        daily_counts = []
        for i in range(14, 0, -1):
            day_start = now - timedelta(days=i)
            day_end = now - timedelta(days=i-1)
            count = db.query(SecurityTelemetry).filter(
                SecurityTelemetry.organization_id == user.organization_id,
                SecurityTelemetry.timestamp >= day_start,
                SecurityTelemetry.timestamp < day_end,
            ).count()
            daily_counts.append(count)
        return attack_predictor.get_risk_forecast(daily_counts, days)
    except Exception as e:
        logger.warning(f"Forecast failed: {e}")
        return {"forecast": [], "trend": "insufficient_data", "current_risk": 0}


@router.post("/what-if")
def what_if_analysis(data: dict, current_user: dict = Depends(get_current_user)):
    """What-if scenario analysis"""
    from ...ai.attack_predictor import attack_predictor
    techniques = data.get("techniques", [])
    tactic = data.get("current_tactic", "Initial Access")
    return attack_predictor.predict_next_actions(techniques, tactic, top_k=data.get("top_k", 5))
