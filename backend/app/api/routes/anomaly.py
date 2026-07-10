from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any

from app.database import get_db
from app.models import BehaviorProfile, AnomalyEvent, RiskAssessment
from app.ai.anomaly_engine import AnomalyDetector, BaselineBuilder, RiskScorer

router = APIRouter(prefix="/api/v1/anomaly", tags=["Anomaly Detection"])

# Note: In a real app, dependencies like get_current_user would be added to these endpoints.

@router.post("/analyze")
def analyze_anomaly(event_data: Dict[str, Any], db: Session = Depends(get_db)):
    """
    Analyze a new event against the entity's behavior baseline.
    """
    organization_id = event_data.get("organization_id", 1) # Default to 1 for demonstration
    entity_id = event_data.get("entity_id")
    entity_type = event_data.get("entity_type", "user")
    
    if not entity_id:
        raise HTTPException(status_code=400, detail="entity_id is required")
        
    # Fetch profile
    profile = db.query(BehaviorProfile).filter(
        BehaviorProfile.organization_id == organization_id,
        BehaviorProfile.entity_type == entity_type,
        BehaviorProfile.entity_id == entity_id
    ).first()
    
    if not profile:
        # Build baseline on the fly if missing
        builder = BaselineBuilder(db)
        profile = builder.build_user_baseline(organization_id, entity_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Could not build baseline for entity")
            
    detector = AnomalyDetector()
    anomaly_result = detector.detect_anomalies(event_data, profile)
    
    scorer = RiskScorer()
    context = {"login_time": None} # In a real implementation, extract from event_data
    risk_result = scorer.calculate_risk(anomaly_result, context)
    
    # Save the assessment
    assessment = RiskAssessment(
        organization_id=organization_id,
        entity_type=entity_type,
        entity_id=entity_id,
        risk_score=risk_result["risk_score"],
        explanations=risk_result["reasons"]
    )
    db.add(assessment)
    
    if anomaly_result["is_anomaly"]:
        anomaly_event = AnomalyEvent(
            organization_id=organization_id,
            profile_id=profile.id,
            event_type="behavior_anomaly",
            details={k: float(v) for k, v in anomaly_result.get("deviation_scores", {}).items()},
            deviation_score=float(anomaly_result["anomaly_score"])
        )
        db.add(anomaly_event)
        
    db.commit()
    
    # Ensure all values are native Python types for JSON serialization
    safe_risk = {
        "risk_score": float(risk_result.get("risk_score", 0)),
        "reasons": list(risk_result.get("reasons", []))
    }
    
    return {
        "status": "success",
        "is_anomaly": bool(anomaly_result["is_anomaly"]),
        "risk_assessment": safe_risk
    }


@router.get("/events")
def get_anomaly_events(db: Session = Depends(get_db), limit: int = 50):
    """
    Retrieve anomalous events.
    """
    events = db.query(AnomalyEvent).order_by(AnomalyEvent.timestamp.desc()).limit(limit).all()
    return events


@router.get("/high-risk")
def get_high_risk_entities(db: Session = Depends(get_db), limit: int = 50):
    """
    Retrieve entities currently flagged as high-risk.
    """
    assessments = db.query(RiskAssessment).filter(
        RiskAssessment.risk_score > 70
    ).order_by(RiskAssessment.risk_score.desc()).limit(limit).all()
    return assessments


@router.get("/profile/{entity_id}")
def get_entity_profile(entity_id: str, db: Session = Depends(get_db)):
    """
    Retrieve the behavior profile for a specific entity.
    """
    profile = db.query(BehaviorProfile).filter(
        BehaviorProfile.entity_id == entity_id
    ).first()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
        
    return profile
