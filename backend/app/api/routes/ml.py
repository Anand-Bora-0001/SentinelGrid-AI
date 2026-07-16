"""
ML (Machine Learning) routes: train, predict, status, dashboard.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Dict, List
import logging

from ..deps import get_current_user, get_admin_user, get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ml", tags=["Machine Learning"])


@router.post("/train")
async def train_ml_model(
    organization_id: Optional[int] = None,
    current_user: dict = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    """Train ML model manually"""
    try:
        from ...ml_trainer import ml_training_service
        if not ml_training_service:
            raise HTTPException(status_code=503, detail="ML service not available")
        metrics = await ml_training_service.train_model_manual(organization_id)
        return {
            "status": "success", "message": "ML model trained successfully",
            "metrics": {
                "accuracy": metrics.accuracy, "precision": metrics.precision,
                "recall": metrics.recall, "f1_score": metrics.f1_score,
                "auc_score": metrics.auc_score
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@router.get("/status")
async def get_ml_status(current_user: dict = Depends(get_current_user)):
    """Get ML model status"""
    try:
        from ...ml_trainer import ml_training_service
        from ...ml_engine import ml_engine
        if not ml_training_service:
            return {
                "status": "ML service not available",
                "ml_engine_available": bool(ml_engine),
                "basic_mode": True
            }
        return ml_training_service.get_training_status()
    except Exception as e:
        return {"status": "ML service error", "error": str(e), "basic_mode": True}


@router.post("/predict")
async def predict_threat_level(event_data: Dict, current_user: dict = Depends(get_current_user)):
    """Get ML prediction for a single event"""
    try:
        from ...ml_engine import ml_engine
        if not ml_engine:
            raise HTTPException(status_code=503, detail="ML engine not available")
        prediction = ml_engine.predict_threat(event_data)
        return {
            "threat_level": prediction.threat_level,
            "confidence": prediction.confidence,
            "threat_probability": prediction.threat_probability,
            "anomaly_score": prediction.anomaly_score,
            "model_version": prediction.model_version
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/performance")
async def get_ml_performance(current_user: dict = Depends(get_admin_user)):
    """Get ML model performance metrics"""
    try:
        from ...ml_trainer import ml_training_service
        if not ml_training_service:
            raise HTTPException(status_code=503, detail="ML service not available")
        return await ml_training_service.evaluate_model_performance()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/retrain")
async def retrain_ml_model(events_data: List[Dict], current_user: dict = Depends(get_admin_user)):
    """Retrain ML model with new data"""
    try:
        from ...ml_trainer import ml_training_service
        if not ml_training_service:
            raise HTTPException(status_code=503, detail="ML service not available")
        success = await ml_training_service.update_model_incremental(events_data)
        if success:
            return {"status": "success", "message": f"Model updated with {len(events_data)} new events"}
        return {"status": "skipped", "message": "Not enough new events for model update"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
