"""
SentinelGrid ML Training Service
Handles automated model training, retraining, and performance monitoring
"""
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from .database import get_db
from .models import SecurityEvent, Organization
from .ml_engine import ml_engine, ModelMetrics
from .config import settings

logger = logging.getLogger(__name__)

class MLTrainingService:
    """Service for managing ML model training and updates"""
    
    def __init__(self):
        self.min_training_samples = 50
        self.retrain_interval_hours = 24
        self.last_training_time = None
        self.training_in_progress = False
    
    async def auto_train_model(self) -> Optional[ModelMetrics]:
        """Automatically train model if conditions are met"""
        try:
            if self.training_in_progress:
                logger.info("Training already in progress, skipping")
                return None
            
            # Check if we need to retrain
            if not self._should_retrain():
                return None
            
            logger.info("Starting automatic model training...")
            self.training_in_progress = True
            
            # Get training data
            training_events = await self._get_training_data()
            
            if len(training_events) < self.min_training_samples:
                logger.warning(f"Not enough training data: {len(training_events)} < {self.min_training_samples}")
                return None
            
            # Train model
            metrics = ml_engine.train_model(training_events, retrain=True)
            self.last_training_time = datetime.now()
            
            logger.info(f"Model training completed successfully. Accuracy: {metrics.accuracy:.3f}")
            return metrics
            
        except Exception as e:
            logger.error(f"Auto training failed: {e}")
            return None
        finally:
            self.training_in_progress = False
    
    async def train_model_manual(self, organization_id: Optional[int] = None) -> ModelMetrics:
        """Manually trigger model training"""
        try:
            logger.info(f"Manual model training requested for org: {organization_id}")
            
            if self.training_in_progress:
                raise ValueError("Training already in progress")
            
            self.training_in_progress = True
            
            # Get training data
            training_events = await self._get_training_data(organization_id)
            
            if len(training_events) < 10:
                raise ValueError(f"Not enough training data: {len(training_events)}")
            
            # Train model
            metrics = ml_engine.train_model(training_events, retrain=True)
            self.last_training_time = datetime.now()
            
            logger.info(f"Manual training completed. Accuracy: {metrics.accuracy:.3f}")
            return metrics
            
        except Exception as e:
            logger.error(f"Manual training failed: {e}")
            raise
        finally:
            self.training_in_progress = False
    
    async def update_model_incremental(self, new_events: List[Dict]) -> bool:
        """Update model with new events incrementally"""
        try:
            if len(new_events) < 5:
                return False
            
            logger.info(f"Incremental model update with {len(new_events)} events")
            return ml_engine.update_model(new_events)
            
        except Exception as e:
            logger.error(f"Incremental update failed: {e}")
            return False
    
    async def evaluate_model_performance(self) -> Dict:
        """Evaluate current model performance on recent data"""
        try:
            # Get recent events for evaluation
            recent_events = await self._get_recent_events(limit=200)
            
            if len(recent_events) < 20:
                return {"error": "Not enough recent data for evaluation"}
            
            # Get predictions
            predictions = ml_engine.batch_predict(recent_events)
            
            # Calculate performance metrics
            performance = self._calculate_performance_metrics(recent_events, predictions)
            
            return performance
            
        except Exception as e:
            logger.error(f"Model evaluation failed: {e}")
            return {"error": str(e)}
    
    def get_training_status(self) -> Dict:
        """Get current training status"""
        return {
            "training_in_progress": self.training_in_progress,
            "last_training_time": self.last_training_time.isoformat() if self.last_training_time else None,
            "model_info": ml_engine.get_model_info(),
            "next_auto_training": self._get_next_training_time(),
            "min_training_samples": self.min_training_samples
        }
    
    async def _get_training_data(self, organization_id: Optional[int] = None) -> List[Dict]:
        """Get training data from database"""
        try:
            db = next(get_db())
            
            # Build query
            query = db.query(SecurityEvent)
            
            if organization_id:
                query = query.filter(SecurityEvent.organization_id == organization_id)
            
            # Get events from last 30 days
            thirty_days_ago = datetime.now() - timedelta(days=30)
            query = query.filter(SecurityEvent.timestamp >= thirty_days_ago)
            
            # Order by timestamp and limit
            events = query.order_by(SecurityEvent.timestamp.desc()).limit(1000).all()
            
            # Convert to dict format
            training_data = []
            for event in events:
                event_dict = {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "service": event.service_name,
                    "source_ip": event.source_ip,
                    "source_port": event.source_port,
                    "username": event.username,
                    "password": event.password,
                    "command": event.command,
                    "endpoint": event.endpoint,
                    "method": event.method,
                    "payload": event.payload,
                    "severity": event.severity,
                    "ai_label": event.ai_label,
                    "threat_score": event.threat_score,
                    "location": event.location,
                    "event_metadata": event.event_metadata
                }
                training_data.append(event_dict)
            
            logger.info(f"Retrieved {len(training_data)} events for training")
            return training_data
            
        except Exception as e:
            logger.error(f"Failed to get training data: {e}")
            return []
        finally:
            db.close()
    
    async def _get_recent_events(self, limit: int = 100) -> List[Dict]:
        """Get recent events for evaluation"""
        try:
            db = next(get_db())
            
            # Get recent events
            recent_time = datetime.now() - timedelta(hours=24)
            events = db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= recent_time
            ).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
            
            # Convert to dict format
            event_data = []
            for event in events:
                event_dict = {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                    "service": event.service_name,
                    "source_ip": event.source_ip,
                    "source_port": event.source_port,
                    "username": event.username,
                    "password": event.password,
                    "command": event.command,
                    "endpoint": event.endpoint,
                    "method": event.method,
                    "payload": event.payload,
                    "severity": event.severity,
                    "ai_label": event.ai_label,
                    "threat_score": event.threat_score,
                    "location": event.location,
                    "event_metadata": event.event_metadata
                }
                event_data.append(event_dict)
            
            return event_data
            
        except Exception as e:
            logger.error(f"Failed to get recent events: {e}")
            return []
        finally:
            db.close()
    
    def _should_retrain(self) -> bool:
        """Check if model should be retrained"""
        if self.last_training_time is None:
            return True
        
        time_since_training = datetime.now() - self.last_training_time
        return time_since_training.total_seconds() > (self.retrain_interval_hours * 3600)
    
    def _get_next_training_time(self) -> Optional[str]:
        """Get next scheduled training time"""
        if self.last_training_time is None:
            return "ASAP"
        
        next_training = self.last_training_time + timedelta(hours=self.retrain_interval_hours)
        return next_training.isoformat()
    
    def _calculate_performance_metrics(self, events: List[Dict], predictions: List) -> Dict:
        """Calculate performance metrics for recent predictions"""
        try:
            # Simple performance calculation
            total_events = len(events)
            high_confidence_predictions = sum(1 for p in predictions if p.confidence > 0.8)
            avg_confidence = sum(p.confidence for p in predictions) / len(predictions)
            
            # Threat level distribution
            threat_levels = {}
            for prediction in predictions:
                level = prediction.threat_level
                threat_levels[level] = threat_levels.get(level, 0) + 1
            
            # Anomaly detection stats
            anomaly_scores = [p.anomaly_score for p in predictions]
            avg_anomaly_score = sum(anomaly_scores) / len(anomaly_scores)
            
            return {
                "total_predictions": total_events,
                "high_confidence_predictions": high_confidence_predictions,
                "high_confidence_rate": high_confidence_predictions / total_events,
                "average_confidence": avg_confidence,
                "threat_level_distribution": threat_levels,
                "average_anomaly_score": avg_anomaly_score,
                "evaluation_time": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Performance calculation failed: {e}")
            return {"error": str(e)}

# Global training service instance
ml_training_service = MLTrainingService()

# Background training task
async def background_training_task():
    """Background task for automatic model training"""
    while True:
        try:
            await asyncio.sleep(3600)  # Check every hour
            await ml_training_service.auto_train_model()
        except Exception as e:
            logger.error(f"Background training task error: {e}")

# Start background task
def start_background_training():
    """Start background training task"""
    try:
        asyncio.create_task(background_training_task())
        logger.info("Background ML training task started")
    except Exception as e:
        logger.error(f"Failed to start background training: {e}")
