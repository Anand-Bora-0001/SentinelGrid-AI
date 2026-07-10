"""
Background task: ML model training and batch prediction.
"""
import logging

logger = logging.getLogger(__name__)

# Celery fallback - runs tasks synchronously
def _task(func=None, **kwargs):
    if func is None:
        return lambda f: f
    return func

CELERY_AVAILABLE = False


@_task(name="train_model_async", bind=True, max_retries=1)
def train_model_async(self, organization_id: int = None):
    """Train ML model in background"""
    try:
        from ..ml_trainer import ml_training_service
        if not ml_training_service:
            return {"status": "skipped", "reason": "ml_service_not_available"}

        import asyncio
        loop = asyncio.new_event_loop()
        metrics = loop.run_until_complete(ml_training_service.train_model_manual(organization_id))
        loop.close()

        logger.info(f"✅ Background ML training complete (accuracy: {metrics.accuracy:.3f})")
        return {
            "status": "success",
            "accuracy": metrics.accuracy,
            "f1_score": metrics.f1_score,
        }

    except Exception as e:
        logger.error(f"❌ Background ML training failed: {e}")
        if hasattr(self, 'retry'):
            raise self.retry(exc=e, countdown=60)
        return {"status": "error", "error": str(e)}


@_task(name="batch_predict_async")
def batch_predict_async(events: list):
    """Run ML predictions on a batch of events"""
    try:
        from ..ml_engine import ml_engine
        if not ml_engine:
            return {"status": "skipped", "reason": "ml_engine_not_available"}

        results = []
        for event in events:
            try:
                prediction = ml_engine.predict_threat(event)
                results.append({
                    "source_ip": event.get("source_ip"),
                    "threat_level": prediction.threat_level,
                    "confidence": prediction.confidence,
                })
            except Exception:
                continue

        return {"status": "success", "predictions": len(results), "results": results}

    except Exception as e:
        logger.error(f"❌ Batch prediction failed: {e}")
        return {"status": "error", "error": str(e)}
