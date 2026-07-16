"""
Celery worker configuration.
Falls back to synchronous execution when Celery/Redis is not available.
"""
import os
import logging

logger = logging.getLogger(__name__)

REDIS_URL = os.getenv("REDIS_URL", "")
CELERY_AVAILABLE = False
celery_app = None

try:
    if REDIS_URL:
        from celery import Celery

        celery_app = Celery(
            "sentinelgrid",
            broker=REDIS_URL,
            backend=REDIS_URL,
            include=[
                "app.tasks.report_tasks",
                "app.tasks.alert_tasks",
                "app.tasks.ml_tasks",
            ]
        )

        celery_app.conf.update(
            task_serializer="json",
            accept_content=["json"],
            result_serializer="json",
            timezone="UTC",
            enable_utc=True,
            task_track_started=True,
            task_time_limit=300,          # Hard limit: 5 min
            task_soft_time_limit=240,     # Soft limit: 4 min
            worker_max_tasks_per_child=100,
            worker_prefetch_multiplier=1,
            task_acks_late=True,
            broker_connection_retry_on_startup=True,
        )

        CELERY_AVAILABLE = True
        logger.info("🥬 Celery worker configured")
    else:
        logger.info("⚠️ No REDIS_URL — Celery disabled, using synchronous execution")

except ImportError:
    logger.info("⚠️ Celery not installed — using synchronous execution")
except Exception as e:
    logger.warning(f"⚠️ Celery init failed: {e}")
