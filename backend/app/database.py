"""
Production-grade database configuration.
Supports SQLite (dev), PostgreSQL (production via Neon), and connection pooling.
"""
import os
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import QueuePool, StaticPool
import logging

logger = logging.getLogger(__name__)

# ========================
# DATABASE URL RESOLUTION
# ========================

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sentinelgrid.db")

# Fix Heroku/Render postgres:// → postgresql://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# ========================
# ENGINE CREATION
# ========================

_is_sqlite = DATABASE_URL.startswith("sqlite")

if _is_sqlite:
    # SQLite: local development
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True,
        echo=False,
    )
    # Enable WAL mode for better concurrent read performance
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

else:
    # PostgreSQL (Neon / Supabase / self-hosted): production
    engine = create_engine(
        DATABASE_URL,
        poolclass=QueuePool,
        pool_size=5,               # Base connections
        max_overflow=10,            # Burst connections
        pool_pre_ping=True,         # Validate connections before use
        pool_recycle=300,           # Recycle connections every 5 min
        pool_timeout=30,            # Wait 30s for a connection
        echo=False,
        # Neon serverless-friendly: shorter idle timeout
        connect_args={
            "options": "-c statement_timeout=30000"  # 30s query timeout
        } if "neon" in DATABASE_URL else {},
    )
    logger.info(f" PostgreSQL engine configured (pool_size=5, max_overflow=10)")

# ========================
# SESSION & BASE
# ========================

Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency: yields a database session and closes it after use"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all database tables (safe for both SQLite and PostgreSQL)"""
    logger.info("Creating database tables...")
    try:
        from . import models  # noqa: F401 — registers all models with Base
        Base.metadata.create_all(bind=engine)
        logger.info(" Database tables created successfully")
    except Exception as e:
        logger.error(f" Failed to create database tables: {e}")
        raise


def get_engine_info() -> dict:
    """Return engine info for health checks"""
    return {
        "backend": "sqlite" if _is_sqlite else "postgresql",
        "url_masked": DATABASE_URL[:20] + "..." if len(DATABASE_URL) > 20 else DATABASE_URL,
        "pool_size": getattr(engine.pool, "size", lambda: "N/A")() if hasattr(engine.pool, "size") else "N/A",
    }
