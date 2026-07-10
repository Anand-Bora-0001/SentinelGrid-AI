"""
SentinelGrid AI — Configuration Management
AI-Powered Cyber Resilience Platform for Critical National Infrastructure

Handles environment variables and application settings.
"""
import os
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import validator
import logging


class Settings(BaseSettings):
    """Application settings with environment variable support"""

    # Application
    app_name: str = "SentinelGrid AI"
    app_version: str = "1.0.0"
    app_tagline: str = "Detect. Predict. Contain. Recover."
    debug: bool = False
    log_level: str = "INFO"
    timezone: str = "UTC"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False

    # Database
    database_url: str = "sqlite:///./sentinelgrid.db"

    # Security
    jwt_secret_key: str = "your-super-secret-jwt-key-change-this-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480  # 8-hour SOC shift

    # Telegram Notifications
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    # Email/SMTP
    smtp_server: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: str = "alerts@sentinelgrid.ai"
    smtp_from_name: str = "SentinelGrid AI"
    smtp_use_tls: bool = True

    # Rate Limiting
    rate_limit_per_minute: int = 100
    max_events_per_hour: int = 5000

    # Alerts
    alert_cooldown_minutes: int = 5
    max_alerts_per_hour: int = 50

    # File Storage
    reports_dir: str = "reports"
    logs_dir: str = "logs"
    upload_max_size: int = 10485760  # 10MB

    # AI/ML Configuration
    anomaly_contamination: float = 0.1       # Isolation Forest contamination factor
    anomaly_threshold: float = 0.7           # Risk score threshold for anomaly flag
    svm_nu: float = 0.1                      # One-Class SVM nu parameter
    ml_model_dir: str = "models"
    ml_retrain_interval_hours: int = 6

    # ChromaDB (Vector Store for RAG)
    chromadb_path: str = "./data/chromadb"
    embedding_model: str = "all-MiniLM-L6-v2"
    rag_collection_name: str = "threat_intelligence"
    rag_top_k: int = 5

    # MITRE ATT&CK
    mitre_data_path: str = "app/data/mitre_attack_enterprise.json"

    # External APIs (optional — ₹0 budget, all optional)
    ipapi_key: Optional[str] = None
    abuseipdb_key: Optional[str] = None
    nvd_api_key: Optional[str] = None

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f'Log level must be one of: {valid_levels}')
        return v.upper()

    @validator('jwt_secret_key')
    def validate_jwt_secret(cls, v):
        if len(v) < 32:
            raise ValueError('JWT secret key must be at least 32 characters long')
        return v

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import json

        # Parse SMTP_CONFIG if present in environment
        smtp_config_str = os.environ.get("SMTP_CONFIG")
        if smtp_config_str:
            try:
                smtp_config = json.loads(smtp_config_str)
                if isinstance(smtp_config, dict):
                    if "smtp_server" in smtp_config:
                        self.smtp_server = smtp_config["smtp_server"]
                    if "smtp_port" in smtp_config:
                        self.smtp_port = int(smtp_config["smtp_port"])
                    if "smtp_username" in smtp_config:
                        self.smtp_username = smtp_config["smtp_username"]
                    if "smtp_password" in smtp_config:
                        self.smtp_password = smtp_config["smtp_password"]
                    if "smtp_from_email" in smtp_config:
                        self.smtp_from_email = smtp_config["smtp_from_email"]
                    if "smtp_from_name" in smtp_config:
                        self.smtp_from_name = smtp_config["smtp_from_name"]
                    if "smtp_use_tls" in smtp_config:
                        val = smtp_config["smtp_use_tls"]
                        self.smtp_use_tls = val if isinstance(val, bool) else str(val).lower() in ("true", "1", "yes")
            except Exception as e:
                logging.getLogger("SentinelGrid").warning(f"Failed to parse SMTP_CONFIG JSON: {e}")

        # Parse TELEGRAM_CONFIG if present in environment
        telegram_config_str = os.environ.get("TELEGRAM_CONFIG")
        if telegram_config_str:
            try:
                telegram_config = json.loads(telegram_config_str)
                if isinstance(telegram_config, dict):
                    if "telegram_bot_token" in telegram_config:
                        self.telegram_bot_token = telegram_config["telegram_bot_token"]
                    if "telegram_chat_id" in telegram_config:
                        self.telegram_chat_id = telegram_config["telegram_chat_id"]
            except Exception as e:
                logging.getLogger("SentinelGrid").warning(f"Failed to parse TELEGRAM_CONFIG JSON: {e}")

    @property
    def is_telegram_configured(self) -> bool:
        """Check if Telegram is properly configured"""
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @property
    def is_email_configured(self) -> bool:
        """Check if email is properly configured"""
        return bool(self.smtp_server and self.smtp_username and self.smtp_password)

    def setup_directories(self):
        """Create necessary directories"""
        for d in [self.reports_dir, self.logs_dir, self.ml_model_dir, self.chromadb_path, os.path.dirname(self.mitre_data_path) or "app/data"]:
            try:
                os.makedirs(d, exist_ok=True)
            except Exception as e:
                print(f"Warning: Could not create directory {d}: {e}")

    def setup_logging(self):
        """Configure application logging"""
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        # Fix Windows console encoding for emoji/Unicode characters
        import sys
        import io

        # Force UTF-8 on Windows stdout/stderr so all handlers work
        if sys.platform == 'win32':
            os.environ['PYTHONIOENCODING'] = 'utf-8'
            try:
                sys.stdout.reconfigure(encoding='utf-8', errors='replace')
                sys.stderr.reconfigure(encoding='utf-8', errors='replace')
            except Exception:
                # Fallback: wrap the buffer streams
                sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
                sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setFormatter(logging.Formatter(log_format))

        handlers = [console_handler]

        # File handler with rotation (UTF-8 encoding for log files)
        from logging.handlers import RotatingFileHandler
        try:
            file_handler = RotatingFileHandler(
                f"{self.logs_dir}/sentinelgrid.log",
                maxBytes=10485760,  # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(file_handler)
        except Exception as e:
            print(f"Warning: Could not set up file logging: {e}. Falling back to console logging only.")

        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, self.log_level),
            handlers=handlers,
            format=log_format
        )

        # Reduce noise from external libraries
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
        logging.getLogger("chromadb").setLevel(logging.WARNING)
        logging.getLogger("sentence_transformers").setLevel(logging.WARNING)

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"


# Global settings instance
settings = Settings()

# Setup on import
settings.setup_directories()
settings.setup_logging()

# Export commonly used values
DATABASE_URL = settings.database_url
JWT_SECRET_KEY = settings.jwt_secret_key
JWT_ALGORITHM = settings.jwt_algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = settings.jwt_expire_minutes
