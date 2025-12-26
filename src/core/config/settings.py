"""
Application configuration settings
"""
import os
from pathlib import Path
from typing import Optional

try:
    from pydantic import BaseSettings
except ImportError:
    # Fallback for older pydantic versions
    from pydantic import BaseModel as BaseSettings


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Behavioral Anomaly Detection Agent"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Database
    DATABASE_URL: str = "postgresql://user:password@localhost:5432/anomaly_db"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # ML Models
    MODEL_PATH: str = "models"
    RETRAIN_INTERVAL_HOURS: int = 24
    
    # Anomaly Detection
    ANOMALY_THRESHOLD: float = 0.7
    MIN_SAMPLES_FOR_TRAINING: int = 1000
    
    # API
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    
    class Config:
        env_file = ".env"


settings = Settings()
