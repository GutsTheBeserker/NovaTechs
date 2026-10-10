"""Application configuration module with safe defaults and environment variable support."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file from backend directory if present
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base application configuration with safe production-ready defaults."""

    ENV: str = os.getenv("FLASK_ENV", "production")
    DEBUG: bool = os.getenv("FLASK_DEBUG", "false").lower() in ("true", "1", "t")
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "5000"))
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY", "phishguard-default-safe-secret-key-entropy-128"
    )

    # ML Model configuration paths (resolved relative to backend directory)
    MODEL_PATH: Path = BASE_DIR / os.getenv(
        "MODEL_PATH", "app/ml/models/phishing_model.joblib"
    )
    METADATA_PATH: Path = BASE_DIR / os.getenv(
        "METADATA_PATH", "app/ml/models/model_metadata.json"
    )

    # Security settings
    CORS_ALLOWED_ORIGINS: str = os.getenv("CORS_ALLOWED_ORIGINS", "*")
    MAX_CONTENT_LENGTH: int = 16 * 1024  # Max 16KB payload - strict privacy safeguard


class DevelopmentConfig(Config):
    """Development environment specific configuration."""

    DEBUG: bool = True
    ENV: str = "development"


class TestingConfig(Config):
    """Test environment specific configuration."""

    TESTING: bool = True
    DEBUG: bool = False
    ENV: str = "testing"


def get_config() -> type[Config]:
    """Retrieve configuration class based on environment variable."""
    env = os.getenv("FLASK_ENV", "development").lower()
    if env == "testing":
        return TestingConfig
    elif env == "development":
        return DevelopmentConfig
    return Config
