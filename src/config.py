"""Configuration management for OpenShift AI Security Dashboard."""

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration."""
    
    # Application settings
    APP_NAME = "OpenShift AI Security Dashboard"
    VERSION = "1.0.0"
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    
    # Database settings
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///openshift_ai_security.db")
    
    # API settings
    PYXIS_BASE_URL = os.getenv(
        "PYXIS_BASE_URL", 
        "https://catalog.redhat.com/api/containers/v1/"
    )
    SECURITY_DATA_BASE_URL = os.getenv(
        "SECURITY_DATA_BASE_URL",
        "https://access.redhat.com/hydra/rest/securitydata"
    )
    
    # API request settings
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "30"))
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
    RETRY_BACKOFF_FACTOR = float(os.getenv("RETRY_BACKOFF_FACTOR", "0.5"))
    
    # Cache settings
    CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))  # 1 hour
    ENABLE_CACHING = os.getenv("ENABLE_CACHING", "true").lower() == "true"
    
    # UI settings
    STREAMLIT_SERVER_PORT = int(os.getenv("STREAMLIT_SERVER_PORT", "8501"))
    STREAMLIT_SERVER_ADDRESS = os.getenv("STREAMLIT_SERVER_ADDRESS", "0.0.0.0")
    PAGE_TITLE = "OpenShift AI Security Overview"
    PAGE_ICON = "🛡️"
    LAYOUT = "wide"
    
    # Data processing settings
    MAX_CONCURRENT_REQUESTS = int(os.getenv("MAX_CONCURRENT_REQUESTS", "10"))
    BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
    CVE_PAGINATION_SIZE = int(os.getenv("CVE_PAGINATION_SIZE", "25"))
    MAX_IMAGES_PER_RELEASE = int(os.getenv("MAX_IMAGES_PER_RELEASE", "500"))
    MAX_CVES_TOTAL = int(os.getenv("MAX_CVES_TOTAL", "10000"))
    
    # Export settings
    EXPORT_DIR = Path(os.getenv("EXPORT_DIR", "./exports"))
    MAX_EXPORT_SIZE_MB = int(os.getenv("MAX_EXPORT_SIZE_MB", "100"))
    
    # Logging settings
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
    LOG_FORMAT = os.getenv(
        "LOG_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    ENABLE_STRUCTURED_LOGGING = os.getenv("ENABLE_STRUCTURED_LOGGING", "false").lower() == "true"
    
    # Performance settings
    ENABLE_ASYNC_PROCESSING = os.getenv("ENABLE_ASYNC_PROCESSING", "true").lower() == "true"
    WORKER_THREAD_COUNT = int(os.getenv("WORKER_THREAD_COUNT", "4"))
    
    # API availability settings
    OFFLINE_MODE = os.getenv("OFFLINE_MODE", "false").lower() == "true"
    USE_MOCK_DATA = os.getenv("USE_MOCK_DATA", "auto").lower()  # auto, true, false
    
    # Security settings
    ALLOWED_EXPORT_FORMATS = ["pdf", "csv", "json"]
    MAX_FILENAME_LENGTH = 255
    SANITIZE_FILENAMES = True
    
    @classmethod
    def get_pyxis_headers(cls) -> dict:
        """Get headers for Pyxis API requests."""
        headers = {
            "User-Agent": f"{cls.APP_NAME}/{cls.VERSION}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        
        # Add authentication if available
        api_key = os.getenv("PYXIS_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        return headers
    
    @classmethod
    def get_security_data_headers(cls) -> dict:
        """Get headers for Security Data API requests."""
        headers = {
            "User-Agent": f"{cls.APP_NAME}/{cls.VERSION}",
            "Accept": "application/json",
        }
        
        # Add authentication if available
        api_key = os.getenv("SECURITY_DATA_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        return headers
    
    @classmethod
    def validate_config(cls) -> list:
        """Validate configuration and return any errors."""
        errors = []
        
        # Validate URLs
        if not cls.PYXIS_BASE_URL.startswith(("http://", "https://")):
            errors.append("PYXIS_BASE_URL must be a valid HTTP/HTTPS URL")
        
        if not cls.SECURITY_DATA_BASE_URL.startswith(("http://", "https://")):
            errors.append("SECURITY_DATA_BASE_URL must be a valid HTTP/HTTPS URL")
        
        # Validate numeric settings
        if cls.REQUEST_TIMEOUT <= 0:
            errors.append("REQUEST_TIMEOUT must be positive")
        
        if cls.MAX_RETRIES < 0:
            errors.append("MAX_RETRIES must be non-negative")
        
        if cls.CACHE_TTL <= 0:
            errors.append("CACHE_TTL must be positive")
        
        if cls.CVE_PAGINATION_SIZE <= 0:
            errors.append("CVE_PAGINATION_SIZE must be positive")
        
        # Validate export directory
        try:
            cls.EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create export directory: {e}")
        
        return errors
    
    @classmethod
    def get_database_config(cls) -> dict:
        """Get database configuration."""
        return {
            "url": cls.DATABASE_URL,
            "echo": cls.DEBUG,
            "pool_pre_ping": True,
            "pool_recycle": 300,
        }
    
    @classmethod
    def get_streamlit_config(cls) -> dict:
        """Get Streamlit configuration."""
        return {
            "page_title": cls.PAGE_TITLE,
            "page_icon": cls.PAGE_ICON,
            "layout": cls.LAYOUT,
            "initial_sidebar_state": "expanded",
        }


class DevelopmentConfig(Config):
    """Development-specific configuration."""
    
    DEBUG = True
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///dev_openshift_ai_security.db")
    CACHE_TTL = 60  # 1 minute for faster development
    LOG_LEVEL = "DEBUG"


class TestConfig(Config):
    """Test-specific configuration."""
    
    DEBUG = True
    DATABASE_URL = "sqlite:///:memory:"
    ENABLE_CACHING = False
    REQUEST_TIMEOUT = 5
    MAX_RETRIES = 1
    LOG_LEVEL = "WARNING"


class ProductionConfig(Config):
    """Production-specific configuration."""
    
    DEBUG = False
    CACHE_TTL = 3600  # 1 hour
    LOG_LEVEL = "INFO"
    ENABLE_STRUCTURED_LOGGING = True


def get_config(env: Optional[str] = None) -> Config:
    """Get configuration based on environment."""
    if env is None:
        env = os.getenv("ENVIRONMENT", "development").lower()
    
    config_map = {
        "development": DevelopmentConfig,
        "dev": DevelopmentConfig,
        "testing": TestConfig,
        "test": TestConfig,
        "production": ProductionConfig,
        "prod": ProductionConfig,
    }
    
    config_class = config_map.get(env, DevelopmentConfig)
    return config_class()


# Global configuration instance
config = get_config()