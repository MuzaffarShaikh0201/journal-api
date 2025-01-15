import warnings
from typing import List
import importlib.metadata
from pydantic_settings import BaseSettings, SettingsConfigDict


# Get the current version of the project from the package metadata
try:
    current_version = importlib.metadata.version("journal-api")
except Exception:
    current_version = "0.0.0"

# Configure Pydantic settings
warnings.filterwarnings("ignore", category=DeprecationWarning)


class Settings(BaseSettings):
    PROJECT_NAME: str = "Journal API"
    API_VERSION: str = current_version
    BASE_URL: str = "0.0.0.0"
    DATABASE_URL: str
    REDIS_URL: str
    SUPABASE_URL: str
    SUPABASE_KEY: str
    BUCKET_NAME: str
    JWT_ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PRIVATE_KEY_FILE: str
    PUBLIC_KEY_FILE: str
    PRIVATE_KEY: str
    PUBLIC_KEY: str
    DEVELOPERS_EMAIL: List[str]

    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", env_file_encoding="utf-8"
    )


settings = Settings()
