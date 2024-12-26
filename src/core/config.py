import warnings
import importlib.metadata
from pydantic_settings import BaseSettings, SettingsConfigDict

try:
    current_version = importlib.metadata.version("journal-api")
except Exception:
    current_version = "0.0.0"
warnings.filterwarnings("ignore", category=DeprecationWarning)


class Settings(BaseSettings):
    PROJECT_NAME: str = "Journal API"
    API_VERSION: str = current_version
    BASE_URL: str = "0.0.0.0"

    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", env_file_encoding="utf-8"
    )


settings = Settings()
