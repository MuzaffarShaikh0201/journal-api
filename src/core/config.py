import warnings
from typing import List
from pathlib import Path
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
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PRIVATE_KEY_FILE: str = "keys/private_key.pem"
    PUBLIC_KEY_FILE: str = "keys/public_key.pem"
    DEVELOPERS_EMAIL: List[str]

    @property
    def PRIVATE_KEY(self) -> str:
        """
        Reads and returns the private key from the file.
        """
        private_key_path = Path(self.PRIVATE_KEY_FILE)
        if not private_key_path.is_file():
            raise FileNotFoundError(
                f"Private key file not found: {self.PRIVATE_KEY_FILE}"
            )
        return private_key_path.read_text()

    @property
    def PUBLIC_KEY(self) -> str:
        """
        Reads and returns the public key from the file.
        """
        public_key_path = Path(self.PUBLIC_KEY_FILE)
        if not public_key_path.is_file():
            raise FileNotFoundError(
                f"Public key file not found: {self.PUBLIC_KEY_FILE}"
            )
        return public_key_path.read_text()

    model_config = SettingsConfigDict(
        env_file=".env", extra="ignore", env_file_encoding="utf-8"
    )


settings = Settings()
