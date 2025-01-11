import os
import warnings
import requests
from typing import List
from pathlib import Path
import importlib.metadata
from functools import cached_property
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..middleware.logging import logger


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
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PRIVATE_KEY_FILE: str = "keys/private_key.pem"
    PUBLIC_KEY_FILE: str = "keys/public_key.pem"
    DEVELOPERS_EMAIL: List[str]

    def download_keys(self):
        """
        Downloads the keys from the supabase storage.
        """
        logger.info(f"Downloading keys from Supabase Storage...")
        try:
            public_key_file = self.PUBLIC_KEY_FILE
            private_key_file = self.PRIVATE_KEY_FILE

            if not os.path.isdir("keys"):
                os.makedirs("keys")

            headers = {
                "Authorization": f"Bearer {self.SUPABASE_KEY}",
            }
            public_key_response = requests.get(
                f"{self.SUPABASE_URL}/storage/v1/object/authenticated/{self.BUCKET_NAME}/{public_key_file}",
                headers=headers,
                stream=True,
            )

            with open(public_key_file, "wb") as file:
                for chunk in public_key_response.iter_content(chunk_size=8192):
                    file.write(chunk)

            logger.info(
                f"Public key downloaded successfully and saved as '{public_key_file}'"
            )

            private_key_response = requests.get(
                f"{self.SUPABASE_URL}/storage/v1/object/authenticated/{self.BUCKET_NAME}/{private_key_file}",
                headers=headers,
                stream=True,
            )

            with open(private_key_file, "wb") as file:
                for chunk in private_key_response.iter_content(chunk_size=8192):
                    file.write(chunk)

            logger.info(
                f"Private key downloaded successfully and saved as '{private_key_file}'"
            )
        except requests.exceptions.RequestException as e:
            logger.info(f"Error downloading key: {str(e)}")
            raise e

    @cached_property
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

    @cached_property
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
