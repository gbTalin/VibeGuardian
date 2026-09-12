from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration kept independent of CyberGuard's future settings service."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="CG_")

    environment: str = "development"
    database_url: str = "sqlite:///./cyberguard_plugin.db"
    api_prefix: str = "/v1"
    cors_origins: str = "http://localhost:3000"
    exa_webhook_secret: SecretStr | None = None
    release_webhook_secret: SecretStr | None = None
    local_encryption_key: SecretStr | None = None
    redis_url: str = "redis://localhost:6379/0"


@lru_cache
def get_settings() -> Settings:
    return Settings()
