from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    database_url: str = Field(..., env="DATABASE_URL")
    secret_key: str = Field(..., env="SECRET_KEY")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    rate_limit_window_minutes: int = Field(default=15, env="RATE_LIMIT_WINDOW_MINUTES")
    max_failed_attempts: int = Field(default=5, env="MAX_FAILED_ATTEMPTS")
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")
    app_name: str = Field(default="CyberAuth", env="APP_NAME")
    debug: bool = Field(default=True, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()