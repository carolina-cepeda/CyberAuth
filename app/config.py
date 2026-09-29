from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    # Database
    database_url: str = Field(..., env="DATABASE_URL")

    # Security - JWT
    secret_key: str = Field(..., env="SECRET_KEY")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    max_session_lifetime_hours: int = Field(default=8, env="MAX_SESSION_LIFETIME_HOURS")
    jwt_issuer: str = Field(default="CyberAuth", env="JWT_ISSUER")
    jwt_audience: str = Field(default="cyberauth-api", env="JWT_AUDIENCE")

    # Account Lockout (separate from IP rate limit)
    max_failed_attempts: int = Field(default=5, env="MAX_FAILED_ATTEMPTS")
    account_lock_window_minutes: int = Field(default=15, env="ACCOUNT_LOCK_WINDOW_MINUTES")

    # IP Rate Limiting
    ip_rate_limit_max: int = Field(default=100, env="IP_RATE_LIMIT_MAX")
    ip_rate_limit_window_minutes: int = Field(default=15, env="IP_RATE_LIMIT_WINDOW_MINUTES")

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")

    # CORS & HTTPS
    allowed_origins: str = Field(default="*", env="ALLOWED_ORIGINS")
    trusted_proxy_ips: str = Field(default="", env="TRUSTED_PROXY_IPS")

    # Privacy Policy
    policy_version: str = Field(default="1.0", env="POLICY_VERSION")

    # App
    app_name: str = Field(default="CyberAuth", env="APP_NAME")
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="INFO", env="LOG_LEVEL")

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long")
        return v

    @field_validator("allowed_origins")
    @classmethod
    def parse_allowed_origins(cls, v: str) -> list[str]:
        if v == "*":
            return ["*"]
        return [origin.strip() for origin in v.split(",") if origin.strip()]

    @field_validator("trusted_proxy_ips")
    @classmethod
    def parse_trusted_proxy_ips(cls, v: str) -> list[str]:
        if not v:
            return []
        return [ip.strip() for ip in v.split(",") if ip.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()