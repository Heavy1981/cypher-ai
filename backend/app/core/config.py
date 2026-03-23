from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # App
    APP_NAME: str = "CYPHER AI"
    APP_ENV: str = "development"
    APP_SECRET_KEY: str
    APP_CORS_ORIGINS: List[str] = ["http://localhost:3000"]
    API_V1_PREFIX: str = "/api/v1"

    # Database
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 40

    # Redis
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = "redis://redis:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://redis:6379/2"

    # Auth
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # AI
    ANTHROPIC_API_KEY: str
    ANTHROPIC_MODEL: str = "claude-sonnet-4-20250514"
    AI_MAX_TOKENS: int = 4096
    AI_TEMPERATURE: float = 0.2

    # Enrichment
    VIRUSTOTAL_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # Notifications
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "cypher@yourdomain.com"
    SLACK_BOT_TOKEN: str = ""
    SLACK_DEFAULT_CHANNEL: str = "#security-incidents"
    PAGERDUTY_API_KEY: str = ""
    TEAMS_WEBHOOK_URL: str = ""

    # Ticketing
    JIRA_URL: str = ""
    JIRA_USER: str = ""
    JIRA_API_TOKEN: str = ""
    JIRA_DEFAULT_PROJECT: str = "SEC"
    SERVICENOW_URL: str = ""
    SERVICENOW_USER: str = ""
    SERVICENOW_PASSWORD: str = ""

    # Storage
    STORAGE_BACKEND: str = "local"
    STORAGE_LOCAL_PATH: str = "/app/uploads"
    S3_BUCKET: str = ""
    S3_REGION: str = "us-east-1"

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"
    SENTRY_DSN: str = ""

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 100

    @property
    def is_production(self) -> bool:
        return self.APP_ENV == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
