from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # SQLite DB path (default: backend/soc.db)
    DATABASE_URL: str = "sqlite:///./soc.db"

    # CORS
    ALLOWED_ORIGINS: str = "*"  # change to your frontend URL in production

    # App
    APP_NAME: str = "AI SOC Analyst Copilot API"
    APP_VERSION: str = "1.0.0"


settings = Settings()
