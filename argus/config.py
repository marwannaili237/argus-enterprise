from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from functools import lru_cache
import os


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Argus OSINT"
    debug: bool = False
    api_port: int = int(os.getenv("PORT", 8000))
    argus_db_url: str = "sqlite+aiosqlite:///./argus.db"

    # Security: SESSION_SECRET must be provided in production
    secret_key: str = os.getenv("SESSION_SECRET", "")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24 * 7

    telegram_bot_token: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    telegram_bot_name: str = os.getenv("TELEGRAM_BOT_NAME", "ArgusOSINTBot")

    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")

    cors_origins: str = "*"
    max_concurrent_investigations: int = 5
    investigation_timeout_seconds: int = 120
    data_retention_days: int = 90

    # Monster Mode: concurrency + AI + intel tuning (low-end friendly)
    max_concurrent_plugins: int = int(os.getenv("MAX_CONCURRENT_PLUGINS", "5"))
    enable_entity_extraction: bool = os.getenv("ENABLE_ENTITY_EXTRACTION", "true").lower() == "true"
    enable_chain_of_custody: bool = os.getenv("ENABLE_CHAIN_OF_CUSTODY", "true").lower() == "true"
    
    # AI Analysis Mode: "disabled" (no AI), "ollama" (local only), "gemini" (cloud), "auto" (ollama first, fallback to gemini)
    ai_analysis_mode: str = os.getenv("AI_ANALYSIS_MODE", "auto")
    
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model: str = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
    enable_ollama: bool = os.getenv("ENABLE_OLLAMA", "false").lower() == "true"
    
    # Optional free API keys (all 100% free, no CC required)
    virustotal_api_key: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    urlscan_api_key: str = os.getenv("URLSCAN_API_KEY", "")
    censys_api_id: str = os.getenv("CENSYS_API_ID", "")
    censys_api_secret: str = os.getenv("CENSYS_API_SECRET", "")
    steam_api_key: str = os.getenv("STEAM_API_KEY", "")
    etherscan_api_key: str = os.getenv("ETHERSCAN_API_KEY", "")
    otx_api_key: str = os.getenv("OTX_API_KEY", "")  # optional, free

    # Bot & API configuration
    api_base_url: str = os.getenv("API_BASE_URL", "")  # Production API URL (e.g., https://api.example.com/api/v1)
    
    # SMTP (email notifications)
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    from_email: str = ""

    @field_validator("secret_key", mode="after")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Ensure SESSION_SECRET is set in production."""
        if not v:
            raise ValueError(
                "SESSION_SECRET environment variable must be set in production. "
                "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
            )
        if len(v) < 32:
            raise ValueError("SESSION_SECRET must be at least 32 characters long")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
