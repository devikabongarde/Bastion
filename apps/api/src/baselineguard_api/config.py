from functools import lru_cache

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="BG_",
        env_file=".env",
        extra="ignore",
        frozen=True,
    )

    environment: str = "development"
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8000, ge=1, le=65535)
    database_url: str = "postgresql+psycopg://bg_api:development-only@127.0.0.1:5432/baselineguard"
    session_secret: SecretStr = SecretStr("development-only-change-this-session-key")
    log_level: str = "INFO"
    docs_enabled: bool = False
    cors_origins: tuple[str, ...] = ()
    evidence_root: str = "./data/evidence"
    master_key_file: str = "./data/keys/master.key"
    password_blocklist_file: str | None = None
    # Development convenience: run collector/evaluator loops inside the API process.
    # Workers claim jobs across organizations, so WORKER_DATABASE_URL must name a role
    # that is allowed to do so (never the restricted API role in production).
    embedded_workers: bool = False
    worker_database_url: str | None = None
    # Demo convenience: allow password-only sign-in (MFA skipped) for live presentations.
    # Never permitted in production; every use is written to the audit log.
    demo_login: bool = False
    # Live SSH collection: pinned host keys are written here and enforced by the collector.
    known_hosts_file: str = "./data/known_hosts"
    # Lab convenience: allow loopback targets such as the bundled mock device on
    # 127.0.0.1:2222. Loopback is otherwise refused (SSRF guard). Never in production.
    lab_targets: bool = False

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        allowed = {"development", "test", "production"}
        if value not in allowed:
            raise ValueError("BG_ENVIRONMENT must be development, test, or production")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("BG_LOG_LEVEL is not a supported logging level")
        return normalized

    @model_validator(mode="after")
    def validate_deployment_security(self) -> "Settings":
        if self.environment == "production":
            if len(self.session_secret.get_secret_value()) < 32:
                raise ValueError("Production session secret must contain at least 32 characters")
            if self.session_secret.get_secret_value().startswith("development-only"):
                raise ValueError("Production session secret must be provisioned explicitly")
            if self.docs_enabled:
                raise ValueError("Interactive API documentation must be disabled in production")
            if self.cors_origins:
                raise ValueError(
                    "Cross-origin browser access is disabled; use the same-origin reverse proxy"
                )
            if self.demo_login:
                raise ValueError("Demo sign-in (BG_DEMO_LOGIN) must be disabled in production")
            if self.lab_targets:
                raise ValueError("Lab loopback targets (BG_LAB_TARGETS) must be disabled in production")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
