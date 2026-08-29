from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "mysql+pymysql://root@127.0.0.1:3306/members"
    secret_key: str = "dev-insecure-change-me"
    app_env: str = "development"
    debug: bool = True
    public_base_url: str = "http://127.0.0.1:8000"
    session_hours: int = 12
    access_token_minutes: int = 15
    refresh_token_days: int = 30
    cookie_name: str = "members_session"
    cookie_secure: bool = False
    seed_demo: bool = True
    demo_email: str = "member@workers.club"
    demo_password: str = "MembersOnly!2026"
    jwt_private_key_pem: str | None = None
    oauth_first_party_client_id: str = "workers-club"
    google_client_id: str | None = None
    google_client_secret: str | None = None
    github_client_id: str | None = None
    github_client_secret: str | None = None


@lru_cache
def get_settings() -> Settings:
    return Settings()


def clear_settings_cache() -> None:
    get_settings.cache_clear()
