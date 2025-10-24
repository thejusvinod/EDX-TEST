import os
from datetime import timedelta


class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-change-me")
    SESSION_SECRET: str = os.getenv("SESSION_SECRET", "session-secret-change-me")
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data.db")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
    REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
    TOKEN_ISSUER: str = os.getenv("TOKEN_ISSUER", "auth-service")
    ALLOWED_CORS_ORIGINS: str = os.getenv("ALLOWED_CORS_ORIGINS", "*")

    # Open edX SSO settings
    OPENEDX_ENABLED: bool = os.getenv("OPENEDX_ENABLED", "false").lower() == "true"
    OPENEDX_BASE_URL: str = os.getenv("OPENEDX_BASE_URL", "")
    OPENEDX_AUTH_URL: str = os.getenv("OPENEDX_AUTH_URL", "")
    OPENEDX_TOKEN_URL: str = os.getenv("OPENEDX_TOKEN_URL", "")
    OPENEDX_USERINFO_URL: str = os.getenv("OPENEDX_USERINFO_URL", "")
    OPENEDX_CLIENT_ID: str = os.getenv("OPENEDX_CLIENT_ID", "")
    OPENEDX_CLIENT_SECRET: str = os.getenv("OPENEDX_CLIENT_SECRET", "")
    OPENEDX_REDIRECT_URI: str = os.getenv("OPENEDX_REDIRECT_URI", "")
    OPENEDX_SCOPES: str = os.getenv("OPENEDX_SCOPES", "openid profile email")

    @property
    def access_token_expires(self) -> timedelta:
        return timedelta(minutes=self.ACCESS_TOKEN_EXPIRE_MINUTES)

    @property
    def refresh_token_expires(self) -> timedelta:
        return timedelta(days=self.REFRESH_TOKEN_EXPIRE_DAYS)

    @property
    def openedx_authorize_url(self) -> str:
        if self.OPENEDX_AUTH_URL:
            return self.OPENEDX_AUTH_URL
        if self.OPENEDX_BASE_URL:
            return f"{self.OPENEDX_BASE_URL.rstrip('/')}/oauth2/authorize"
        return ""

    @property
    def openedx_token_url(self) -> str:
        if self.OPENEDX_TOKEN_URL:
            return self.OPENEDX_TOKEN_URL
        if self.OPENEDX_BASE_URL:
            # Open edX commonly uses /oauth2/access_token
            return f"{self.OPENEDX_BASE_URL.rstrip('/')}/oauth2/access_token"
        return ""

    @property
    def openedx_userinfo_url(self) -> str:
        if self.OPENEDX_USERINFO_URL:
            return self.OPENEDX_USERINFO_URL
        if self.OPENEDX_BASE_URL:
            # Some distributions expose /oauth2/user_info
            return f"{self.OPENEDX_BASE_URL.rstrip('/')}/oauth2/user_info"
        return ""


settings = Settings()
