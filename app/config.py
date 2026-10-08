"""Runtime configuration.

All secrets come from environment variables (Kubernetes Secret / GitHub Actions
secret / local .env). Nothing secret is hard-coded in the repository.
"""
import os
import secrets


class Settings:
    def __init__(self) -> None:
        self.env = os.getenv("APP_ENV", "dev")
        self.db_path = os.getenv("DB_PATH", "/tmp/wallet.db")  # nosec B108 - dev default, overridden in container
        self.jwt_secret = os.getenv("JWT_SECRET", "")
        self.hmac_secret = os.getenv("HMAC_SECRET", "")
        self.jwt_ttl_seconds = int(os.getenv("JWT_TTL_SECONDS", "900"))
        self.replay_window_seconds = int(os.getenv("REPLAY_WINDOW_SECONDS", "300"))
        self.max_failed_logins = int(os.getenv("MAX_FAILED_LOGINS", "5"))
        self.lockout_seconds = int(os.getenv("LOCKOUT_SECONDS", "300"))

        if not self.jwt_secret or not self.hmac_secret:
            if self.env == "prod":
                # Fail closed: production must receive secrets from the platform.
                raise RuntimeError("JWT_SECRET and HMAC_SECRET must be set in production")
            # Dev/test only: random per-process secrets, never a fixed literal.
            self.jwt_secret = self.jwt_secret or secrets.token_urlsafe(48)
            self.hmac_secret = self.hmac_secret or secrets.token_urlsafe(48)


settings = Settings()
