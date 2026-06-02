"""Centralized DCOL configuration.

Production values should come from environment variables. Do not commit camera
URLs, stream keys, or plaintext passwords.
"""

import os


def _bool_env(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _csv_env(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if not value:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


# Camera. Use DCOL_CAMERA_SOURCE for an RTSP/HTTP/MJPEG URL, or leave as 0 for
# the first local webcam.
CAMERA_SOURCE = os.getenv("DCOL_CAMERA_SOURCE", "0")
CAMERA_BACKEND = os.getenv("DCOL_CAMERA_BACKEND", "CAP_DSHOW")
JPEG_QUALITY = int(os.getenv("DCOL_JPEG_QUALITY", "70"))
FRAME_WIDTH = int(os.getenv("DCOL_FRAME_WIDTH", "640"))
FRAME_HEIGHT = int(os.getenv("DCOL_FRAME_HEIGHT", "480"))

# Server
HOST = os.getenv("DCOL_HOST", "0.0.0.0")
PORT = int(os.getenv("DCOL_PORT", "5001"))
DEBUG = _bool_env("DCOL_DEBUG", False)
USE_RELOADER = _bool_env("DCOL_USE_RELOADER", False)
SECRET_KEY = os.getenv("DCOL_SECRET_KEY")

# Database Configuration
# Render automatically injects DATABASE_URL when you attach a PostgreSQL instance
DATABASE_URL = os.getenv("DATABASE_URL")

# CORS is only needed if you host the frontend on a separate origin.
ALLOWED_ORIGINS = _csv_env(
    "DCOL_ALLOWED_ORIGINS",
    ["http://127.0.0.1:5001", "http://localhost:5001"],
)

# Credentials. Prefer DCOL_ADMIN_PASSWORD_HASH. DCOL_ADMIN_PASS is accepted for
# local setup but should not be used in production.
ADMIN_USERNAME = os.getenv("DCOL_ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = os.getenv("DCOL_ADMIN_PASSWORD_HASH", "")
ADMIN_PASSWORD = os.getenv("DCOL_ADMIN_PASS", "")

# Anti-brute-force and rate limiting
MAX_FAILED_ATTEMPTS = int(os.getenv("DCOL_MAX_FAILED_ATTEMPTS", "3"))
LOCKOUT_SECONDS = int(os.getenv("DCOL_LOCKOUT_SECONDS", "120"))
RATE_LIMIT_REQUESTS = int(os.getenv("DCOL_RATE_LIMIT_REQUESTS", "60"))
RATE_LIMIT_WINDOW = int(os.getenv("DCOL_RATE_LIMIT_WINDOW", "60"))
BURST_LIMIT = int(os.getenv("DCOL_BURST_LIMIT", "10"))
BLOCK_DURATION = int(os.getenv("DCOL_BLOCK_DURATION", "300"))

# Sessions
TOKEN_BYTES = int(os.getenv("DCOL_TOKEN_BYTES", "32"))
SESSION_TTL = int(os.getenv("DCOL_SESSION_TTL", "1800"))
MAX_SESSIONS = int(os.getenv("DCOL_MAX_SESSIONS", "25"))
SESSION_COOKIE_NAME = os.getenv("DCOL_SESSION_COOKIE_NAME", "dcol_session")
SESSION_COOKIE_SECURE = _bool_env("DCOL_SESSION_COOKIE_SECURE", True)
SESSION_BIND_IP = _bool_env("DCOL_SESSION_BIND_IP", False)

# Logging
LOG_DIR = os.getenv("DCOL_LOG_DIR", "logs")
LOG_MAX_BYTES = int(os.getenv("DCOL_LOG_MAX_BYTES", str(5 * 1024 * 1024)))
LOG_BACKUP_COUNT = int(os.getenv("DCOL_LOG_BACKUP_COUNT", "5"))
LOG_RING_SIZE = int(os.getenv("DCOL_LOG_RING_SIZE", "50"))
