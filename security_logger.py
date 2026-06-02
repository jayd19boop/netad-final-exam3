"""Structured security audit logging."""

import json
import logging
import os
import threading
from collections import deque
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional

from config import LOG_BACKUP_COUNT, LOG_DIR, LOG_MAX_BYTES, LOG_RING_SIZE

LOG_FILE = os.path.join(LOG_DIR, "security_audit.log")


class Event:
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    SQL_INJECTION = "SQL_INJECTION"
    XSS_ATTEMPT = "XSS_ATTEMPT"
    COMMAND_INJECTION = "CMD_INJECTION"
    BRUTE_FORCE = "BRUTE_FORCE"
    RATE_LIMIT = "RATE_LIMIT"
    TOKEN_INVALID = "TOKEN_INVALID"
    TOKEN_HIJACK = "TOKEN_HIJACK"
    IP_BLOCKED = "IP_BLOCKED"
    SESSION_REVOKED = "SESSION_REVOKED"
    STREAM_ACCESS = "STREAM_ACCESS"
    STREAM_DENIED = "STREAM_DENIED"


_THREAT_EVENTS = {
    Event.SQL_INJECTION,
    Event.XSS_ATTEMPT,
    Event.COMMAND_INJECTION,
    Event.BRUTE_FORCE,
    Event.TOKEN_HIJACK,
    Event.RATE_LIMIT,
    Event.IP_BLOCKED,
}


class SecurityLogger:
    def __init__(self) -> None:
        self._ring: deque[dict] = deque(maxlen=LOG_RING_SIZE)
        self._lock = threading.Lock()
        self._file_logger = self._setup_file_logger()

    def log(
        self,
        event_type: str,
        ip: str,
        username: Optional[str] = None,
        password_hint: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> dict:
        now = datetime.now(timezone.utc)
        entry = {
            "time": now.strftime("%H:%M:%S UTC"),
            "timestamp": now.isoformat(),
            "event": event_type,
            "ip": self._mask_ip(ip),
            "username": username or "",
            "is_threat": event_type in _THREAT_EVENTS,
            "status": self._human_status(event_type),
        }
        if extra:
            entry.update(extra)

        with self._lock:
            self._ring.appendleft(entry)

        self._file_logger.info(json.dumps(entry, separators=(",", ":")))
        return entry

    def recent(self, n: int = 8) -> list[dict]:
        with self._lock:
            return list(self._ring)[:n]

    def threats_only(self, n: int = 20) -> list[dict]:
        with self._lock:
            return [e for e in self._ring if e["is_threat"]][:n]

    @staticmethod
    def _mask_ip(ip: str) -> str:
        if not ip:
            return ""
        if ":" in ip:
            parts = ip.split(":")
            return ":".join(parts[:3]) + "::"
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["0"])
        return ip

    @staticmethod
    def _human_status(event_type: str) -> str:
        mapping = {
            Event.LOGIN_SUCCESS: "Authorized Access",
            Event.LOGIN_FAILURE: "Invalid Credentials",
            Event.SQL_INJECTION: "SQL Injection Detected",
            Event.XSS_ATTEMPT: "XSS Attempt Detected",
            Event.COMMAND_INJECTION: "Command Injection Detected",
            Event.BRUTE_FORCE: "Brute Force Lockout",
            Event.RATE_LIMIT: "Rate Limit Exceeded",
            Event.TOKEN_INVALID: "Invalid Stream Token",
            Event.TOKEN_HIJACK: "Token Reuse Blocked",
            Event.IP_BLOCKED: "IP Blocked",
            Event.SESSION_REVOKED: "Session Revoked",
            Event.STREAM_ACCESS: "Stream Accessed",
            Event.STREAM_DENIED: "Stream Access Denied",
        }
        return mapping.get(event_type, event_type)

    @staticmethod
    def _setup_file_logger() -> logging.Logger:
        os.makedirs(LOG_DIR, exist_ok=True)
        logger = logging.getLogger("dcol.security")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = RotatingFileHandler(
                LOG_FILE,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            logger.addHandler(handler)
        return logger


security_logger = SecurityLogger()
