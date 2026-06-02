"""
session_manager.py — Secure Session Token Lifecycle
Handles creation, validation, expiry, and revocation of stream tokens.
"""

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional
from config import MAX_SESSIONS, SESSION_TTL, TOKEN_BYTES

CLEANUP_INTERVAL = 300        # run GC every 5 minutes


@dataclass
class Session:
    token: str
    ip: str
    username: str
    created_at: float = field(default_factory=time.time)
    last_seen: float  = field(default_factory=time.time)
    revoked: bool     = False

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > SESSION_TTL

    def is_valid(self) -> bool:
        return not self.revoked and not self.is_expired()

    def touch(self) -> None:
        self.last_seen = time.time()

    def to_dict(self) -> dict:
        return {
            "token_prefix": self.token[:8] + "...",
            "ip": self.ip,
            "username": self.username,
            "age_seconds": int(time.time() - self.created_at),
            "revoked": self.revoked,
            "expired": self.is_expired(),
        }


class SessionManager:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._start_cleanup_thread()

    # ── Public API ─────────────────────────────────────────────────────────────

    def create_session(self, ip: str, username: str) -> Optional[str]:
        """
        Mint a new session token.
        Returns the token string, or None if the session cap is reached.
        """
        with self._lock:
            self._gc()
            if len(self._sessions) >= MAX_SESSIONS:
                return None
            token = secrets.token_hex(TOKEN_BYTES)
            self._sessions[token] = Session(token=token, ip=ip, username=username)
            return token

    def validate(self, token: str, ip: str | None = None) -> bool:
        """
        Return True if the token is known, unexpired, unrevoked, and (if
        ip is supplied) originated from the same address.
        """
        with self._lock:
            session = None
            for stored_token, candidate in self._sessions.items():
                if secrets.compare_digest(stored_token, token or ""):
                    session = candidate
                    break
            if session is None or not session.is_valid():
                return False
            if ip and session.ip != ip:
                # Token hijack attempt — revoke immediately
                session.revoked = True
                return False
            session.touch()
            return True

    def revoke(self, token: str) -> None:
        with self._lock:
            if token in self._sessions:
                self._sessions[token].revoked = True

    def revoke_all_for_ip(self, ip: str) -> int:
        """Revoke all sessions belonging to an IP. Returns count revoked."""
        with self._lock:
            count = 0
            for s in self._sessions.values():
                if s.ip == ip and not s.revoked:
                    s.revoked = True
                    count += 1
            return count

    def active_sessions(self) -> list[dict]:
        with self._lock:
            return [
                s.to_dict()
                for s in self._sessions.values()
                if s.is_valid()
            ]

    # ── Internal ───────────────────────────────────────────────────────────────

    def _gc(self) -> None:
        """Remove expired/revoked sessions (must be called with lock held)."""
        dead = [t for t, s in self._sessions.items() if not s.is_valid()]
        for t in dead:
            del self._sessions[t]

    def _cleanup_loop(self) -> None:
        while True:
            time.sleep(CLEANUP_INTERVAL)
            with self._lock:
                self._gc()

    def _start_cleanup_thread(self) -> None:
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()


# Singleton — import this everywhere
session_manager = SessionManager()
