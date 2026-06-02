"""
rate_limiter.py — Token Bucket Rate Limiter
Limits how many requests an IP can make per minute to prevent DDoS/flooding.
"""

import time
import threading
from collections import defaultdict
from config import (
    BLOCK_DURATION,
    BURST_LIMIT,
    LOCKOUT_SECONDS,
    MAX_FAILED_ATTEMPTS,
    RATE_LIMIT_REQUESTS,
    RATE_LIMIT_WINDOW,
)

_lock = threading.Lock()

_buckets: dict[str, dict] = defaultdict(lambda: {
    "tokens": RATE_LIMIT_REQUESTS,
    "last_refill": time.time(),
    "burst_count": 0,
    "burst_window_start": time.time(),
})

_blocked_ips: dict[str, float] = {}
_failed_logins: dict[str, dict] = defaultdict(lambda: {
    "count": 0,
    "window_start": time.time(),
})
FAILED_LOGIN_WINDOW = 300


def _refill(bucket: dict) -> None:
    now = time.time()
    elapsed = now - bucket["last_refill"]
    refill_amount = (elapsed / RATE_LIMIT_WINDOW) * RATE_LIMIT_REQUESTS
    bucket["tokens"] = min(RATE_LIMIT_REQUESTS, bucket["tokens"] + refill_amount)
    bucket["last_refill"] = now


def is_allowed(ip: str) -> tuple[bool, str]:
    """
    Returns (allowed: bool, reason: str).
    Call this at the top of every sensitive route.
    """
    now = time.time()

    with _lock:
        # --- Check hard block ---
        if ip in _blocked_ips:
            if now < _blocked_ips[ip]:
                remaining = int(_blocked_ips[ip] - now)
                return False, f"IP temporarily blocked. Try again in {remaining}s."
            else:
                del _blocked_ips[ip]

        bucket = _buckets[ip]
        _refill(bucket)

        # --- Burst check (too many hits in 5 seconds) ---
        if now - bucket["burst_window_start"] > 5:
            bucket["burst_count"] = 0
            bucket["burst_window_start"] = now
        bucket["burst_count"] += 1

        if bucket["burst_count"] > BURST_LIMIT:
            _blocked_ips[ip] = now + BLOCK_DURATION
            return False, "Burst limit exceeded. IP blocked for 5 minutes."

        # --- Token bucket check ---
        if bucket["tokens"] < 1:
            return False, "Rate limit exceeded. Slow down."

        bucket["tokens"] -= 1
        return True, "OK"


def block_ip(ip: str, duration: int = BLOCK_DURATION) -> None:
    """Manually block an IP (e.g., after confirmed attack)."""
    with _lock:
        _blocked_ips[ip] = time.time() + duration
        _failed_logins.pop(ip, None)


def record_failed_login(ip: str) -> tuple[bool, int]:
    """
    Track wrong credentials for an IP.
    Returns (blocked_now, failed_count).
    """
    now = time.time()
    with _lock:
        attempts = _failed_logins[ip]
        if now - attempts["window_start"] > FAILED_LOGIN_WINDOW:
            attempts["count"] = 0
            attempts["window_start"] = now

        attempts["count"] += 1
        failed_count = attempts["count"]

        if failed_count >= MAX_FAILED_ATTEMPTS:
            _blocked_ips[ip] = now + LOCKOUT_SECONDS
            _failed_logins.pop(ip, None)
            return True, failed_count

        return False, failed_count


def clear_failed_logins(ip: str) -> None:
    """Reset failed credential attempts after a successful login."""
    with _lock:
        _failed_logins.pop(ip, None)


def get_blocked_ips() -> dict[str, int]:
    """Return dict of {ip: seconds_remaining}."""
    now = time.time()
    with _lock:
        return {
            ip: int(exp - now)
            for ip, exp in _blocked_ips.items()
            if exp > now
        }
