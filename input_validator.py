"""
input_validator.py — Input Sanitization & Threat Detection
Validates and cleans all user-supplied data before it touches the app logic.
"""

import re
import html
import unicodedata
from typing import Any

# ─── SQL Injection patterns ────────────────────────────────────────────────────
_SQLI_PATTERNS = [
    r"(\bOR\b|\bAND\b)\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+",   # OR 1=1 / AND '1'='1'
    r"--",                                                           # SQL line comment
    r"/\*.*?\*/",                                                    # block comment
    r"\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|TRUNCATE|REPLACE|LOAD)\b",
    r";\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER)",
    r"xp_cmdshell",
    r"information_schema",
    r"sleep\s*\(\s*\d+\s*\)",                                        # time-based blind
    r"benchmark\s*\(",
    r"waitfor\s+delay",
]

# ─── XSS patterns ─────────────────────────────────────────────────────────────
_XSS_PATTERNS = [
    r"<\s*script[^>]*>",
    r"javascript\s*:",
    r"on\w+\s*=",            # onclick=, onerror=, etc.
    r"<\s*iframe",
    r"<\s*object",
    r"<\s*embed",
    r"<\s*img[^>]+onerror",
    r"data\s*:",             # data: URI schemes
    r"vbscript\s*:",
    r"expression\s*\(",
]

# ─── Command Injection patterns ────────────────────────────────────────────────
_CMDI_PATTERNS = [
    r"[;&|`$]",
    r"\$\(",
    r"\.\./",                # path traversal
    r"\.\.\\",
]

_COMPILED_SQLI  = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _SQLI_PATTERNS]
_COMPILED_XSS   = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _XSS_PATTERNS]
_COMPILED_CMDI  = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in _CMDI_PATTERNS]


# ─── Public helpers ────────────────────────────────────────────────────────────

def sanitize_string(value: Any, max_length: int = 256) -> str:
    """
    Clean a raw string:
    1. Normalize unicode (NFKC) to collapse homoglyph attacks.
    2. Strip leading/trailing whitespace.
    3. HTML-escape special chars.
    4. Truncate to max_length.
    """
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", str(value))
    text = text.strip()
    text = html.escape(text, quote=True)
    return text[:max_length]


def detect_sqli(payload: Any) -> bool:
    """Return True if the payload looks like a SQL injection attempt."""
    raw = str(payload)
    return any(p.search(raw) for p in _COMPILED_SQLI)


def detect_xss(payload: Any) -> bool:
    """Return True if the payload looks like an XSS attempt."""
    raw = str(payload)
    return any(p.search(raw) for p in _COMPILED_XSS)


def detect_cmdi(payload: Any) -> bool:
    """Return True if the payload looks like command injection."""
    raw = str(payload)
    return any(p.search(raw) for p in _COMPILED_CMDI)


def classify_threat(username: Any, password: Any) -> str | None:
    """
    Run all detectors on login inputs.
    Returns a threat label string or None if clean.
    """
    combined = f"{username} {password}"
    if detect_sqli(combined):
        return "SQL_INJECTION"
    if detect_xss(combined):
        return "XSS_ATTEMPT"
    if detect_cmdi(combined):
        return "COMMAND_INJECTION"
    return None


def validate_login_payload(data: dict) -> tuple[str, str, str | None]:
    """
    Extract, sanitize, and classify a login request body.
    Returns (clean_username, clean_password, threat_type_or_None).
    """
    raw_user = data.get("username", "")
    raw_pass = data.get("password", "")

    # Classify on RAW values (before sanitization strips attack chars)
    threat = classify_threat(raw_user, raw_pass)

    clean_user = sanitize_string(raw_user, max_length=64)
    clean_pass = sanitize_string(raw_pass, max_length=128)

    return clean_user, clean_pass, threat
