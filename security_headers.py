"""
security_headers.py — HTTP Security Headers Middleware
Registers an after_request hook that injects hardened security headers
into every Flask response.

Usage:
    from security_headers import init_security_headers
    init_security_headers(app)
"""

from flask import Flask, Response


# Content-Security-Policy — very restrictive for a CCTV dashboard
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "   # allow inline JS in the single HTML file
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: blob:; "           # allow base64 / blob frames
    "connect-src 'self'; "
    "frame-ancestors 'none'; "               # blocks all iframe embedding
    "form-action 'self'; "
    "base-uri 'self';"
)

# Permissions-Policy — disable browser features the app never uses
_PERMISSIONS = (
    "geolocation=(), "
    "microphone=(), "
    "payment=(), "
    "usb=(), "
    "accelerometer=(), "
    "gyroscope=(), "
    "magnetometer=()"
)

_HEADERS: dict[str, str] = {
    # Prevent MIME-type sniffing attacks
    "X-Content-Type-Options": "nosniff",

    # Block the page from being embedded in an iframe (clickjacking)
    "X-Frame-Options": "DENY",

    # Legacy XSS filter (IE/old Chrome)
    "X-XSS-Protection": "1; mode=block",

    # Force HTTPS for 1 year (set this only if you have TLS)
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",

    # Prevent browsers from leaking the Referer header cross-origin
    "Referrer-Policy": "strict-origin-when-cross-origin",

    # Restrict browser API access
    "Permissions-Policy": _PERMISSIONS,

    # Content Security Policy
    "Content-Security-Policy": _CSP,

    # Remove the "Powered-By" header Flask adds by default
    "X-Powered-By": "",   # empty = header gets deleted below
}


def init_security_headers(app: Flask) -> None:
    """
    Call this once during app setup to attach the after_request hook.

        from security_headers import init_security_headers
        init_security_headers(app)
    """

    @app.after_request
    def _add_headers(response: Response) -> Response:
        for key, value in _HEADERS.items():
            if value == "":
                response.headers.pop(key, None)
            else:
                response.headers[key] = value

        # Also remove server fingerprinting header
        response.headers.pop("Server", None)

        return response
