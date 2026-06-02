"""DCOL secure surveillance backend with complete PostgreSQL persistence."""

import os
import secrets
import threading
import time
from functools import wraps
from urllib.parse import urlparse

import cv2
from flask import Flask, Response, abort, jsonify, make_response, request, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import config
from input_validator import validate_login_payload
from rate_limiter import block_ip, get_blocked_ips, is_allowed
from security_headers import init_security_headers
from security_logger import Event, security_logger


def _camera_source():
    source = config.CAMERA_SOURCE
    return int(source) if str(source).isdigit() else source


def _camera_backend():
    if config.CAMERA_BACKEND == "CAP_DSHOW" and os.name == "nt":
        return cv2.CAP_DSHOW
    return cv2.CAP_ANY


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def _session_token() -> str:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.removeprefix("Bearer ").strip()
    return request.cookies.get(config.SESSION_COOKIE_NAME, "")


def _is_allowed_origin() -> bool:
    origin = request.headers.get("Origin")
    if not origin:
        return True
    return origin in config.ALLOWED_ORIGINS


app = Flask(__name__, static_folder=None)
app.secret_key = config.SECRET_KEY or os.urandom(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ── POSTGRESQL PERSISTENCE LAYER & SCHEMAS ───────────────────────────────────
db_url = config.DATABASE_URL
if db_url:
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
else:
    db_url = "sqlite:///:memory:"

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class DBLog(db.Model):
    """Schema for persistent Security Access Logs."""
    __tablename__ = "security_events"
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)
    event = db.Column(db.String(50), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(50), default="")
    status = db.Column(db.String(100), nullable=False)
    is_threat = db.Column(db.Boolean, default=False)


class DBSession(db.Model):
    """Schema for persistent Active Sessions."""
    __tablename__ = "active_sessions"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.Float, nullable=False, default=time.time)
    last_seen = db.Column(db.Float, nullable=False, default=time.time)
    revoked = db.Column(db.Boolean, default=False)


class DBBlockedIP(db.Model):
    """Schema for persistent Blocked IPs."""
    __tablename__ = "blocked_ips"
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), unique=True, nullable=False)
    blocked_at = db.Column(db.Float, nullable=False, default=time.time)
    unblock_at = db.Column(db.Float, nullable=False)


class DBFailedLogin(db.Model):
    """Schema for tracking brute-force attempts persistently across restarts."""
    __tablename__ = "failed_logins"
    ip = db.Column(db.String(45), primary_key=True)
    count = db.Column(db.Integer, default=0)
    last_attempt = db.Column(db.Float, default=time.time)


# ── DATABASE OPERATION CONTROLLERS ───────────────────────────────────────────

def log_security_event(event_type: str, ip: str, username: str = None, extra: dict = None):
    """Logs security actions simultaneously to files and the database."""
    entry = security_logger.log(event_type, ip, username=username, extra=extra)
    try:
        db_entry = DBLog(
            time=entry.get("time", ""),
            timestamp=entry.get("timestamp", ""),
            event=entry.get("event", ""),
            ip=entry.get("ip", ""),
            username=entry.get("username", ""),
            status=entry.get("status", ""),
            is_threat=entry.get("is_threat", False)
        )
        db.session.add(db_entry)
        db.session.commit()
    except Exception as e:
        print(f"[DB ERROR] Failed to record security event: {e}", flush=True)
        db.session.rollback()


def _validate_db_session(token: str, client_ip: str = None) -> bool:
    """Validates session structures directly against database targets."""
    if not token:
        return False
    sess = DBSession.query.filter_by(token=token, revoked=False).first()
    if not sess:
        return False
    
    if (time.time() - sess.created_at) > config.SESSION_TTL:
