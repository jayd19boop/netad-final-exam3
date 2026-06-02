"""DCOL secure surveillance backend with PostgreSQL database integration."""

import os
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
from rate_limiter import block_ip, clear_failed_logins, get_blocked_ips, is_allowed, record_failed_login
from security_headers import init_security_headers
from security_logger import Event, security_logger
from session_manager import session_manager


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


def require_session(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _is_allowed_origin():
            abort(403)

        token = _session_token()
        client = _client_ip()
        bound_ip = client if config.SESSION_BIND_IP else None
        if not session_manager.validate(token, ip=bound_ip):
            log_security_event(Event.TOKEN_INVALID, ip=client)
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def _admin_password_hash() -> str:
    if config.ADMIN_PASSWORD_HASH:
        return config.ADMIN_PASSWORD_HASH
    if config.DEBUG and config.ADMIN_PASSWORD:
        return generate_password_hash(config.ADMIN_PASSWORD)
    raise RuntimeError(
        "Set DCOL_ADMIN_PASSWORD_HASH in Render. "
        "Generate one locally with: python -c \"from werkzeug.security import "
        "generate_password_hash; print(generate_password_hash('your-password'))\""
    )


app = Flask(__name__, static_folder=None)
app.secret_key = config.SECRET_KEY or os.urandom(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ── POSTGRESQL CONFIGURATION & DATABASE MODELS ───────────────────────────────
db_url = config.DATABASE_URL
if db_url:
    # Safely convert old dialect strings to SQLAlchemy 1.4+ standards
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
else:
    db_url = "sqlite:///:memory:"

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class DBLog(db.Model):
    """PostgreSQL Schema mirroring audit events for persistent collection."""
    __tablename__ = "security_events"
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)
    event = db.Column(db.String(50), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    username = db.Column(db.String(50), default="")
    status = db.Column(db.String(100), nullable=False)
    is_threat = db.Column(db.Boolean, default=False)


def log_security_event(event_type: str, ip: str, username: str = None, extra: dict = None):
    """Dispatches logging events directly to file structures and PostgreSQL."""
    # Write to local memory buffers/files first
    entry = security_logger.log(event_type, ip, username=username, extra=extra)
    
    # Mirror persistently to database layer
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
        print(f"[DATABASE ERROR] Logging mirroring connection dropped: {e}", flush=True)
        db.session.rollback()


# Automatically initialize tables inside the database context during instantiation
with app.app_context():
    db.create_all()
# ─────────────────────────────────────────────────────────────────────────────

CORS(
    app,
    resources={r"/api/*": {"origins": config.ALLOWED_ORIGINS}},
    supports_credentials=True,
)
init_security_headers(app)

ADMIN_PASSWORD_HASH = _admin_password_hash()
camera_lock = threading.Lock()
camera = None


def _open_camera():
    cap = cv2.VideoCapture(_camera_source(), _camera_backend())
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, config.FRAME_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, config.FRAME_HEIGHT)
    return cap


def _get_camera():
    global camera
    with camera_lock:
        if camera is None or not camera.isOpened():
            if camera is not None:
                camera.release()
            camera = _open_camera()
        return camera


def _reopen_camera():
    global camera
    with camera_lock:
        if camera is not None:
            camera.release()
        camera = _open_camera()
        return camera


@app.route("/")
def index():
    return send_from_directory(os.path.dirname(__file__), "frontend.html")


def generate_frames():
    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), config.JPEG_QUALITY]
    failures = 0
    while True:
        cap = _get_camera()
        success, frame = cap.read()
        if not success:
            failures += 1
            if failures >= 3:
                _reopen_camera()
                failures = 0
            time.sleep(1)
            continue
        failures = 0
        ok, buffer = cv2.imencode(".jpg", frame, encode_params)
        if not ok:
            continue
        yield (
            b"--frame\r\n"
            b"Content-Type: image/jpeg\r\n\r\n" + buffer.tobytes() + b"\r\n"
        )


@app.route("/video_feed")
@require_session
def video_feed():
    client = _client_ip()
    log_security_event(Event.STREAM_ACCESS, ip=client)
    return Response(
        generate_frames(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
        headers={"Cache-Control": "no-store"},
    )


@app.route("/api/login", methods=["POST"])
def login():
    if not _is_allowed_origin():
        abort(403)

    client = _client_ip()
    allowed, reason = is_allowed(client)
    if not allowed:
        log_security_event(Event.RATE_LIMIT, ip=client, extra={"reason": reason})
        return jsonify({"success": False, "message": "Too many attempts. Try again later."}), 429

    if not request.is_json:
        return jsonify({"success": False, "message": "Invalid request."}), 400

    raw_data = request.get_json(silent=True) or {}
    clean_user, _clean_pass, threat_type = validate_login_payload(raw_data)

    if threat_type:
        event_map = {
            "SQL_INJECTION": Event.SQL_INJECTION,
            "XSS_ATTEMPT": Event.XSS_ATTEMPT,
            "COMMAND_INJECTION": Event.COMMAND_INJECTION,
        }
        log_security_event(event_map.get(threat_type, Event.LOGIN_FAILURE), ip=client, username=clean_user)
        block_ip(client)
        return jsonify({"success": False, "message": "Request blocked."}), 403

    is_valid = (
        clean_user == config.ADMIN_USERNAME
        and check_password_hash(ADMIN_PASSWORD_HASH, raw_data.get("password", ""))
    )

    if not is_valid:
        blocked_now, failed_count = record_failed_login(client)
        event = Event.BRUTE_FORCE if blocked_now else Event.LOGIN_FAILURE
        log_security_event(
            event,
            ip=client,
            username=clean_user,
            extra={"failed_attempts": failed_count},
        )
        if blocked_now:
            return jsonify({"success": False, "message": "Too many failed attempts. Try again later."}), 429
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    clear_failed_logins(client)
    token = session_manager.create_session(ip=client, username=clean_user)
    if token is None:
        return jsonify({"success": False, "message": "Server session limit reached."}), 503

    log_security_event(Event.LOGIN_SUCCESS, ip=client, username=clean_user)
    response = make_response(jsonify({"success": True, "message": "Authorized Access"}))
    response.set_cookie(
        config.SESSION_COOKIE_NAME,
        token,
        max_age=config.SESSION_TTL,
        httponly=True,
        secure=config.SESSION_COOKIE_SECURE,
        samesite="Strict",
    )
    return response


@app.route("/api/logout", methods=["POST"])
@require_session
def logout():
    token = _session_token()
    session_manager.revoke(token)
    log_security_event(Event.SESSION_REVOKED, ip=_client_ip())
    response = make_response(jsonify({"success": True}))
    response.delete_cookie(config.SESSION_COOKIE_NAME)
    return response


@app.route("/api/security_logs", methods=["GET"])
@require_session
def get_logs():
    try:
        logs = DBLog.query.order_by(DBLog.id.desc()).limit(8).all()
        return jsonify([{
            "time": log.time,
            "timestamp": log.timestamp,
            "event": log.event,
            "ip": log.ip,
            "username": log.username,
            "status": log.status,
            "is_threat": log.is_threat
        } for log in logs])
    except Exception as e:
        print(f"[DB STATUS] Reading logs from fallback volatile buffer: {e}", flush=True)
        return jsonify(security_logger.recent(8))


@app.route("/api/threat_logs", methods=["GET"])
@require_session
def get_threat_logs():
    try:
        logs = DBLog.query.filter_by(is_threat=True).order_by(DBLog.id.desc()).limit(20).all()
        return jsonify([{
            "time": log.time,
            "timestamp": log.timestamp,
            "event": log.event,
            "ip": log.ip,
            "username": log.username,
            "status": log.status,
            "is_threat": log.is_threat
        } for log in logs])
    except Exception as e:
        print(f"[DB STATUS] Reading threat sequences from fallback volatile buffer: {e}", flush=True)
        return jsonify(security_logger.threats_only(20))


@app.route("/api/blocked_ips", methods=["GET"])
@require_session
def get_blocked():
    return jsonify(get_blocked_ips())


@app.route("/api/active_sessions", methods=["GET"])
@require_session
def get_sessions():
    return jsonify(session_manager.active_sessions())


@app.route("/api/health", methods=["GET"])
def health():
    source = str(config.CAMERA_SOURCE)
    parsed = urlparse(source)
    source_type = "remote" if parsed.scheme else "local"
    cap = _get_camera()
    
    db_connected = False
    try:
        db.session.execute(db.text("SELECT 1"))
        db_connected = True
    except Exception:
        pass

    return jsonify({
        "status": "ok", 
        "camera": cap.isOpened(), 
        "source": source_type,
        "database": db_connected
    })


if __name__ == "__main__":
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        use_reloader=config.USE_RELOADER,
    )
