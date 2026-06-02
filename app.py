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
        sess.revoked = True
        db.session.commit()
        return False
        
    if config.SESSION_BIND_IP and client_ip and sess.ip != client_ip:
        sess.revoked = True
        db.session.commit()
        return False
        
    sess.last_seen = time.time()
    db.session.commit()
    return True


def _create_db_session(ip: str, username: str) -> str or None:
    """Creates a tracking token bound securely into persistent tables."""
    now = time.time()
    expired = DBSession.query.filter(DBSession.revoked == False, (now - DBSession.created_at) > config.SESSION_TTL).all()
    for s in expired:
        s.revoked = True
    if expired:
        db.session.commit()

    active_count = DBSession.query.filter_by(revoked=False).count()
    if active_count >= config.MAX_SESSIONS:
        return None

    token = secrets.token_hex(config.TOKEN_BYTES)
    new_sess = DBSession(token=token, ip=ip, username=username, created_at=now, last_seen=now, revoked=False)
    db.session.add(new_sess)
    db.session.commit()
    return token


def _db_block_ip(ip: str, duration: int):
    """Saves firewall lockout parameters directly into PostgreSQL."""
    now = time.time()
    existing = DBBlockedIP.query.filter_by(ip=ip).first()
    if existing:
        existing.unblock_at = now + duration
    else:
        new_block = DBBlockedIP(ip=ip, blocked_at=now, unblock_at=now + duration)
        db.session.add(new_block)
    db.session.commit()


# Automatically initialize tables inside the database context during instantiation
with app.app_context():
    db.create_all()
# ─────────────────────────────────────────────────────────────────────────────

def require_session(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _is_allowed_origin():
            abort(403)

        token = _session_token()
        client = _client_ip()
        bound_ip = client if config.SESSION_BIND_IP else None
        if not _validate_db_session(token, client_ip=bound_ip):
            log_security_event(Event.TOKEN_INVALID, ip=client)
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def _admin_password_hash() -> str:
    if config.ADMIN_PASSWORD_HASH:
        return config.ADMIN_PASSWORD_HASH
    if config.DEBUG and config.ADMIN_PASSWORD:
        return generate_password_hash(config.ADMIN_PASSWORD)
    raise RuntimeError("Set DCOL_ADMIN_PASSWORD_HASH in Render configurations.")


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
    now = time.time()
    
    # 1. Enforce persistent DB-backed Blocklist Check
    block = DBBlockedIP.query.filter_by(ip=client).first()
    if block:
        if now < block.unblock_at:
            log_security_event(Event.RATE_LIMIT, ip=client, extra={"reason": "IP explicitly blocked in DB database cluster"})
            return jsonify({"success": False, "message": "Too many attempts. Try again later."}), 429
        else:
            db.session.delete(block)
            db.session.commit()

    # 2. Check general rolling window allocations
    allowed, reason = is_allowed(client)
    if not allowed:
        log_security_event(Event.RATE_LIMIT, ip=client, extra={"reason": reason})
        _db_block_ip(client, config.BLOCK_DURATION)
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
        _db_block_ip(client, config.BLOCK_DURATION)
        return jsonify({"success": False, "message": "Request blocked."}), 403

    is_valid = (
        clean_user == config.ADMIN_USERNAME
        and check_password_hash(ADMIN_PASSWORD_HASH, raw_data.get("password", ""))
    )

    if not is_valid:
        # DB-backed failed login attempt tracking
        fail_record = DBFailedLogin.query.filter_by(ip=client).first()
        if not fail_record:
            fail_record = DBFailedLogin(ip=client, count=1, last_attempt=now)
            db.session.add(fail_record)
        else:
            fail_record.count += 1
            fail_record.last_attempt = now
        
        blocked_now = False
        if fail_record.count >= config.MAX_FAILED_ATTEMPTS:
            blocked_now = True
            _db_block_ip(client, config.LOCKOUT_SECONDS)
            fail_record.count = 0
            
        db.session.commit()
        
        event = Event.BRUTE_FORCE if blocked_now else Event.LOGIN_FAILURE
        log_security_event(
            event,
            ip=client,
            username=clean_user,
            extra={"failed_attempts": fail_record.count if not blocked_now else config.MAX_FAILED_ATTEMPTS},
        )
        if blocked_now:
            return jsonify({"success": False, "message": "Too many failed attempts. Try again later."}), 429
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    # Clean up tracking on successful authorization
    fail_record = DBFailedLogin.query.filter_by(ip=client).first()
    if fail_record:
        db.session.delete(fail_record)
        db.session.commit()

    token = _create_db_session(ip=client, username=clean_user)
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
    sess = DBSession.query.filter_by(token=token).first()
    if sess:
        sess.revoked = True
        db.session.commit()
        
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
    except Exception:
        return jsonify([])


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
    except Exception:
        return jsonify([])


@app.route("/api/blocked_ips", methods=["GET"])
@require_session
def get_blocked():
    now = time.time()
    try:
        expired = DBBlockedIP.query.filter(DBBlockedIP.unblock_at <= now).all()
        for b in expired:
            db.session.delete(b)
        if expired:
            db.session.commit()

        blocks = DBBlockedIP.query.all()
        return jsonify({b.ip: max(0, int(b.unblock_at - now)) for b in blocks})
    except Exception:
        return jsonify({})


@app.route("/api/active_sessions", methods=["GET"])
@require_session
def get_sessions():
    now = time.time()
    try:
        expired = DBSession.query.filter(DBSession.revoked == False, (now - DBSession.created_at) > config.SESSION_TTL).all()
        for s in expired:
            s.revoked = True
        if expired:
            db.session.commit()

        sessions = DBSession.query.filter_by(revoked=False).all()
        return jsonify([{
            "token_prefix": s.token[:8] + "...",
            "ip": s.ip,
            "username": s.username,
            "age_seconds": int(now - s.created_at),
            "revoked": s.revoked,
            "expired": (now - s.created_at) > config.SESSION_TTL
        } for s in sessions])
    except Exception:
        return jsonify([])


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
