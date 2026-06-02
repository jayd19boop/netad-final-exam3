"""DCOL secure surveillance backend for Render deployment."""

import os
import threading
import time
from functools import wraps
from urllib.parse import urlparse

import cv2
from flask import Flask, Response, abort, jsonify, make_response, request, send_from_directory
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import config
from input_validator import validate_login_payload
from rate_limiter import block_ip, get_blocked_ips, is_allowed
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
            security_logger.log(Event.TOKEN_INVALID, ip=client)
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

CORS(
    app,
    resources={r"/api/*": {"origins": config.ALLOWED_ORIGINS}},
    supports_credentials=True,
)
init_security_headers(app)

ADMIN_PASSWORD_HASH = _admin_password_hash()

# --- BACKGROUND THREAD BROADCAST LOGIC ---
latest_frame = None
frame_lock = threading.Lock()

def camera_background_thread():
    """Continuously reads the camera from a single thread and stores the latest frame."""
    global latest_frame
    encode_params = [int(cv2.IMWRITE_JPEG_QUALITY), config.JPEG_QUALITY]
    
    cap = cv2.VideoCapture(_camera_source(), _camera_backend())
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, config.FRAME_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, config.FRAME_HEIGHT)

    while True:
        if not cap.isOpened():
            time.sleep(2)
            cap.open(_camera_source(), _camera_backend())
            continue

        success, frame = cap.read()
        if success:
            ok, buffer = cv2.imencode(".jpg", frame, encode_params)
            if ok:
                with frame_lock:
                    latest_frame = buffer.tobytes()
        else:
            time.sleep(1)
            cap.release()
            cap.open(_camera_source(), _camera_backend())

# Start the worker thread
threading.Thread(target=camera_background_thread, daemon=True).start()


@app.route("/")
def index():
    return send_from_directory(os.path.dirname(__file__), "frontend.html")


def generate_frames():
    """Serves the globally buffered frame to connected clients."""
    global latest_frame
    while True:
        with frame_lock:
            current_frame = latest_frame
        if current_frame:
            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n\r\n" + current_frame + b"\r\n"
            )
        time.sleep(0.05)  # Caps stream delivery at ~20 frames per second


@app.route("/video_feed")
@require_session
def video_feed():
    client = _client_ip()
    security_logger.log(Event.STREAM_ACCESS, ip=client)
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
        security_logger.log(Event.RATE_LIMIT, ip=client, extra={"reason": reason})
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
        security_logger.log(event_map.get(threat_type, Event.LOGIN_FAILURE), ip=client, username=clean_user)
        block_ip(client)
        return jsonify({"success": False, "message": "Request blocked."}), 403

    is_valid = (
        clean_user == config.ADMIN_USERNAME
        and check_password_hash(ADMIN_PASSWORD_HASH, raw_data.get("password", ""))
    )

    if not is_valid:
        security_logger.log(Event.LOGIN_FAILURE, ip=client, username=clean_user)
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    token = session_manager.create_session(ip=client, username=clean_user)
    if token is None:
        return jsonify({"success": False, "message": "Server session limit reached."}), 503

    security_logger.log(Event.LOGIN_SUCCESS, ip=client, username=clean_user)
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
    security_logger.log(Event.SESSION_REVOKED, ip=_client_ip())
    response = make_response(jsonify({"success": True}))
    response.delete_cookie(config.SESSION_COOKIE_NAME)
    return response


@app.route("/api/security_logs", methods=["GET"])
@require_session
def get_logs():
    return jsonify(security_logger.recent(8))


@app.route("/api/threat_logs", methods=["GET"])
@require_session
def get_threat_logs():
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
    return jsonify({"status": "ok", "camera": latest_frame is not None, "source": source_type})


if __name__ == "__main__":
    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        use_reloader=config.USE_RELOADER,
    )
