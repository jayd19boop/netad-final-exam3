# Render Deployment Notes

Use these files as the Render service root.

Build command:

```bash
pip install -r requirements.txt
```

Start command:

```bash
gunicorn app:app --workers 1 --threads 4 --timeout 120
```

Required environment variables:

```text
DCOL_ADMIN_USER=admin
DCOL_ADMIN_PASSWORD_HASH=<generated password hash>
DCOL_SECRET_KEY=<long random secret>
DCOL_CAMERA_SOURCE=<your CCTV/MJPEG/RTSP URL>
```

Generate the password hash locally:

```bash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('replace-with-a-strong-password'))"
```

For your Cloudflare feed, put the URL in `DCOL_CAMERA_SOURCE` in Render's environment settings. Do not commit it to code, because the `key=` value is effectively a secret.

Optional environment variables:

```text
DCOL_ALLOWED_ORIGINS=https://your-render-app.onrender.com
DCOL_SESSION_COOKIE_SECURE=true
DCOL_DEBUG=false
DCOL_MAX_FAILED_ATTEMPTS=3
DCOL_LOCKOUT_SECONDS=120
DCOL_SESSION_BIND_IP=false
```

Security checklist:

- Rotate the CCTV `key=` value if this URL has been shared anywhere public.
- Keep `DCOL_DEBUG=false` on Render.
- Use a strong admin password and store only `DCOL_ADMIN_PASSWORD_HASH`.
- Leave the dashboard and stream behind the login; do not expose `/video_feed` directly.
- Set `DCOL_MAX_FAILED_ATTEMPTS` and `DCOL_LOCKOUT_SECONDS` to control automatic lockouts after wrong credentials.
- Keep `DCOL_SESSION_BIND_IP=false` on Render unless you are sure every request arrives from the same client IP.
