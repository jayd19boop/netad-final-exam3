"""Optional local camera transmitter.

Use only if you run a separate relay service. Configure with environment
variables instead of hardcoding public URLs or secrets.
"""

import base64
import os
import time

import cv2
import socketio

RENDER_URL = os.getenv("DCOL_RELAY_URL", "").strip()
RELAY_TOKEN = os.getenv("DCOL_RELAY_TOKEN", "").strip()
CAMERA_INDEX = int(os.getenv("DCOL_LOCAL_CAMERA_INDEX", "0"))
FRAME_WIDTH = int(os.getenv("DCOL_TX_FRAME_WIDTH", "480"))
FRAME_HEIGHT = int(os.getenv("DCOL_TX_FRAME_HEIGHT", "360"))
JPEG_QUALITY = int(os.getenv("DCOL_TX_JPEG_QUALITY", "45"))
FRAME_DELAY = float(os.getenv("DCOL_TX_FRAME_DELAY", "0.08"))

if not RENDER_URL.startswith("https://"):
    raise RuntimeError("Set DCOL_RELAY_URL to your HTTPS Render relay URL.")

sio = socketio.Client(reconnection=True, reconnection_attempts=5)


@sio.event
def connect():
    print("Connected to relay.")


@sio.event
def disconnect():
    print("Disconnected from relay.")


@sio.event
def connect_error(data):
    print("Relay connection failed.")


auth = {"token": RELAY_TOKEN} if RELAY_TOKEN else None
sio.connect(RENDER_URL, auth=auth)

cap = cv2.VideoCapture(CAMERA_INDEX, cv2.CAP_DSHOW if os.name == "nt" else cv2.CAP_ANY)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)

try:
    while True:
        ret, frame = cap.read()
        if not ret:
            time.sleep(FRAME_DELAY)
            continue

        frame = cv2.resize(frame, (FRAME_WIDTH, FRAME_HEIGHT))
        ok, buffer = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY])
        if not ok:
            continue

        image = base64.b64encode(buffer).decode("utf-8")
        sio.emit("video_frame", {"image": f"data:image/jpeg;base64,{image}"})
        time.sleep(FRAME_DELAY)
except KeyboardInterrupt:
    pass
finally:
    cap.release()
    sio.disconnect()
