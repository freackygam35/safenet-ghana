"""
SafeNet Ghana - CCTV Network Security Monitor (Module 3)
Author: Patrick Idan - GCTU Cybersecurity
"""

import cv2
import threading
import time
import datetime
import numpy as np
from collections import deque
from typing import Optional, Callable

ALERT_SEVERITY = {
    "MOTION_DETECTED":    "HIGH",
    "FEED_INTERRUPTED":   "CRITICAL",
    "FEED_RESTORED":      "LOW",
    "TAMPERING_DETECTED": "CRITICAL",
    "QUALITY_DEGRADED":   "MEDIUM",
    "STREAM_REPLAY":      "HIGH",
    "BANDWIDTH_SPIKE":    "MEDIUM",
    "CAMERA_OFFLINE":     "HIGH",
    "CAMERA_ONLINE":      "LOW",
    "BRIGHTNESS_ANOMALY": "MEDIUM",
}

ALERT_DESCRIPTIONS = {
    "MOTION_DETECTED":    "Motion detected in monitored area — possible unauthorized access",
    "FEED_INTERRUPTED":   "Camera feed lost — possible physical tampering or cable cut",
    "FEED_RESTORED":      "Camera feed restored after interruption",
    "TAMPERING_DETECTED": "Camera tampering detected — lens blocked or camera moved",
    "QUALITY_DEGRADED":   "Feed quality degraded — signal interference or encoding attack",
    "STREAM_REPLAY":      "Stream replay attack suspected — identical frames detected",
    "BANDWIDTH_SPIKE":    "Unusual bandwidth spike — possible unauthorized stream access",
    "CAMERA_OFFLINE":     "Camera went offline unexpectedly",
    "CAMERA_ONLINE":      "Camera came online",
    "BRIGHTNESS_ANOMALY": "Sudden brightness change — possible camera blinding attempt",
}


class CameraMonitor:
    def __init__(self, camera_id, source, name="Camera", location="Unknown",
                 alert_callback=None, motion_sensitivity=0.5, restricted_hours=None):
        self.camera_id          = camera_id
        self.source             = source
        self.name               = name
        self.location           = location
        self.alert_callback     = alert_callback
        self.motion_sensitivity = motion_sensitivity
        self.restricted_hours   = restricted_hours
        self.cap                = None
        self.running            = False
        self.thread             = None
        self.status             = "offline"
        self.alerts             = []
        self.frame_count        = 0
        self.fps                = 0
        self.last_frame         = None
        self.last_frame_time    = None
        self.prev_frame         = None
        self.frame_history      = deque(maxlen=30)
        self.consecutive_lost   = 0
        self.last_brightness    = None
        self.tamper_baseline    = None
        self.tamper_check_count = 0
        self.motion_cooldown    = 0
        self.total_motion_events = 0
        self.total_alerts       = 0
        self.start_time         = None
        self.bytes_processed    = 0

    def _fire_alert(self, alert_type, detail=None, extra=None):
        alert = {
            "id":          f"{self.camera_id}-{int(time.time()*1000) % 999999:06d}",
            "camera_id":   self.camera_id,
            "camera_name": self.name,
            "location":    self.location,
            "type":        alert_type,
            "severity":    ALERT_SEVERITY.get(alert_type, "MEDIUM"),
            "detail":      detail or ALERT_DESCRIPTIONS.get(alert_type, ""),
            "timestamp":   datetime.datetime.now().isoformat(),
            "extra":       extra or {},
        }
        self.alerts.append(alert)
        if len(self.alerts) > 200:
            self.alerts = self.alerts[-200:]
        self.total_alerts += 1
        print(f"[CCTV] {alert['severity']:8s} | {self.camera_id} | {alert_type:22s} | {alert['detail'][:50]}")
        if self.alert_callback:
            self.alert_callback(alert)

    def _is_restricted_time(self):
        if not self.restricted_hours:
            return True
        start_h, end_h = self.restricted_hours
        hour = datetime.datetime.now().hour
        if start_h > end_h:
            return hour >= start_h or hour < end_h
        return start_h <= hour < end_h

    def _detect_motion(self, frame):
        if self.prev_frame is None:
            self.prev_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            self.prev_frame = cv2.GaussianBlur(self.prev_frame, (21, 21), 0)
            return False
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray = cv2.GaussianBlur(gray, (21, 21), 0)
        diff = cv2.absdiff(self.prev_frame, gray)
        thresh = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)[1]
        thresh = cv2.dilate(thresh, None, iterations=2)
        contours, _ = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        motion_detected = False
        for contour in contours:
            if cv2.contourArea(contour) > 500 * self.motion_sensitivity:
                motion_detected = True
                break
        self.prev_frame = gray
        return motion_detected

    def _detect_tampering(self, frame):
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        self.tamper_check_count += 1
        if self.tamper_check_count < 30:
            if self.tamper_baseline is None:
                self.tamper_baseline = gray.astype(float)
            else:
                self.tamper_baseline = 0.95 * self.tamper_baseline + 0.05 * gray.astype(float)
            return False
        if self.tamper_baseline is None:
            return False
        diff = cv2.absdiff(gray, self.tamper_baseline.astype(np.uint8))
        return np.mean(diff) > 60

    def _detect_brightness_anomaly(self, frame):
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        brightness = np.mean(gray)
        if self.last_brightness is None:
            self.last_brightness = brightness
            return False
        change = abs(brightness - self.last_brightness)
        self.last_brightness = brightness
        return change > 80

    def _detect_replay(self, frame):
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        small = cv2.resize(gray, (32, 32))
        frame_hash = hash(small.tobytes())
        if self.frame_history.count(frame_hash) > 5:
            return True
        self.frame_history.append(frame_hash)
        return False

    def _check_quality(self, frame):
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        return cv2.Laplacian(gray, cv2.CV_64F).var() < 10

    def _capture_loop(self):
        self.cap = cv2.VideoCapture(self.source)
        if not self.cap.isOpened():
            self.status = "offline"
            self._fire_alert("CAMERA_OFFLINE", f"{self.name} could not be opened")
            return

        self.status = "online"
        self.start_time = datetime.datetime.now()
        self._fire_alert("CAMERA_ONLINE", f"{self.name} connected — monitoring started")

        fps_counter = 0
        frame_times = deque(maxlen=30)

        while self.running:
            ret, frame = self.cap.read()

            if not ret or frame is None:
                self.consecutive_lost += 1
                if self.consecutive_lost == 5:
                    self.status = "offline"
                    self._fire_alert("FEED_INTERRUPTED", f"{self.name} feed lost — attempting reconnect")
                    self.cap.release()
                    time.sleep(2)
                    self.cap = cv2.VideoCapture(self.source)
                time.sleep(0.1)
                continue

            if self.consecutive_lost >= 5:
                self.status = "online"
                self._fire_alert("FEED_RESTORED", f"{self.name} feed restored after interruption")
            self.consecutive_lost = 0

            self.frame_count += 1
            self.last_frame = frame.copy()
            self.last_frame_time = datetime.datetime.now()

            fps_counter += 1
            now = time.time()
            frame_times.append(now)
            if fps_counter % 30 == 0 and len(frame_times) > 1:
                self.fps = round(len(frame_times) / (frame_times[-1] - frame_times[0]), 1)

            try:
                if self.motion_cooldown <= 0:
                    if self._detect_motion(frame) and self._is_restricted_time():
                        self._fire_alert("MOTION_DETECTED",
                            f"Motion in {self.location} at {datetime.datetime.now().strftime('%H:%M:%S')}")
                        self.total_motion_events += 1
                        self.motion_cooldown = 30
                else:
                    self.motion_cooldown -= 1

                if self.frame_count % 10 == 0:
                    if self._detect_tampering(frame):
                        self._fire_alert("TAMPERING_DETECTED", f"{self.name} — lens may be blocked")

                if self.frame_count % 5 == 0:
                    if self._detect_brightness_anomaly(frame):
                        self._fire_alert("BRIGHTNESS_ANOMALY", f"{self.name} — sudden brightness change")

                if self.frame_count % 15 == 0:
                    if self._detect_replay(frame):
                        self._fire_alert("STREAM_REPLAY", f"{self.name} — repeated frames detected")

                if self.frame_count % 30 == 0:
                    if self._check_quality(frame):
                        if self.status != "degraded":
                            self.status = "degraded"
                            self._fire_alert("QUALITY_DEGRADED", f"{self.name} — low sharpness detected")
                    else:
                        if self.status == "degraded":
                            self.status = "online"
            except Exception:
                pass

            time.sleep(0.033)

        if self.cap:
            self.cap.release()
        self.status = "offline"
        print(f"[CCTV] {self.camera_id} monitoring stopped")

    def start(self):
        if self.running:
            return {"status": "already_running"}
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()
        print(f"[CCTV] Starting monitor: {self.camera_id} ({self.name}) source={self.source}")
        return {"status": "started", "camera_id": self.camera_id}

    def stop(self):
        self.running = False
        return {"status": "stopped", "camera_id": self.camera_id,
                "frames_seen": self.frame_count, "total_alerts": self.total_alerts}

    def get_status(self):
        uptime = None
        if self.start_time and self.running:
            uptime = int((datetime.datetime.now() - self.start_time).total_seconds())
        return {
            "camera_id":     self.camera_id,
            "name":          self.name,
            "location":      self.location,
            "status":        self.status,
            "running":       self.running,
            "fps":           self.fps,
            "frame_count":   self.frame_count,
            "total_alerts":  self.total_alerts,
            "motion_events": self.total_motion_events,
            "uptime_secs":   uptime,
        }

    def get_alerts(self, limit=50):
        return list(reversed(self.alerts))[:limit]

    def get_snapshot(self):
        if self.last_frame is None:
            return None
        try:
            _, buf = cv2.imencode(".jpg", self.last_frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
            return buf.tobytes()
        except Exception:
            return None


class CCTVManager:
    def __init__(self):
        self.cameras = {}
        self.global_alerts = []
        self.alert_callback = None

    def _on_alert(self, alert):
        self.global_alerts.append(alert)
        if len(self.global_alerts) > 1000:
            self.global_alerts = self.global_alerts[-1000:]
        if self.alert_callback:
            self.alert_callback(alert)

    def add_camera(self, camera_id, source, name="Camera", location="Unknown",
                   motion_sensitivity=0.5, restricted_hours=None):
        if camera_id in self.cameras:
            return {"status": "already_exists", "camera_id": camera_id}
        cam = CameraMonitor(
            camera_id=camera_id, source=source, name=name, location=location,
            alert_callback=self._on_alert, motion_sensitivity=motion_sensitivity,
            restricted_hours=restricted_hours,
        )
        self.cameras[camera_id] = cam
        return cam.start()

    def remove_camera(self, camera_id):
        if camera_id not in self.cameras:
            return {"status": "not_found"}
        result = self.cameras[camera_id].stop()
        del self.cameras[camera_id]
        return result

    def stop_all(self):
        result = {cid: cam.stop() for cid, cam in self.cameras.items()}
        self.cameras = {}
        return result

    def get_all_status(self):
        return [cam.get_status() for cam in self.cameras.values()]

    def get_all_alerts(self, limit=100):
        return list(reversed(self.global_alerts))[:limit]

    def get_stats(self):
        from collections import defaultdict
        counts_by_type = defaultdict(int)
        counts_by_sev  = defaultdict(int)
        for a in self.global_alerts:
            counts_by_type[a["type"]] += 1
            counts_by_sev[a["severity"]] += 1
        online  = sum(1 for c in self.cameras.values() if c.status == "online")
        offline = sum(1 for c in self.cameras.values() if c.status == "offline")
        return {
            "total_cameras": len(self.cameras),
            "online":        online,
            "offline":       offline,
            "total_alerts":  len(self.global_alerts),
            "by_type":       dict(counts_by_type),
            "by_severity":   dict(counts_by_sev),
        }

    def get_snapshot(self, camera_id):
        if camera_id not in self.cameras:
            return None
        return self.cameras[camera_id].get_snapshot()

    @staticmethod
    def list_available_cameras(max_test=5):
        available = []
        for i in range(max_test):
            cap = cv2.VideoCapture(i)
            if cap.isOpened():
                ret, _ = cap.read()
                if ret:
                    available.append({"index": i, "source": i})
            cap.release()
        return available


cctv_manager = CCTVManager()


if __name__ == "__main__":
    print("SafeNet Ghana - CCTV Monitor v0.1")
    cameras = CCTVManager.list_available_cameras()
    print(f"Found {len(cameras)} camera(s): {cameras}")
    if not cameras:
        print("No cameras found.")
        exit(1)

    def on_alert(alert):
        print(f"ALERT: {alert['severity']} — {alert['type']} — {alert['detail']}")

    manager = CCTVManager()
    manager.alert_callback = on_alert
    manager.add_camera("CAM-01", cameras[0]["index"], "Iriun Phone Camera", "Test Environment", 0.4)

    print("Monitoring... Press Ctrl+C to stop")
    try:
        while True:
            time.sleep(5)
            for c in manager.get_all_status():
                print(f"[STATUS] {c['camera_id']} | {c['status']} | FPS:{c['fps']} | Alerts:{c['total_alerts']}")
    except KeyboardInterrupt:
        manager.stop_all()
        print("Stopped.")
