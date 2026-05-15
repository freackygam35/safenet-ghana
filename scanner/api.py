"""
SafeNet Ghana - API Server v0.5.0
Vulnerability Scanner + WiFi IDS + CCTV Monitor + PostgreSQL + JWT Auth

Author: Patrick Idan
Project: SafeNet Ghana - GCTU Cybersecurity
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional
import datetime

from scanner      import resolve_target, run_scan, analyze_results
from auth         import authenticate_user, create_access_token, get_current_user, require_admin, Token, User, TOKEN_EXPIRE
from database     import engine, get_db
from models       import Base, ScanResult, WifiAlert, CctvAlert, SystemLog
from wifi_ids     import wifi_ids, WiFiIDS
from cctv_monitor import cctv_manager, CCTVManager

# ── Create all DB tables on startup ───────────
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="SafeNet Ghana API",
    description="Affordable integrated security system for Ghanaian small businesses.",
    version="0.5.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
#  ALERT DB CALLBACKS
# ─────────────────────────────────────────────
def save_wifi_alert_to_db(alert: dict):
    try:
        from database import SessionLocal
        db = SessionLocal()
        db_alert = WifiAlert(
            alert_type = alert["type"],
            device_mac = alert["device_mac"],
            ssid       = alert.get("ssid"),
            channel    = alert.get("channel"),
            detail     = alert["detail"],
            severity   = alert["severity"],
        )
        db.add(db_alert)
        db.commit()
        db.close()
    except Exception as e:
        print(f"[DB] Failed to save WiFi alert: {e}")

def save_cctv_alert_to_db(alert: dict):
    try:
        from database import SessionLocal
        db = SessionLocal()
        db_alert = CctvAlert(
            camera_id  = alert["camera_id"],
            alert_type = alert["type"],
            detail     = alert["detail"],
            severity   = alert["severity"],
        )
        db.add(db_alert)
        db.commit()
        db.close()
    except Exception as e:
        print(f"[DB] Failed to save CCTV alert: {e}")

# Attach callbacks
wifi_ids.alert_callback     = save_wifi_alert_to_db
cctv_manager.alert_callback = save_cctv_alert_to_db


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def log_to_db(db: Session, level: str, source: str, message: str):
    try:
        entry = SystemLog(level=level, source=source, message=message)
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()


# ─────────────────────────────────────────────
#  REQUEST MODELS
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    target:    str
    scan_type: str = "basic"

class WifiStartRequest(BaseModel):
    interface:        Optional[str]  = None
    whitelist_ssids:  Optional[list] = []
    whitelist_bssids: Optional[list] = []

class CameraAddRequest(BaseModel):
    camera_id:          str
    source:             str            # "0", "1" for webcam index or RTSP URL
    name:               str = "Camera"
    location:           str = "Unknown"
    motion_sensitivity: float = 0.5
    restricted_hours:   Optional[list] = None  # [22, 6] = 10pm to 6am


# ─────────────────────────────────────────────
#  PUBLIC ROUTES
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "system":  "SafeNet Ghana",
        "version": "0.5.0",
        "status":  "online",
        "author":  "Patrick Idan - GCTU Cybersecurity",
        "modules": {
            "vulnerability_scanner": "live",
            "wifi_ids":              "live",
            "cctv_monitor":          "live",
        },
    }

@app.get("/health")
def health():
    return {
        "status":       "ok",
        "timestamp":    datetime.datetime.now().isoformat(),
        "wifi_ids":     wifi_ids.get_status(),
        "cctv_cameras": len(cctv_manager.cameras),
    }


# ─────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────
@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        log_to_db(db, "WARNING", "AUTH", f"Failed login: {form_data.username}")
        raise HTTPException(status_code=401, detail="Incorrect username or password.", headers={"WWW-Authenticate": "Bearer"})
    token = create_access_token({"sub": user["username"]})
    log_to_db(db, "INFO", "AUTH", f"Login: {user['username']} ({user['role']})")
    print(f"[AUTH] Login → {user['username']} ({user['role']})")
    return Token(access_token=token, token_type="bearer", username=user["username"], full_name=user["full_name"], role=user["role"], expires_in=TOKEN_EXPIRE * 60)

@app.get("/auth/me", response_model=User)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# ─────────────────────────────────────────────
#  VULNERABILITY SCANNER ROUTES
# ─────────────────────────────────────────────
@app.post("/scan")
def trigger_scan(request: ScanRequest, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    valid_types = ["basic", "version", "full"]
    if request.scan_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid scan_type. Choose: {valid_types}")
    ip = resolve_target(request.target)
    if not ip:
        raise HTTPException(status_code=400, detail=f"Cannot resolve: {request.target}")
    log_to_db(db, "INFO", "VULN", f"Scan started by {current_user.username} on {request.target}")
    try:
        nm     = run_scan(ip, request.scan_type)
        report = analyze_results(nm, request.target)
    except Exception as e:
        log_to_db(db, "ERROR", "VULN", f"Scan failed on {request.target}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
    report["scan_metadata"]["scanned_by"] = current_user.username
    summary = report["summary"]
    db_scan = ScanResult(
        target=request.target, scan_type=request.scan_type, scanned_by=current_user.username,
        overall_risk=summary["overall_risk"], total_hosts=summary["total_hosts"],
        open_ports=summary["open_ports"], critical_count=summary["critical_count"],
        high_count=summary["high_count"], medium_count=summary["medium_count"],
        low_count=summary["low_count"], full_report=report,
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    log_to_db(db, "INFO", "VULN", f"Scan complete {request.target} — {summary['overall_risk']}")
    return {"success": True, "message": f"Scan complete. Risk: {summary['overall_risk']}", "scan_id": db_scan.id, "data": report}

@app.get("/scans/history")
def get_history(limit: int = 50, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).limit(limit).all()
    return {"total": len(scans), "scans": [{"id": s.id, "target": s.target, "scan_type": s.scan_type, "timestamp": s.timestamp.isoformat(), "risk": s.overall_risk, "open_ports": s.open_ports, "scanned_by": s.scanned_by} for s in scans]}

@app.get("/scans/stats")
def get_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(ScanResult).all()
    if not scans:
        return {"message": "No scans yet.", "stats": {}}
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    total_ports = 0
    for s in scans:
        risk_counts[s.overall_risk] = risk_counts.get(s.overall_risk, 0) + 1
        total_ports += s.open_ports
    return {"total_scans": len(scans), "total_ports_found": total_ports, "risk_breakdown": risk_counts, "targets_scanned": [s.target for s in scans]}

@app.get("/scans/latest")
def get_latest(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).first()
    if not scan:
        raise HTTPException(status_code=404, detail="No scans yet.")
    return scan.full_report

@app.get("/scans/{scan_id}")
def get_scan(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return scan.full_report


# ─────────────────────────────────────────────
#  WIFI IDS ROUTES
# ─────────────────────────────────────────────
@app.post("/wifi/start")
def start_wifi_ids(request: WifiStartRequest, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    if wifi_ids.running:
        return {"status": "already_running"}
    for ssid  in request.whitelist_ssids:  wifi_ids.add_to_whitelist(ssid=ssid)
    for bssid in request.whitelist_bssids: wifi_ids.add_to_whitelist(bssid=bssid)
    result = wifi_ids.start(interface=request.interface)
    log_to_db(db, "INFO", "WIFI", f"WiFi IDS started by {current_user.username}")
    return result

@app.post("/wifi/stop")
def stop_wifi_ids(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    result = wifi_ids.stop()
    log_to_db(db, "INFO", "WIFI", f"WiFi IDS stopped by {current_user.username}")
    return result

@app.get("/wifi/status")
def wifi_status(current_user: User = Depends(get_current_user)):
    return wifi_ids.get_status()

@app.get("/wifi/interfaces")
def get_interfaces(current_user: User = Depends(get_current_user)):
    return {"interfaces": WiFiIDS.list_interfaces()}

@app.get("/wifi/alerts")
def get_wifi_alerts(limit: int = 50, severity: Optional[str] = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    live = wifi_ids.get_alerts(limit=limit, severity=severity)
    query = db.query(WifiAlert).order_by(WifiAlert.timestamp.desc())
    if severity:
        query = query.filter(WifiAlert.severity == severity)
    db_alerts = query.limit(limit).all()
    return {
        "live_alerts": live,
        "db_alerts": [{"id": a.id, "type": a.alert_type, "severity": a.severity, "device_mac": a.device_mac, "ssid": a.ssid, "channel": a.channel, "detail": a.detail, "timestamp": a.timestamp.isoformat()} for a in db_alerts],
        "stats": wifi_ids.get_stats(),
    }

@app.get("/wifi/stats")
def get_wifi_stats(current_user: User = Depends(get_current_user)):
    return wifi_ids.get_stats()

@app.post("/wifi/whitelist")
def add_whitelist(ssid: Optional[str] = None, bssid: Optional[str] = None, current_user: User = Depends(require_admin)):
    wifi_ids.add_to_whitelist(ssid=ssid, bssid=bssid)
    return {"status": "added", "ssid": ssid, "bssid": bssid}


# ─────────────────────────────────────────────
#  CCTV MONITOR ROUTES
# ─────────────────────────────────────────────
@app.post("/cctv/cameras")
def add_camera(request: CameraAddRequest, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Add and start monitoring a camera."""
    # Convert source to int if it's a webcam index
    source = int(request.source) if request.source.isdigit() else request.source
    restricted = tuple(request.restricted_hours) if request.restricted_hours else None

    result = cctv_manager.add_camera(
        camera_id          = request.camera_id,
        source             = source,
        name               = request.name,
        location           = request.location,
        motion_sensitivity = request.motion_sensitivity,
        restricted_hours   = restricted,
    )
    log_to_db(db, "INFO", "CCTV", f"Camera {request.camera_id} added by {current_user.username}")
    return result

@app.delete("/cctv/cameras/{camera_id}")
def remove_camera(camera_id: str, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Stop and remove a camera."""
    result = cctv_manager.remove_camera(camera_id)
    log_to_db(db, "INFO", "CCTV", f"Camera {camera_id} removed by {current_user.username}")
    return result

@app.get("/cctv/cameras")
def list_cameras(current_user: User = Depends(get_current_user)):
    """List all monitored cameras and their status."""
    return {
        "cameras": cctv_manager.get_all_status(),
        "stats":   cctv_manager.get_stats(),
    }

@app.get("/cctv/cameras/available")
def available_cameras(current_user: User = Depends(get_current_user)):
    """Detect all connected webcams on this machine."""
    return {"cameras": CCTVManager.list_available_cameras()}

@app.get("/cctv/cameras/{camera_id}/snapshot")
def get_snapshot(camera_id: str, current_user: User = Depends(get_current_user)):
    """
    Returns a live JPEG snapshot from the camera.
    The dashboard uses this to show real camera previews.
    """
    snapshot = cctv_manager.get_snapshot(camera_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail=f"No snapshot available for {camera_id}")
    return Response(content=snapshot, media_type="image/jpeg")

@app.get("/cctv/cameras/{camera_id}/status")
def camera_status(camera_id: str, current_user: User = Depends(get_current_user)):
    """Status of a specific camera."""
    if camera_id not in cctv_manager.cameras:
        raise HTTPException(status_code=404, detail=f"Camera {camera_id} not found.")
    return cctv_manager.cameras[camera_id].get_status()

@app.get("/cctv/cameras/{camera_id}/alerts")
def camera_alerts(camera_id: str, limit: int = 50, current_user: User = Depends(get_current_user)):
    """Alerts from a specific camera."""
    if camera_id not in cctv_manager.cameras:
        raise HTTPException(status_code=404, detail=f"Camera {camera_id} not found.")
    return {"alerts": cctv_manager.cameras[camera_id].get_alerts(limit=limit)}

@app.get("/cctv/alerts")
def get_all_cctv_alerts(
    limit: int = 50,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """All CCTV alerts — live memory + database history."""
    live = cctv_manager.get_all_alerts(limit=limit)
    query = db.query(CctvAlert).order_by(CctvAlert.timestamp.desc())
    if severity:
        query = query.filter(CctvAlert.severity == severity)
    db_alerts = query.limit(limit).all()
    return {
        "live_alerts": live,
        "db_alerts": [{"id": a.id, "camera_id": a.camera_id, "type": a.alert_type, "severity": a.severity, "detail": a.detail, "timestamp": a.timestamp.isoformat()} for a in db_alerts],
        "stats": cctv_manager.get_stats(),
    }

@app.get("/cctv/stats")
def get_cctv_stats(current_user: User = Depends(get_current_user)):
    """Overall CCTV stats — cameras online, alert breakdown."""
    return cctv_manager.get_stats()

@app.post("/cctv/stop-all")
def stop_all_cameras(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Stop all cameras."""
    result = cctv_manager.stop_all()
    log_to_db(db, "INFO", "CCTV", f"All cameras stopped by {current_user.username}")
    return result


# ─────────────────────────────────────────────
#  UNIFIED DASHBOARD SUMMARY
#  Single endpoint that returns everything
#  the dashboard needs in one call.
# ─────────────────────────────────────────────
@app.get("/dashboard/summary")
def dashboard_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Returns a unified summary for the dashboard.
    One call instead of many — faster dashboard load.
    """
    # Latest scan
    latest_scan = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).first()
    scan_stats  = None
    scans       = db.query(ScanResult).all()
    if scans:
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
        for s in scans:
            risk_counts[s.overall_risk] = risk_counts.get(s.overall_risk, 0) + 1
        scan_stats = {"total": len(scans), "risk_breakdown": risk_counts}

    return {
        "timestamp":    datetime.datetime.now().isoformat(),
        "system":       "SafeNet Ghana v0.5.0",
        "vuln_scanner": {
            "latest_risk": latest_scan.overall_risk if latest_scan else None,
            "latest_target": latest_scan.target if latest_scan else None,
            "stats": scan_stats,
        },
        "wifi_ids": wifi_ids.get_status(),
        "cctv":     cctv_manager.get_stats(),
        "recent_alerts": {
            "wifi": wifi_ids.get_alerts(limit=5),
            "cctv": cctv_manager.get_all_alerts(limit=5),
        },
    }


# ─────────────────────────────────────────────
#  SYSTEM LOGS
# ─────────────────────────────────────────────
@app.get("/logs")
def get_logs(limit: int = 100, current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    logs = db.query(SystemLog).order_by(SystemLog.timestamp.desc()).limit(limit).all()
    return {"total": len(logs), "logs": [{"id": l.id, "level": l.level, "source": l.source, "message": l.message, "timestamp": l.timestamp.isoformat()} for l in logs]}


# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("""
  ╔══════════════════════════════════════╗
  ║   SafeNet Ghana API v0.5.0           ║
  ║   http://127.0.0.1:8000             ║
  ║   Module 1: Vuln Scanner    LIVE    ║
  ║   Module 2: WiFi IDS        LIVE    ║
  ║   Module 3: CCTV Monitor    LIVE    ║
  ║   PostgreSQL                LIVE    ║
  ║   JWT Auth                  LIVE    ║
  ╚══════════════════════════════════════╝
    """)
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
