"""
SafeNet Ghana - API Server (with PostgreSQL persistence)
All scan results now saved permanently to the database.

Author: Patrick Idan
Project: SafeNet Ghana - GCTU Cybersecurity
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
import datetime

from scanner  import resolve_target, run_scan, analyze_results
from auth     import authenticate_user, create_access_token, get_current_user, require_admin, Token, User, TOKEN_EXPIRE
from database import engine, get_db
from models   import Base, ScanResult, SystemLog

# ─────────────────────────────────────────────
#  CREATE ALL TABLES ON STARTUP
#  If the tables don't exist, SQLAlchemy creates them.
#  If they already exist, nothing happens.
# ─────────────────────────────────────────────
Base.metadata.create_all(bind=engine)

# ─────────────────────────────────────────────
#  APP SETUP
# ─────────────────────────────────────────────
app = FastAPI(
    title="SafeNet Ghana API",
    description="Affordable integrated security system for Ghanaian small businesses.",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────
#  REQUEST MODELS
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    target:    str
    scan_type: str = "basic"


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
def log_to_db(db: Session, level: str, source: str, message: str):
    """Save a system log entry to the database."""
    try:
        entry = SystemLog(level=level, source=source, message=message)
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()


# ─────────────────────────────────────────────
#  PUBLIC ROUTES
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "system":  "SafeNet Ghana",
        "version": "0.3.0",
        "status":  "online",
        "author":  "Patrick Idan - GCTU Cybersecurity",
        "modules": ["vulnerability-scanner", "wifi-ids (coming)", "cctv-monitor (coming)"],
    }


@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.datetime.now().isoformat()}


# ─────────────────────────────────────────────
#  AUTH ROUTES
# ─────────────────────────────────────────────
@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        log_to_db(db, "WARNING", "AUTH", f"Failed login attempt for username: {form_data.username}")
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token({"sub": user["username"]})
    log_to_db(db, "INFO", "AUTH", f"Login successful: {user['username']} ({user['role']})")
    print(f"[AUTH] Login successful → {user['username']} ({user['role']})")
    return Token(
        access_token = token,
        token_type   = "bearer",
        username     = user["username"],
        full_name    = user["full_name"],
        role         = user["role"],
        expires_in   = TOKEN_EXPIRE * 60,
    )


@app.get("/auth/me", response_model=User)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# ─────────────────────────────────────────────
#  SCAN ROUTES
# ─────────────────────────────────────────────
@app.post("/scan")
def trigger_scan(
    request: ScanRequest,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    valid_types = ["basic", "version", "full"]
    if request.scan_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid scan_type. Choose: {valid_types}")

    ip = resolve_target(request.target)
    if not ip:
        raise HTTPException(status_code=400, detail=f"Cannot resolve: {request.target}")

    print(f"\n[SCAN] {current_user.username} → target={request.target}, type={request.scan_type}")
    log_to_db(db, "INFO", "VULN", f"Scan started by {current_user.username} on {request.target}")

    try:
        nm     = run_scan(ip, request.scan_type)
        report = analyze_results(nm, request.target)
    except Exception as e:
        log_to_db(db, "ERROR", "VULN", f"Scan failed on {request.target}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    report["scan_metadata"]["scanned_by"] = current_user.username

    # ── Save to PostgreSQL ──────────────────
    summary = report["summary"]
    db_scan = ScanResult(
        target         = request.target,
        scan_type      = request.scan_type,
        scanned_by     = current_user.username,
        overall_risk   = summary["overall_risk"],
        total_hosts    = summary["total_hosts"],
        open_ports     = summary["open_ports"],
        critical_count = summary["critical_count"],
        high_count     = summary["high_count"],
        medium_count   = summary["medium_count"],
        low_count      = summary["low_count"],
        full_report    = report,
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    # ───────────────────────────────────────

    log_to_db(db, "INFO", "VULN", f"Scan complete on {request.target} — risk: {summary['overall_risk']}")
    print(f"[SCAN] Complete → risk={summary['overall_risk']} — saved to DB (id={db_scan.id})")

    return {
        "success": True,
        "message": f"Scan complete. Risk: {summary['overall_risk']}",
        "scan_id": db_scan.id,
        "data":    report,
    }


@app.get("/scans/history")
def get_history(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Returns scan history from PostgreSQL.
    Results persist across server restarts.
    """
    scans = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).limit(limit).all()
    return {
        "total": len(scans),
        "scans": [
            {
                "id":         s.id,
                "target":     s.target,
                "scan_type":  s.scan_type,
                "timestamp":  s.timestamp.isoformat(),
                "risk":       s.overall_risk,
                "open_ports": s.open_ports,
                "scanned_by": s.scanned_by,
            }
            for s in scans
        ],
    }


@app.get("/scans/{scan_id}")
def get_scan(
    scan_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch a specific scan by ID — returns the full report."""
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
    return scan.full_report


@app.get("/scans/latest")
def get_latest(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(ScanResult).order_by(ScanResult.timestamp.desc()).first()
    if not scan:
        raise HTTPException(status_code=404, detail="No scans yet.")
    return scan.full_report


@app.get("/scans/stats")
def get_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scans = db.query(ScanResult).all()
    if not scans:
        return {"message": "No scans yet.", "stats": {}}

    risk_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    total_ports  = 0
    targets      = []

    for s in scans:
        risk_counts[s.overall_risk] = risk_counts.get(s.overall_risk, 0) + 1
        total_ports += s.open_ports
        targets.append(s.target)

    return {
        "total_scans":       len(scans),
        "total_ports_found": total_ports,
        "risk_breakdown":    risk_counts,
        "targets_scanned":   targets,
    }


@app.get("/logs")
def get_logs(
    limit: int = 100,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """System logs — admin only."""
    logs = db.query(SystemLog).order_by(SystemLog.timestamp.desc()).limit(limit).all()
    return {
        "total": len(logs),
        "logs": [
            {
                "id":        l.id,
                "level":     l.level,
                "source":    l.source,
                "message":   l.message,
                "timestamp": l.timestamp.isoformat(),
            }
            for l in logs
        ],
    }


# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("""
  ╔══════════════════════════════════════╗
  ║   SafeNet Ghana API v0.3.0           ║
  ║   http://127.0.0.1:8000             ║
  ║   PostgreSQL persistence ENABLED    ║
  ║   JWT Authentication ENABLED        ║
  ╚══════════════════════════════════════╝
    """)
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
