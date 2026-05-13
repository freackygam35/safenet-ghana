"""
SafeNet Ghana - API Server (with JWT Authentication)
All scan endpoints are now protected. You must log in to use them.

Author: Patrick Idan
Project: SafeNet Ghana - GCTU Cybersecurity
"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
import datetime
import json

from scanner import resolve_target, run_scan, analyze_results
from auth import (
    authenticate_user, create_access_token,
    get_current_user, require_admin,
    Token, User, TOKEN_EXPIRE
)

# ─────────────────────────────────────────────
#  APP SETUP
# ─────────────────────────────────────────────
app = FastAPI(
    title="SafeNet Ghana API",
    description="Affordable integrated security system for Ghanaian small businesses.",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_history = []


# ─────────────────────────────────────────────
#  REQUEST MODELS
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    target:    str
    scan_type: str = "basic"


# ─────────────────────────────────────────────
#  PUBLIC ROUTES (no token needed)
# ─────────────────────────────────────────────
@app.get("/")
def root():
    return {
        "system":  "SafeNet Ghana",
        "version": "0.2.0",
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
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login endpoint. Returns a JWT token on success.
    The React app stores this token and sends it with every request.
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token({"sub": user["username"]})
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
    """Returns the currently logged-in user's profile."""
    return current_user


# ─────────────────────────────────────────────
#  PROTECTED SCAN ROUTES
#  Depends(require_admin) → only admin can scan
#  Depends(get_current_user) → any logged-in user
# ─────────────────────────────────────────────
@app.post("/scan")
def trigger_scan(
    request: ScanRequest,
    current_user: User = Depends(require_admin),   # admin only
):
    """
    Triggers a vulnerability scan. Admin role required.
    The token must be sent in the Authorization header:
    Authorization: Bearer <token>
    """
    valid_types = ["basic", "version", "full"]
    if request.scan_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid scan_type. Choose: {valid_types}")

    ip = resolve_target(request.target)
    if not ip:
        raise HTTPException(status_code=400, detail=f"Cannot resolve: {request.target}")

    print(f"\n[SCAN] {current_user.username} → target={request.target}, type={request.scan_type}")

    try:
        nm     = run_scan(ip, request.scan_type)
        report = analyze_results(nm, request.target)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    # Tag who ran this scan
    report["scan_metadata"]["scanned_by"] = current_user.username
    scan_history.append(report)

    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"[SCAN] Complete → risk={report['summary']['overall_risk']}")

    return {
        "success": True,
        "message": f"Scan complete. Risk: {report['summary']['overall_risk']}",
        "data":    report,
    }


@app.get("/scans/history")
def get_history(current_user: User = Depends(get_current_user)):
    """All scans. Any logged-in user can view."""
    return {
        "total": len(scan_history),
        "scans": [
            {
                "target":     s["scan_metadata"]["target"],
                "timestamp":  s["scan_metadata"]["timestamp"],
                "risk":       s["summary"]["overall_risk"],
                "open_ports": s["summary"]["open_ports"],
                "scanned_by": s["scan_metadata"].get("scanned_by", "unknown"),
            }
            for s in scan_history
        ],
    }


@app.get("/scans/latest")
def get_latest(current_user: User = Depends(get_current_user)):
    if not scan_history:
        raise HTTPException(status_code=404, detail="No scans yet.")
    return scan_history[-1]


@app.get("/scans/stats")
def get_stats(current_user: User = Depends(get_current_user)):
    if not scan_history:
        return {"message": "No scans yet.", "stats": {}}

    risk_counts  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    total_ports  = 0
    targets      = []

    for scan in scan_history:
        risk = scan["summary"]["overall_risk"]
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        total_ports += scan["summary"]["open_ports"]
        targets.append(scan["scan_metadata"]["target"])

    return {
        "total_scans":       len(scan_history),
        "total_ports_found": total_ports,
        "risk_breakdown":    risk_counts,
        "targets_scanned":   targets,
    }


# ─────────────────────────────────────────────
#  RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    print("""
  ╔══════════════════════════════════════╗
  ║   SafeNet Ghana API v0.2.0           ║
  ║   http://127.0.0.1:8000             ║
  ║   Docs: http://127.0.0.1:8000/docs  ║
  ║   JWT Authentication ENABLED        ║
  ╚══════════════════════════════════════╝
    """)
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
