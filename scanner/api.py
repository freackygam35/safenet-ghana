"""
SafeNet Ghana - API Server
Wraps the vulnerability scanner in a web API.
Your React dashboard and Flutter app will talk to this.

Author: Patrick Idan
Project: SafeNet Ghana Final Year Project - GCTU Cybersecurity
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import datetime
import json
import os

# Import our scanner functions directly
from scanner import resolve_target, run_scan, analyze_results

# ─────────────────────────────────────────────
#  APP SETUP
# ─────────────────────────────────────────────
app = FastAPI(
    title="SafeNet Ghana API",
    description="Affordable integrated security system for Ghanaian small businesses.",
    version="0.1.0",
)

# CORS — allows your React app and Flutter app to call this API
# In production you'll restrict this to your actual domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan history (later this moves to PostgreSQL)
scan_history = []


# ─────────────────────────────────────────────
#  REQUEST / RESPONSE MODELS
#  Pydantic validates incoming JSON automatically
# ─────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str
    scan_type: str = "basic"   # basic | version | full


class ScanResponse(BaseModel):
    success: bool
    message: str
    data: dict = {}


# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────

@app.get("/")
def root():
    """Health check — confirms API is running."""
    return {
        "system":  "SafeNet Ghana",
        "version": "0.1.0",
        "status":  "online",
        "author":  "Patrick Idan - GCTU Cybersecurity",
        "modules": ["vulnerability-scanner", "wifi-ids (coming)", "cctv-monitor (coming)"],
    }


@app.get("/health")
def health():
    """Simple health check for uptime monitoring."""
    return {"status": "ok", "timestamp": datetime.datetime.now().isoformat()}


@app.post("/scan", response_model=ScanResponse)
def trigger_scan(request: ScanRequest):
    """
    Triggers a vulnerability scan against a target.

    Request body:
      { "target": "192.168.1.1", "scan_type": "basic" }

    Returns:
      Full scan report with open ports, severity ratings, and summary.
    """
    # Validate scan type
    valid_types = ["basic", "version", "full"]
    if request.scan_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan_type. Choose from: {valid_types}"
        )

    # Resolve hostname to IP
    ip = resolve_target(request.target)
    if not ip:
        raise HTTPException(
            status_code=400,
            detail=f"Could not resolve target: {request.target}"
        )

    # Run the scan
    print(f"\n[API] Scan triggered → target={request.target}, type={request.scan_type}")
    try:
        nm     = run_scan(ip, request.scan_type)
        report = analyze_results(nm, request.target)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    # Save to history
    scan_history.append(report)

    # Save latest report to file
    with open("scan_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"[API] Scan complete → risk={report['summary']['overall_risk']}")

    return ScanResponse(
        success=True,
        message=f"Scan complete. Overall risk: {report['summary']['overall_risk']}",
        data=report,
    )


@app.get("/scans/history")
def get_history():
    """
    Returns all scans run in this session.
    Later this will query your PostgreSQL database.
    """
    return {
        "total": len(scan_history),
        "scans": [
            {
                "target":    s["scan_metadata"]["target"],
                "timestamp": s["scan_metadata"]["timestamp"],
                "risk":      s["summary"]["overall_risk"],
                "open_ports":s["summary"]["open_ports"],
            }
            for s in scan_history
        ]
    }


@app.get("/scans/latest")
def get_latest():
    """Returns the most recent scan report."""
    if not scan_history:
        raise HTTPException(status_code=404, detail="No scans run yet.")
    return scan_history[-1]


@app.get("/scans/stats")
def get_stats():
    """
    Summary statistics across all scans in this session.
    This feeds your dashboard charts.
    """
    if not scan_history:
        return {"message": "No scans yet.", "stats": {}}

    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    total_ports  = 0
    targets      = []

    for scan in scan_history:
        risk = scan["summary"]["overall_risk"]
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        total_ports += scan["summary"]["open_ports"]
        targets.append(scan["scan_metadata"]["target"])

    return {
        "total_scans":  len(scan_history),
        "total_ports_found": total_ports,
        "risk_breakdown": risk_counts,
        "targets_scanned": targets,
    }


# ─────────────────────────────────────────────
#  RUN THE SERVER
# ─────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    print("""
  ╔══════════════════════════════════════╗
  ║   SafeNet Ghana - API Server         ║
  ║   Running on http://127.0.0.1:8000  ║
  ║   Docs at   http://127.0.0.1:8000/docs
  ╚══════════════════════════════════════╝
    """)

    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)