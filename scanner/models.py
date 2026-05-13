"""
SafeNet Ghana - Database Models
Defines the tables that get created in PostgreSQL.

Author: Patrick Idan
Project: SafeNet Ghana - GCTU Cybersecurity
"""

from sqlalchemy import Column, Integer, String, DateTime, JSON, Float, Boolean, Text
from sqlalchemy.sql import func
from database import Base


# ─────────────────────────────────────────────
#  SCAN RESULTS TABLE
#  Stores every vulnerability scan permanently.
#  The open_ports and summary fields use JSON
#  so we can store complex nested data easily.
# ─────────────────────────────────────────────
class ScanResult(Base):
    __tablename__ = "scan_results"

    id           = Column(Integer, primary_key=True, index=True)
    target       = Column(String,  nullable=False)
    scan_type    = Column(String,  default="basic")
    scanned_by   = Column(String,  default="unknown")
    timestamp    = Column(DateTime(timezone=True), server_default=func.now())
    overall_risk = Column(String,  default="UNKNOWN")
    total_hosts  = Column(Integer, default=0)
    open_ports   = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count   = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count    = Column(Integer, default=0)
    full_report  = Column(JSON,    nullable=True)   # stores complete scan JSON


# ─────────────────────────────────────────────
#  WIFI ALERTS TABLE
#  Stores WiFi intrusion detection events.
#  Will be populated when Module 2 is built.
# ─────────────────────────────────────────────
class WifiAlert(Base):
    __tablename__ = "wifi_alerts"

    id          = Column(Integer, primary_key=True, index=True)
    alert_type  = Column(String,  nullable=False)
    device_mac  = Column(String,  nullable=True)
    ssid        = Column(String,  nullable=True)
    channel     = Column(Integer, nullable=True)
    detail      = Column(Text,    nullable=True)
    severity    = Column(String,  default="MEDIUM")
    timestamp   = Column(DateTime(timezone=True), server_default=func.now())


# ─────────────────────────────────────────────
#  CCTV ALERTS TABLE
#  Stores CCTV security events.
#  Will be populated when Module 3 is built.
# ─────────────────────────────────────────────
class CctvAlert(Base):
    __tablename__ = "cctv_alerts"

    id          = Column(Integer, primary_key=True, index=True)
    camera_id   = Column(String,  nullable=False)
    alert_type  = Column(String,  nullable=False)
    detail      = Column(Text,    nullable=True)
    severity    = Column(String,  default="MEDIUM")
    timestamp   = Column(DateTime(timezone=True), server_default=func.now())


# ─────────────────────────────────────────────
#  SYSTEM LOGS TABLE
#  General system activity log.
# ─────────────────────────────────────────────
class SystemLog(Base):
    __tablename__ = "system_logs"

    id        = Column(Integer, primary_key=True, index=True)
    level     = Column(String,  default="INFO")   # INFO, WARNING, ERROR
    source    = Column(String,  default="SYSTEM") # VULN, WIFI, CCTV, AUTH
    message   = Column(Text,    nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
