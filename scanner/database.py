"""
SafeNet Ghana - Database Connection
Sets up SQLAlchemy connection to PostgreSQL.

Author: Patrick Idan
Project: SafeNet Ghana - GCTU Cybersecurity
"""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# ─────────────────────────────────────────────
#  DATABASE URL
#  Format: postgresql://user:password@host:port/database
#  In production this comes from an environment variable.
# ─────────────────────────────────────────────
DATABASE_URL = "postgresql://postgres:safenet123@localhost:5432/safenet_ghana"

# ─────────────────────────────────────────────
#  ENGINE
#  The engine is the core connection to PostgreSQL.
# ─────────────────────────────────────────────
engine = create_engine(DATABASE_URL)

# ─────────────────────────────────────────────
#  SESSION
#  Every API request gets its own session.
#  The session is closed after the request finishes.
# ─────────────────────────────────────────────
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ─────────────────────────────────────────────
#  BASE
#  All models inherit from this base class.
# ─────────────────────────────────────────────
Base = declarative_base()


def get_db():
    """
    Dependency injected into routes that need database access.
    FastAPI calls this automatically and closes the session after.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
