"""
SafeNet Ghana - Authentication Engine
Handles user creation, password hashing, and JWT token generation.

Author: Patrick Idan
Project: SafeNet Ghana - GCTU Cybersecurity
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# ─────────────────────────────────────────────
#  CONFIG
#  In production, SECRET_KEY comes from an
#  environment variable, never hardcoded.
# ─────────────────────────────────────────────
SECRET_KEY   = "safenet-ghana-gctu-cybersecurity-2024-patrick-idan"
ALGORITHM    = "HS256"
TOKEN_EXPIRE = 60  # minutes

# ─────────────────────────────────────────────
#  PASSWORD HASHING
#  bcrypt is the industry standard for
#  storing passwords securely.
# ─────────────────────────────────────────────
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

# ─────────────────────────────────────────────
#  DEMO USERS DATABASE
#  Later this moves to PostgreSQL.
#  Passwords are stored as bcrypt hashes,
#  never as plain text.
# ─────────────────────────────────────────────
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

USERS_DB = {
    "admin": {
        "username":        "admin",
        "full_name":       "Patrick Idan",
        "email":           "admin@safenetghana.com",
        "role":            "admin",
        "hashed_password": "$5$rounds=535000$cjb3ACc14fJSx.q8$gHnKkP6Vdln3x65CcVXWIrnQBsvmBb4LeHiJpgFQQ43",
        "disabled":        False,
    },
    "viewer": {
        "username":        "viewer",
        "full_name":       "SafeNet Viewer",
        "email":           "viewer@safenetghana.com",
        "role":            "viewer",
        "hashed_password": "$5$rounds=535000$7zwj0i.pN/bGLlrd$8/Ye5qvkATQHjO9Mv.6jrpCmHWFOt0cGXZVydby/su.",
        "disabled":        False,
    },
}

# ─────────────────────────────────────────────
#  MODELS
# ─────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type:   str
    username:     str
    full_name:    str
    role:         str
    expires_in:   int


class User(BaseModel):
    username:  str
    full_name: str
    email:     str
    role:      str
    disabled:  bool


# ─────────────────────────────────────────────
#  OAUTH2 SCHEME
# ─────────────────────────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


# ─────────────────────────────────────────────
#  CORE FUNCTIONS
# ─────────────────────────────────────────────
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def get_user(username: str) -> Optional[dict]:
    return USERS_DB.get(username)


def authenticate_user(username: str, password: str) -> Optional[dict]:
    user = get_user(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict) -> str:
    payload = data.copy()
    expire  = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRE)
    payload.update({"exp": expire})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload  = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user(username)
    if user is None or user["disabled"]:
        raise credentials_exception

    return User(
        username  = user["username"],
        full_name = user["full_name"],
        email     = user["email"],
        role      = user["role"],
        disabled  = user["disabled"],
    )


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required for this action.",
        )
    return current_user
