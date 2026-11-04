import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from pwdlib import PasswordHash
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import func
from sqlalchemy.orm import Session

from . import models, schemas
from .database import get_db

router = APIRouter(prefix="/auth", tags=["Authentication"])
bearer_scheme = HTTPBearer(auto_error=False)
password_hasher = PasswordHash.recommended()
ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 60


def _secret_key() -> str:
    key = os.getenv("SECRET_KEY")
    if not key or len(key) < 32:
        raise RuntimeError(
            "Set SECRET_KEY in the backend environment to a random value "
            "of at least 32 characters"
        )
    return key


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_hasher.verify(password, password_hash)
    except Exception:
        return False


def create_access_token(user: models.User) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }
    return jwt.encode(payload, _secret_key(), algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if credentials is None:
        raise unauthorized

    try:
        payload = jwt.decode(
            credentials.credentials,
            _secret_key(),
            algorithms=[ALGORITHM],
        )
        subject = payload.get("sub")
        user_id = uuid.UUID(subject)
    except RuntimeError:
        raise
    except (jwt.InvalidTokenError, ValueError, TypeError, AttributeError):
        raise unauthorized

    user = (
        db.query(models.User)
        .filter(
            models.User.id == user_id,
            models.User.is_active.is_(True),
        )
        .first()
    )
    if user is None:
        raise unauthorized

    return user


def get_admin_user(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def _normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 255 or not re.fullmatch(
        r"[^\s@]+@[^\s@]+\.[^\s@]+",
        normalized,
    ):
        raise HTTPException(
            status_code=422,
            detail="Enter a valid email address",
        )
    return normalized


@router.post(
    "/signup",
    response_model=schemas.TokenOut,
    status_code=status.HTTP_201_CREATED,
)
def signup(data: schemas.SignupRequest, db: Session = Depends(get_db)):
    email = _normalize_email(data.email)

    if db.query(models.User).filter(models.User.email == email).first():
        raise HTTPException(
            status_code=409,
            detail="An account with this email already exists",
        )

    user = models.User(
        full_name=data.full_name.strip(),
        email=email,
        password_hash=hash_password(data.password),
        role="user",
        is_active=True,
    )
    db.add(user)

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    db.refresh(user)
    return {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "user": user,
    }


@router.post("/login", response_model=schemas.TokenOut)
def login(data: schemas.LoginRequest, db: Session = Depends(get_db)):
    email = _normalize_email(data.email)
    user = db.query(models.User).filter(models.User.email == email).first()

    if (
        user is None
        or not user.is_active
        or not verify_password(data.password, user.password_hash)
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Record successful login and update the user's last-login timestamp.
    user.last_login_at = datetime.utcnow()
    db.add(models.LoginEvent(user_id=user.id))

    try:
        db.commit()
    except Exception:
        db.rollback()
        raise

    db.refresh(user)
    return {
        "access_token": create_access_token(user),
        "token_type": "bearer",
        "user": user,
    }


@router.get("/me", response_model=schemas.UserOut)
def me(current_user: models.User = Depends(get_current_user)):
    return current_user


@router.get(
    "/admin/users",
    response_model=list[schemas.AdminUserOut],
)
def get_all_users(
    admin: models.User = Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    results = (
        db.query(
            models.User,
            func.count(models.Scan.id).label("scan_count"),
        )
        .outerjoin(models.Scan, models.Scan.user_id == models.User.id)
        .group_by(models.User.id)
        .order_by(models.User.created_at.desc())
        .all()
    )

    return [
        {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "role": user.role,
            "is_active": user.is_active,
            "created_at": user.created_at,
            "last_login_at": user.last_login_at,
            "scan_count": scan_count,
        }
        for user, scan_count in results
    ]


@router.get(
    "/admin/login-history",
    response_model=list[schemas.LoginHistoryOut],
)
def get_login_history(
    admin: models.User = Depends(get_admin_user),
    db: Session = Depends(get_db),
):
    results = (
        db.query(
            models.User.full_name,
            models.User.email,
            models.LoginEvent.logged_in_at,
        )
        .join(
            models.LoginEvent,
            models.LoginEvent.user_id == models.User.id,
        )
        .order_by(models.LoginEvent.logged_in_at.desc())
        .limit(100)
        .all()
    )

    return [
        {
            "full_name": full_name,
            "email": email,
            "logged_in_at": logged_in_at,
        }
        for full_name, email, logged_in_at in results
    ]
