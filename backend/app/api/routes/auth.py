"""
Authentication routes: login, token refresh, protected endpoint.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
import logging

from ..deps import (
    authenticate_user, create_access_token,
    get_current_user, get_db, ACCESS_TOKEN_EXPIRE_MINUTES
)
from ...config import settings

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login endpoint - Returns JWT token"""
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        logger.warning(f"❌ Failed login attempt: {form_data.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token_expires = timedelta(minutes=settings.jwt_expire_minutes)
    token = create_access_token(
        data={"sub": user["username"], "role": user.get("role")},
        expires_delta=access_token_expires
    )

    logger.info(f"✅ User logged in: {user['username']}")

    return {
        "access_token": token,
        "token_type": "bearer",
        "user": user["username"],
        "role": user.get("role"),
        "is_first_login": user.get("is_first_login", False),
        "telegram_configured": user.get("telegram_configured", False)
    }


@router.get("/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current authenticated user info"""
    return current_user
