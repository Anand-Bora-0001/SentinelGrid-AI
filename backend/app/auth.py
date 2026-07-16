from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import logging

from .database import get_db
from .models import User, Organization

logger = logging.getLogger(__name__)

# Security configuration — imported from centralized config
from .config import JWT_SECRET_KEY as SECRET_KEY, JWT_ALGORITHM as ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")  #  REMOVED leading slash

# Generate password hashes
def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)

# In-memory user database with plain passwords (for demo only)
# In production, NEVER store plain passwords
DEMO_USERS = {
    "admin": {"password": "admin123", "role": "admin", "email": "admin@sentinelgrid.local"},
    "analyst": {"password": "analyst123", "role": "analyst", "email": "analyst@sentinelgrid.local"}
}

# Build user database with hashed passwords
fake_users_db = {}
for username, user_info in DEMO_USERS.items():
    fake_users_db[username] = {
        "username": username,
        "password": get_password_hash(user_info["password"]),
        "role": user_info["role"],
        "email": user_info["email"]
    }

logger.info(" Users database initialized with hashed passwords")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)

def ensure_demo_users_in_db(db: Session):
    """Ensure demo users exist in database with proper organization"""
    try:
        # Check if demo organization exists
        demo_org = db.query(Organization).filter(Organization.slug == "demo-org").first()
        
        if not demo_org:
            # Create demo organization
            demo_org = Organization(
                name="Demo Organization",
                slug="demo-org",
                email="demo@sentinelgrid.local"
            )
            db.add(demo_org)
            db.commit()
            db.refresh(demo_org)
            logger.info(" Created demo organization")
        
        # Ensure demo users exist
        for username, user_data in DEMO_USERS.items():
            existing_user = db.query(User).filter(User.username == username).first()
            
            if not existing_user:
                new_user = User(
                    username=username,
                    email=user_data["email"],
                    hashed_password=get_password_hash(user_data["password"]),
                    role=user_data["role"],
                    organization_id=demo_org.id,
                    is_active=True,
                    is_first_login=True,  # Mark as first login for Telegram setup
                    telegram_configured=False
                )
                db.add(new_user)
                logger.info(f" Created demo user: {username}")
        
        db.commit()
        
    except Exception as e:
        logger.error(f"Failed to ensure demo users: {e}")
        db.rollback()

def authenticate_user(username: str, password: str, db: Session = None):
    """Authenticate user - try database first, fallback to in-memory"""
    try:
        if db:
            # Ensure demo users exist in database
            ensure_demo_users_in_db(db)
            
            # Try database authentication
            user = db.query(User).filter(User.username == username).first()
            if user and user.is_active and verify_password(password, user.hashed_password):
                # Update last login
                user.last_login = datetime.now()
                db.commit()
                
                logger.info(f" Database authentication successful: {username}")
                return {
                    "username": user.username,
                    "role": user.role,
                    "email": user.email,
                    "organization_id": user.organization_id,
                    "is_first_login": user.is_first_login,
                    "telegram_configured": user.telegram_configured
                }
    except Exception as e:
        logger.warning(f"Database authentication failed: {e}")
    
    # Fallback to in-memory authentication
    user = fake_users_db.get(username)
    if not user or not verify_password(password, user["password"]):
        logger.warning(f" Failed login attempt: {username}")
        return False
    
    logger.info(f" In-memory authentication successful: {username}")
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Get current user from token"""
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credential_exception
    except JWTError:
        raise credential_exception
    
    # Try database first
    try:
        if db:
            user = db.query(User).filter(User.username == username).first()
            if user and user.is_active:
                return {
                    "username": user.username,
                    "role": user.role,
                    "email": user.email,
                    "organization_id": user.organization_id,
                    "is_first_login": user.is_first_login,
                    "telegram_configured": user.telegram_configured
                }
    except Exception as e:
        logger.warning(f"Database user lookup failed: {e}")
    
    # Fallback to in-memory
    user = fake_users_db.get(username)
    if user is None:
        raise credential_exception
    return user

async def get_admin_user(current_user: dict = Depends(get_current_user)):
    """Verify user is admin"""
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized - Admin access required")
    return current_user
