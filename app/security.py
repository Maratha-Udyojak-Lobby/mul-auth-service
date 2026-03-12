"""JWT token generation and validation."""

import os
from datetime import datetime, timedelta
from typing import Optional
import jwt
from fastapi import HTTPException, status

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "mul-super-secret-key-change-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 60


def create_access_token(user_id: int, username: str, expires_delta: Optional[timedelta] = None) -> str:
    """Create a new JWT access token."""
    if expires_delta is None:
        expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    expire = datetime.utcnow() + expires_delta
    
    payload = {
        "sub": str(user_id),
        "username": username,
        "exp": expire,
        "iat": datetime.utcnow()
    }
    
    encoded_jwt = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str) -> dict:
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        username: str = payload.get("username")
        
        if user_id is None or username is None:
            raise ValueError("Invalid token payload")
        
        return {
            "valid": True,
            "user_id": user_id,
            "username": username,
            "message": "Token is valid"
        }
    except jwt.ExpiredSignatureError:
        return {
            "valid": False,
            "user_id": None,
            "username": None,
            "message": "Token has expired"
        }
    except jwt.InvalidTokenError as e:
        return {
            "valid": False,
            "user_id": None,
            "username": None,
            "message": f"Invalid token: {str(e)}"
        }


def extract_token_from_header(authorization_header: str) -> str:
    """Extract token from Authorization header."""
    if not authorization_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    
    parts = authorization_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header format (expected 'Bearer <token>')"
        )
    
    return parts[1]
