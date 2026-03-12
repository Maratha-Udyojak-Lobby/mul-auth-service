from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Optional

from app.database import get_db, init_db
from app.models import (
    User,
    UserRegister,
    UserLogin,
    UserResponse,
    TokenResponse,
    TokenValidateRequest,
    TokenValidateResponse,
)
from app.security import create_access_token, verify_token, extract_token_from_header

# Initialize database tables on startup
init_db()

app = FastAPI(
    title="MUL Auth Service",
    version="1.0.0",
    description="Authentication and user management service",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    init_db()


@app.get("/", summary="Auth Service Root")
async def root() -> dict[str, str]:
    return {"message": "MUL Auth Service is running"}


@app.get("/health", summary="Health Check")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "auth-service"}


@app.post(
    "/auth/register",
    summary="Register New User",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(user_data: UserRegister, db: Session = Depends(get_db)) -> TokenResponse:
    """Register a new user and return a JWT token."""
    try:
        # Check if user already exists
        existing_user = db.query(User).filter(
            (User.username == user_data.username) | (User.email == user_data.email)
        ).first()
        
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username or email already registered"
            )
        
        # Create new user
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name
        )
        new_user.set_password(user_data.password)
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        # Generate token
        access_token = create_access_token(user_id=new_user.id, username=new_user.username)
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            user=UserResponse.model_validate(new_user)
        )
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Registration failed due to database constraint"
        )


@app.post("/auth/login", summary="User Login", response_model=TokenResponse)
async def login(credentials: UserLogin, db: Session = Depends(get_db)) -> TokenResponse:
    """Authenticate a user and return a JWT token."""
    user = db.query(User).filter(User.username == credentials.username).first()
    
    if not user or not user.verify_password(credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    access_token = create_access_token(user_id=user.id, username=user.username)
    
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@app.post("/auth/validate", summary="Validate Token", response_model=TokenValidateResponse)
async def validate_token(request: TokenValidateRequest) -> TokenValidateResponse:
    """Validate a JWT token (called by API Gateway and other services)."""
    result = verify_token(request.token)
    return TokenValidateResponse(**result)


@app.get("/auth/validate", summary="Validate Bearer Token", response_model=TokenValidateResponse)
async def validate_bearer_token(authorization: Optional[str] = Header(None)) -> TokenValidateResponse:
    """Validate a JWT token from Authorization header (for service-to-service calls)."""
    try:
        token = extract_token_from_header(authorization)
        result = verify_token(token)
        return TokenValidateResponse(**result)
    except HTTPException as e:
        return TokenValidateResponse(
            valid=False,
            user_id=None,
            username=None,
            message=e.detail
        )


@app.get("/users/me", summary="Get Current User", response_model=UserResponse)
async def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> UserResponse:
    """Get the current authenticated user's profile."""
    try:
        token = extract_token_from_header(authorization)
        token_data = verify_token(token)
        
        if not token_data["valid"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=token_data["message"]
            )
        
        user = db.query(User).filter(User.id == token_data["user_id"]).first()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return UserResponse.model_validate(user)
    except HTTPException as e:
        raise e


@app.post("/users/{user_id}/activate", summary="Activate User", status_code=status.HTTP_200_OK)
async def activate_user(user_id: int, db: Session = Depends(get_db)) -> dict[str, str]:
    """Activate a user account (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_active = True
    db.commit()
    
    return {"message": f"User {user.username} activated successfully"}
