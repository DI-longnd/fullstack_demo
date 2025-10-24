# app/security.py
import bcrypt
import hashlib
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlmodel import Session, select
from .database import get_session
from .models import User
import os

from dotenv import load_dotenv
load_dotenv()

# Configuration




SECRET_KEY = os.getenv("SECRET_KEY", "your-default-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing configuration
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="gen_token")



def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a stored hash.
    
    Uses the same SHA256 + bcrypt logic as get_password_hash().
    
    Args:
        plain_password: Plain text password from user login
        hashed_password: Stored bcrypt hash from database
    
    Returns:
        bool: True if password matches, False otherwise
    
    Example:
        >>> hashed = get_password_hash("mypassword")
        >>> verify_password("mypassword", hashed)
        True
        >>> verify_password("wrongpassword", hashed)
        False
    """
    # Step 1: SHA256 hash the input password (same as in get_password_hash)
    password_sha256 = hashlib.sha256(plain_password.encode('utf-8')).hexdigest()
    
    # Step 2: Compare with bcrypt
    try:
        return bcrypt.checkpw(
            password_sha256.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """
    Hash a password using SHA256 + bcrypt.
    
    SHA256 preprocessing ensures the input to bcrypt is always 64 bytes,
    avoiding bcrypt's 72-byte limitation while supporting passwords of any length.
    
    Args:
        password: Plain text password (any length supported)
    
    Returns:
        str: Bcrypt hash string (format: $2b$12$...)
    
    Example:
        >>> hashed = get_password_hash("mypassword123")
        >>> print(hashed)
        $2b$12$abcdef...
    """
    # Step 1: SHA256 hash the password
    # This produces a fixed-length 64-character hex string (256 bits)
    password_sha256 = hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    # Step 2: Bcrypt hash the SHA256 output
    # Using 12 rounds (default, good balance of security/performance)
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_sha256.encode('utf-8'), salt)
    
    # Return as string (bcrypt returns bytes)
    return hashed.decode('utf-8')


async def authenticate_user(
    username: str,
    password: str,
    session: Session = Depends(get_session)
) -> Optional[User]:
    """
    Authenticate a user with username and password.
    
    Args:
        username: User's username
        password: User's plain text password
        session: Database session
    
    Returns:
        Optional[User]: User object if authentication successful, None otherwise
    """
    # Query user by username
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    
    if not user:
        return None
    
    # Verify password
    if not verify_password(password, user.hashed_password):
        return None
    
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token.
    
    Args:
        data: Data to encode in the token (usually {"sub": username})
        expires_delta: Optional custom expiration time
    
    Returns:
        str: Encoded JWT token
    
    Example:
        >>> token = create_access_token({"sub": "john"})
        >>> print(token)
        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    """
    to_encode = data.copy()
    
    # Set expiration time
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    
    # Encode JWT
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: Session = Depends(get_session)
) -> User:
    """
    Get the current authenticated user from JWT token.
    
    This function is used as a FastAPI dependency to protect routes.
    
    Args:
        token: JWT token from Authorization header
        session: Database session
    
    Returns:
        User: The authenticated user object
    
    Raises:
        HTTPException: If token is invalid or user not found
    
    Example:
        @app.get("/me")
        async def get_me(current_user: User = Depends(get_current_user)):
            return current_user
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if username is None:
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
    
    # Query user from database
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()
    
    if user is None:
        raise credentials_exception
    
    return user