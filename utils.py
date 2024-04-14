"""
This module contains utility functions for authentication and password handling.
"""

from datetime import datetime, timedelta
from typing import Any
from jose import jwt
from config import ALGORITHM, SECRET_KEY
from passlib.context import CryptContext
from dependencies.db import get_user_by_email
from sqlmodel import Session
from models.user_model import User  # Check the module name's case


# Initialize the password context for hashing and verifying passwords
pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

def create_access_token(subject: str | Any, expires_delta: timedelta) -> str:
    """
    Create an access token for a given subject.

    Args:
        subject (str | Any): The subject to be encoded in the token.
        expires_delta (timedelta): The duration after which the token will expire.

    Returns:
        str: The encoded access token.
    """
    expire = datetime.utcnow() + expires_delta
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_password_hash(password: str) -> str:
    """
    Hash a plain-text password using the configured password context.

    Args:
        password (str): The plain-text password to be hashed.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain-text password against a hashed password.

    Args:
        plain_password (str): The plain-text password to be verified.
        hashed_password (str): The hashed password to verify against.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    return pwd_context.verify(plain_password, hashed_password)

def authenticate(*, session: Session, email: str, password: str) -> User | None:
    """
    Authenticate a user by email and password.

    Args:
        session (Session): The database session instance.
        email (str): The email of the user to authenticate.
        password (str): The password of the user to authenticate.

    Returns:
        User | None: The user object if authentication succeeds, None otherwise.
    """
    db_user = get_user_by_email(session=session, email=email)
    if not db_user:
        return None
    if not verify_password(password, db_user.password):
        return None
    return db_user