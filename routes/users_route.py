from fastapi import APIRouter
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from config import ACCESS_TOKEN_EXPIRE_MINUTES
from dependencies.db import get_db
from models.user_model import UserCreate, User, Token
from typing import Annotated
from fastapi.security import OAuth2PasswordRequestForm
from utils import get_password_hash, create_access_token
from datetime import timedelta
from utils import authenticate

router = APIRouter()

@router.post("/register", tags=["login"])
async def register(
    user: UserCreate,
    db: Annotated[Session, Depends(get_db)]
):
    """
    Registers a new user.

    Args:
        user (UserCreate): The user data to be registered.
        db (Session): The database session instance.

    Returns:
        UserCreate: The registered user data.
    """
    
    """
    Hash the password
    """
    user.password = get_password_hash(user.password)
    new_user = User(**user.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return user

@router.post("/login", tags=["login"])
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)]
):
    """
    Authenticates a user and generates an access token.

    Args:
        form_data (OAuth2PasswordRequestForm): The user's email and password.
        db (Session): The database session instance.

    Returns:
        Token: The access token for the authenticated user.

    Raises:
        HTTPException: If the email or password is incorrect.
    """
   
    """
    Get user by email
    """
    user = authenticate(session=db, email=form_data.username, password=form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(
        access_token=create_access_token(
            user.id, expires_delta=access_token_expires
        )
    )