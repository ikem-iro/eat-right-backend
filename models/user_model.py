from sqlmodel import SQLModel, Field, Column, VARCHAR, JSON
from pydantic import BaseModel, EmailStr, validator
import re
from enum import Enum
from datetime import datetime
from typing import List


class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"


class UserCreate(SQLModel):
    first_name: str = Field(
        min_length=2,
        max_length=50,
        description="First Name of the User",
        title="First Name"
    )
    last_name: str = Field(
        min_length=2,
        max_length=50,
        description="Last Name of the User",
        title="Last Name"
    )
    email: EmailStr = Field(
        sa_column=Column("email", VARCHAR, unique=True, index=True),
        description="Email of the user"
    )
    password: str = Field(
        min_length=8,
        max_length=100,
        description="Password of the user",
        title="Password"
    )
    _regex_password = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    )


class UserLogin(BaseModel):
    email: EmailStr
    password: str


@validator("password")
def validate_password(cls, v):
    if not cls._regex_password.match(v):
        raise ValueError(
            "Password must be at least 8 characters long and contain at least one number, one uppercase letter, one lowercase letter, and one special character")
    return v


class User(UserCreate, table=True):
    id: int = Field(primary_key=True)
    is_email_verified: bool = Field(default=False)
    verification_token: str = Field(default="")
    last_active_date: datetime = Field(default_factory=datetime.utcnow)


class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(SQLModel):
    sub: int | None = None


class ForgetPasswordRequest(BaseModel):
    email: EmailStr


class ResestForgetPassword(BaseModel):
    token: str
    new_password: str


class SuccessMessage(BaseModel):
    success: bool
    status_coode: int
    message: str


class Prompt(BaseModel):
    text: str


class Message(SQLModel):
    message: str


class NewPassword(SQLModel):
    token: str
    new_password: str


class UserOutput(SQLModel):
    id: int
    name: str
    email: EmailStr


class ChatHistory(SQLModel, table=True):
    id: int = Field(primary_key=True)
    messages: str
    user_id: int  # Foreign key to the User table
    response: str
    created_at: datetime = Field(default_factory=datetime.now, nullable=False)
