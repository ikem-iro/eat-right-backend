from sqlmodel import SQLModel, Field, Column, VARCHAR
from pydantic import EmailStr, validator 
from typing import Optional, Annotated
import re

class UserCreate(SQLModel):
    """
    Data model for creating a new user.

    Attributes:
        first_name (str): First name of the user. Must be between 2 and 50 characters long.
        last_name (str): Last name of the user. Must be between 2 and 50 characters long.
        email (EmailStr): Email address of the user. Must be a valid email format.
        date_of_birth (str): Date of birth of the user. Format: YYYY-MM-DD.
        password (str): Password of the user. Must be between 8 and 100 characters long and meet certain complexity criteria.
        confirm_password (str): Confirmation of the user's password.
    """
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
    date_of_birth: str = Field(
        description="Date of Birth of the User",
        title="Date of Birth"
    )
    password: str = Field(
        min_length=8,
        max_length=100,
        description="Password of the user",
        title="Password"
    )
    confirm_password: str = Field(
        min_length=8,
        max_length=100,
        description="Confirmation of the user's password",
        title="Confirm Password"
    )

    _regex_password = re.compile(
        r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    )

@validator("password")
def validate_pasword(cls, v):
    """
    validate password to meet complexity criteria.
    """
    if v != cls.confirm_password:
        raise ValueError("Passwords do not match")
    if not cls._regex_password.match(v):
        raise ValueError("Password must be at least 8 characters long and contain at least one number, one uppercase letter, one lowercase letter, and one special character")
    return v

class User(UserCreate, table=True):
    id: int = Field(primary_key=True)

class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"
