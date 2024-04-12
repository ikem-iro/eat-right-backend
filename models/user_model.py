"""
This module defines the data models for User, UserCreate, and Token.
"""

from sqlmodel import SQLModel, Field, Column, VARCHAR
from pydantic import EmailStr
from typing import Optional

class UserCreate(SQLModel):
    """
    Data model for creating a new user.

    Attributes:
        name (str): Name of the user. Must be between 3 and 50 characters long.
        email (EmailStr): Email address of the user. Must be a valid email format.
        password (str): Password of the user. Must be between 8 and 100 characters long.
    """
    name: str = Field(
        min_length=3,
        max_length=50,
        description="Name of the User",
        schema_extra={'example': "A very nice Item"},
        title="Name"
    )
    email: EmailStr = Field(
        sa_column=Column("email", VARCHAR, unique=True, index=True),
        description="Email of the passenger"
    )
    password: str = Field(
        min_length=8,
        max_length=100,
        description="Password of the passenger",
        title="Password"
    )

class User(UserCreate, table=True):
    """
    Data model for a user.

    Inherits from UserCreate and adds an id field.

    Attributes:
        id (Optional[int]): Unique identifier for the user.
    """
    id: Optional[int] = Field(default=None, primary_key=True)

class Token(SQLModel):
    """
    Data model for an authentication token.

    Attributes:
        access_token (str): The access token string.
        token_type (str): The type of token (default: "bearer").
    """
    access_token: str
    token_type: str = "bearer"