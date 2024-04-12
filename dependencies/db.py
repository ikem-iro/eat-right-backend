"""
This module contains database-related utilities and functions.
"""

from typing import Generator
from sqlmodel import Session, create_engine, SQLModel, select
from models.user_model import User

# Database configuration
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

# Create the SQLite engine
engine = create_engine(sqlite_url)

# Create all tables in the database
SQLModel.metadata.create_all(engine)

def get_db() -> Generator[Session, None, None]:
    """
    Get a database session.

    This function creates a new database session and yields it for use in
    other parts of the application. The session is automatically closed
    after the context manager exits.

    Yields:
        Session: A database session instance.
    """
    with Session(engine) as session:
        yield session

def get_user_by_email(*, session: Session, email: str) -> User | None:
    """
    Get a user by email address.

    Args:
        session (Session): The database session instance.
        email (str): The email address of the user.

    Returns:
        User | None: The user object if found, or None if not found.
    """
    statement = select(User).where(User.email == email)
    session_user = session.exec(statement).first()
    return session_user