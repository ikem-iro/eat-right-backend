from sqlmodel import Session, create_engine, SQLModel, select
from models.user_model import User 



sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"


engine = create_engine(sqlite_url)



SQLModel.metadata.create_all(engine)


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
