"""
This module contains utility functions for authentication and password handling.
"""

from datetime import datetime, timedelta
from typing import Any
from config import settings
from pydantic import ValidationError
from jose import jwt, JWTError
from models.user_model import TokenData, User
from passlib.context import CryptContext
from dependencies.db import get_user_by_email
from sqlmodel import Session
from fastapi import HTTPException, status
from models.user_model import User  
from models.review_model import Review, ReviewCreate
import emails
from jinja2 import Template
from sqlmodel import select
from dataclasses import dataclass
from pathlib import Path
# Initialize the password context for hashing and verifying passwords
pwd_context = CryptContext(schemes=['bcrypt'], deprecated="auto")

def create_access_token(subject: str | Any, expires_delta: timedelta) -> str:
    """
    The function `create_access_token` generates a JWT access token with a specified subject and
    expiration time.
    
    :param subject: The `subject` parameter in the `create_access_token` function is typically a string
    representing the subject of the access token. This could be a user ID, username, or any other
    identifier that helps identify the entity for which the token is being generated
    :type subject: str | Any
    :param expires_delta: The `expires_delta` parameter specifies the duration for which the access
    token will be valid. It is a `timedelta` object representing the time interval after which the token
    will expire
    :type expires_delta: timedelta
    :return: The function `create_access_token` returns an encoded JSON Web Token (JWT) as a string.
    """
    expire = datetime.utcnow() + expires_delta
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def get_password_hash(password: str) -> str:
    """
    The function `get_password_hash` takes a password as input and returns its hashed value.
    
    :param password: The `get_password_hash` function takes a password as a string input and returns the
    hashed version of the password using the `pwd_context` object. This function is likely used for
    securely storing passwords by hashing them before saving them in a database
    :type password: str
    :return: A hashed version of the input password is being returned.
    """
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    The function `verify_password` compares a plain text password with a hashed password to determine if
    they match.
    
    :param plain_password: The `plain_password` parameter is the password entered by the user in plain
    text, before it is hashed for security purposes
    :type plain_password: str
    :param hashed_password: The `hashed_password` parameter is the password that has been previously
    hashed using a cryptographic hashing algorithm. This hashed password is stored in the database or
    elsewhere for security reasons instead of storing the plain text password directly
    :type hashed_password: str
    :return: a boolean value, indicating whether the plain password matches the hashed password after
    verification.
    """
    return pwd_context.verify(plain_password, hashed_password)

def create_token(subject: str | Any, type_ops: str):
    if type_ops == "verify":
        hours = settings.EMAIL_VERIFY_EMAIL_EXPIRE_MINUTES
    elif type_ops == "reset":
        hours = settings.EMAIL_RESET_PASSWORD_EXPIRE_MINUTES
    elif type_ops == "access":
        hours = settings.ACCESS_TOKEN_EXPIRE_MINUTES

    expire = datetime.utcnow() + timedelta(
        hours=hours
    )
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt

def verify_token_access(token: str):
    """
    The function `verify_token_access` decodes a JWT token using a secret key and algorithm, and returns
    the token data if valid, otherwise raises a 403 Forbidden HTTPException.
    
    :param token: The `token` parameter is a string that represents a JWT (JSON Web Token) that needs to
    be decoded and verified for access. The `verify_token_access` function attempts to decode the token
    using the provided `SECRET_KEY` and `ALGORITHM` from the settings. If the decoding is successful
    :type token: str
    :return: The function `verify_token_access` is returning the `token_data` object after decoding the
    token and validating its payload.
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=settings.ALGORITHM)
        token_data = TokenData(**payload)
    except (JWTError, ValidationError) as e:
        print(e)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    return token_data

def authenticate(*, session: Session, email: str, password: str) -> User | None:
    """
    The function `authenticate` takes in a session, email, and password, retrieves a user from the
    database by email, verifies the password, and returns the user if authentication is successful.
    
    :param session: The `session` parameter is of type `Session` and is used to interact with the
    database session. It is likely being passed to the `get_user_by_email` function to retrieve a user
    from the database based on the provided email address
    :type session: Session
    :param email: The `email` parameter is a string that represents the email address of the user trying
    to authenticate
    :type email: str
    :param password: The `password` parameter in the `authenticate` function represents the password
    input provided by the user trying to authenticate. This password will be compared with the hashed
    password stored in the database for the user with the corresponding email address to verify the
    user's identity
    :type password: str
    :return: The function `authenticate` is returning either a `User` object if the email and password
    match a user in the database, or `None` if the user is not found or the password is incorrect.
    """
    db_user = get_user_by_email(session=session, email=email)
    if not db_user:
        return None
    if not verify_password(password, db_user.password):
        return None
    return db_user


def create_review(db: Session, review: ReviewCreate) -> Review:
    """
    The function `create_review` takes a database session and a review object, creates a new review in
    the database, and returns the created review.
    
    :param db: The `db` parameter in the `create_review` function is expected to be an instance of a
    database session. This session is used to interact with the database, such as adding, committing,
    and refreshing objects
    :type db: Session
    :param review: The `create_review` function takes two parameters:
    :type review: ReviewCreate
    :return: The function `create_review` returns the newly created review object after adding it to the
    database.
    """
    db_review = Review(**review.dict())
    db.add(db_review)
    db.commit()
    db.refresh(db_review)
    return db_review

def get_review(db: Session, review_id: int) -> Review | None:
    """
    This function retrieves a review from a database based on the provided review ID.
    
    :param db: The `db` parameter is of type `Session`, which is likely referring to a database session
    object used for interacting with the database. It is used to query the database to retrieve a
    specific review based on the provided `review_id`
    :type db: Session
    :param review_id: The `review_id` parameter is an integer that represents the unique identifier of a
    review in the database
    :type review_id: int
    :return: The function `get_review` is returning a `Review` object or `None` if no review with the
    specified `review_id` is found in the database.
    """
    return db.query(Review).filter(Review.id == review_id).first()

def get_reviews_by_user(db: Session, user_id: int) -> list[Review]:
    """
    This function retrieves all reviews associated with a specific user from the database.
    
    :param db: The `db` parameter is of type `Session`, which is likely an instance of a database
    session that allows you to interact with the database. It is used to query the database for reviews
    based on the provided `user_id`
    :type db: Session
    :param user_id: The `user_id` parameter is an integer that represents the unique identifier of a
    user in the database. This function `get_reviews_by_user` takes two parameters: `db`, which is a
    database session object, and `user_id`, which is the identifier of the user whose reviews we want to
    :type user_id: int
    :return: A list of Review objects that belong to the user with the specified user_id.
    """
    return db.query(Review).filter(Review.user_id == user_id).all()

def update_review(db: Session, review_id: int, review: ReviewCreate) -> Review | None:
    """
    This function updates a review in the database based on the provided review ID and new review data.
    
    :param db: The `db` parameter is of type `Session`, which is likely an instance of a database
    session that allows you to interact with the database. It is used to query and update data in the
    database
    :type db: Session
    :param review_id: The `review_id` parameter is an integer that represents the unique identifier of
    the review that you want to update in the database
    :type review_id: int
    :param review: The `review` parameter in the `update_review` function is of type `ReviewCreate`. It
    is used to update an existing review in the database with the provided `review_id`. The function
    retrieves the existing review from the database based on the `review_id`, updates its attributes
    with the values from
    :type review: ReviewCreate
    :return: The function `update_review` is returning either an instance of `Review` if the review with
    the specified `review_id` exists in the database and is successfully updated, or `None` if the
    review with the specified `review_id` does not exist in the database.
    """
    db_review = db.query(Review).filter(Review.id == review_id).first()
    if db_review:
        for key, value in review.dict(exclude_unset=True).items():
            setattr(db_review, key, value)
        db.commit()
        db.refresh(db_review)
    return db_review

def delete_review(db: Session, review_id: int) -> Review | None:
    """
    The function `delete_review` deletes a review from the database based on the provided review ID.
    
    :param db: The `db` parameter is of type `Session`, which is likely an instance of a database
    session that allows you to interact with the database. It is used to query and delete a review from
    the database based on the provided `review_id`
    :type db: Session
    :param review_id: The `review_id` parameter is an integer that represents the unique identifier of
    the review that you want to delete from the database
    :type review_id: int
    :return: The function `delete_review` is returning the deleted `Review` object if it exists in the
    database, otherwise it returns `None`.
    """
    db_review = db.query(Review).filter(Review.id == review_id).first()
    if db_review:
        db.delete(db_review)
        db.commit()
    return db_review



BLACKLISTED_TOKENS = set()

def revoke_token(token: str):
    """
    The function `revoke_token` adds a given token to a set of blacklisted tokens.
    
    :param token: The `revoke_token` function takes a `token` parameter, which is a string representing
    the token that needs to be revoked. This function adds the token to a set called
    `BLACKLISTED_TOKENS`, indicating that the token is no longer valid or should not be used for
    authentication or authorization
    :type token: str
    """
    BLACKLISTED_TOKENS.add(token)

def is_token_revoked(token: str) -> bool:
    """
    The function `is_token_revoked` checks if a given token is in a list of blacklisted tokens.
    
    :param token: A string representing a token that needs to be checked for revocation
    :type token: str
    :return: A boolean value is being returned, indicating whether the given token is in the list of
    blacklisted tokens.
    """
    return token in BLACKLISTED_TOKENS


def create_reset_password_token(email: str) -> str:
    """
    The function `create_reset_password_token` generates a JWT token with the user's email and
    expiration time for resetting the password.
    
    :param email: Email is a string parameter that represents the email address of the user for whom we
    want to create a reset password token
    :type email: str
    :return: A JWT token for resetting the password is being returned.
    """
    data = {"sub": email, "exp": datetime.utcnow() + timedelta(minutes=10)}
    token = jwt.encode(data, settings.RESET_PASSWORD, algorithm=settings.ALGORITHM)
    return token



   
def decode_reset_password_token(token: str):
    """
    The function `decode_reset_password_token` decodes a reset password token to extract the email
    address associated with it.
    
    :param token: The `token` parameter is a string that represents a reset password token that needs to
    be decoded to extract the email address associated with it
    :type token: str
    :return: The function `decode_reset_password_token` is returning the email address extracted from
    the decoded JWT token payload.
    """
    payload = jwt.decode(token, settings.RESET_PASSWORD, algorithms=settings.ALGORITHM)
    email: str = payload["sub"]
    return email
   

def send_email(email_to: str, subject: str, html_content: str):
    message = emails.Message(
        subject=subject, html=html_content, mail_from=settings.EMAILS_FROM_NAME
    )
    smtp_options = {
        "host": settings.SMTP_HOST,
        "port": settings.SMTP_PORT,
        "user": settings.SMTP_USER,
        "password": settings.SMTP_PASSWORD,
    }
    if settings.SMTP_TLS:
        smtp_options["tls"] = True
    elif settings.SMTP_SSL:
        smtp_options["ssl"] = True
    response = message.send(to=email_to, smtp=smtp_options)




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



def verify_token(token: str) -> str | None:
    try:
        decoded_token = jwt.decode(
            token, settings.SECRET_KEY, algorithms=settings.ALGORITHM
        )  # noqa
        print(decoded_token, "decoded_token")
        return str(decoded_token["sub"])
    except JWTError:
        return None


@dataclass
class EmailData:
    html_content: str
    subject: str


def render_email_template(*, template_name: str, context: dict[str, Any]) -> str:
    template_str = (
        Path(__file__).parent / "email-templates" / "build" / template_name
    ).read_text()
    html_content = Template(template_str).render(context)
    return html_content


def generate_reset_password_email(email_to: str, email: str, token: str):
    project_name = settings.PROJECT_NAME
    subject = f"{project_name} - Password recovery for user {email}"
    link = f"{settings.FRONTEND_URL}reset-password?token={token}"

    html_content = render_email_template(
        template_name="reset_password.html",
        context={
            "project_name": settings.PROJECT_NAME,
            "username": email,
            "email": email_to,
            "valid_hours": settings.EMAIL_RESET_PASSWORD_EXPIRE_MINUTES,
            "link": link,
        },
    )
    return EmailData(html_content=html_content, subject=subject)

