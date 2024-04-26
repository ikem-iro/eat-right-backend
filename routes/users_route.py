from typing import Annotated, List
from dependencies.deps import get_current_user
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session,select
from config import settings
from dependencies.deps import SessionDep, reusable_oauth2
from models.user_model import (
UserCreate, 
User, 
Token, 
UserLogin, 
Prompt, 
Message, 
NewPassword,
ChatHistory
)

from utils import (
get_password_hash, 
create_access_token, 
authenticate, 
is_token_revoked,
revoke_token, 
send_mail,
create_token,
verify_token,
verify_token_access,
generate_reset_password_email
)

from dependencies.deps import get_db, get_current_user
from datetime import timedelta, datetime
from models.contact_model import ContactUs
from models.review_model import ReviewCreate, Review    
from utils import get_user_by_email
import openai

router = APIRouter(prefix="/api/v1/users")


@router.post("/register", tags=["Authentication"])
async def register(
    user: UserCreate,
    db: SessionDep 
):
    # Hash the password
    user.password = get_password_hash(user.password)
    new_user = User(**user.dict())
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return user

@router.post("/login", tags=["Authentication"])
async def login(

    user_data: UserLogin,
    db: SessionDep 
):
    """
    The `login` function authenticates a user with provided credentials and returns an access token
    along with user details if successful.
    
    :param user_data: The `user_data` parameter in the `login` function represents the data provided by
    the user during the login process. It is of type `UserLogin`, which likely contains the user's email
    and password for authentication
    :type user_data: UserLogin
    :param db: The `db` parameter in the `login` function is of type `SessionDep`, which is likely a
    dependency that provides a database session. This session is used to interact with the database,
    such as querying for user authentication during the login process
    :type db: SessionDep
    :return: The `login` function returns a dictionary containing an access token and user details. The
    access token is generated using the user's ID and expires after a certain duration specified in the
    settings. The user details include the user's ID, first name, and last name.
    """
    user = authenticate(session=db, email=user_data.email, password=user_data.password)
    if not user:
        raise HTTPException(status_code=404, detail=f"Invalid credentials")

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token = Token(
        access_token=create_access_token(
            user.id, expires_delta=access_token_expires
        )
    )
    return {"access_token": token, "details": {"user_id":user.id, "user_firstname": user.first_name, "user_lastname": user.last_name}}



@router.post("/delete-user", tags=["Users"])
async def deleteUser(
    db: SessionDep 
):
 
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    statement = select(User).where(User.last_active_date > thirty_days_ago)
    inactive_users = db.exec(statement).all()
    for inactive_user in inactive_users:
        db.delete(inactive_user)
        db.commit()
    return {"message": "Inactive accounts deleted", "deleted_usernames": inactive_users}



@router.put("/update_activity/", tags=["Users"])
def update_activity(username: str, db: SessionDep):
    user = db.exec(select(User).where(User.username == username)).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.last_active_date = datetime.utcnow()
    user.is_active = True

    db.commit()
    return {"message": "User activity updated"}

@router.post("/contact-us", tags=["Contact"], summary="Submit a contact us request")
async def contact_us(contact: ContactUs):
    # Here you can handle the contact request, such as sending an email or saving it to a database
    # For now, let's just print the received data
    print(f"Received contact request from {contact.full_name} <{contact.email}>")
    print(f"Subject: {contact.subject}")
    print(f"Message: {contact.message}")
    return {"message": "Contact request submitted successfully"}



@router.post("/reviews", tags=["Reviews"], dependencies=[Depends(get_current_user)])
async def create_review(
    review: ReviewCreate,
    db: SessionDep
) -> Review:
    """
    Create a new review.

    Args:
        review (ReviewCreate): The review data.
        db (SessionDep): The database session.

    Returns:
        Review: The created review.
    """
    new_review = Review(**review.dict())
    db.add(new_review)
    db.commit()
    db.refresh(new_review)
    return new_review




# ...

@router.post("/logout", tags=["Authentication"])
async def logout(db: SessionDep, token: str = Depends(reusable_oauth2)):
    """
    Logout the user by revoking the access token.

    Args:
        db (SessionDep): The database session.
        token (str): The access token to be revoked.

    Returns:
        dict: A message indicating successful logout.
    """
    if is_token_revoked(token):
        raise HTTPException(status_code=400, detail="Token has already been revoked")
    
    # Normally, you'd also invalidate refresh tokens, but for simplicity, 
    # let's just invalidate the access token.
    revoke_token(token)
    
    return {"message": "Successfully logged out"}


@router.post("/password-recovery/{email}", tags=["Users"])
async def recover_password(email: str, db: Annotated[Session, Depends(get_db)]):
    "Forgot password flow"
    user = get_user_by_email(session=db, email=email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    password_reset_token = create_token(subject=email, type_ops="reset")

    # create email data
    email_data = generate_reset_password_email(
        email_to=user.email, email=email, token=password_reset_token
    )

    send_mail(
        email_to=user.email,
        subject=email_data.subject,
        html_content=email_data.html_content,
    )
    return Message(message="Password recovery email sent")



@router.post("/reset-password/", tags=["Users"])
def reset_password(
    db: Annotated[Session, Depends(get_db)], body: NewPassword
) -> Message:
    """
    Reset password
    """
    email = verify_token(token=body.token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid token")
    user = get_user_by_email(session=db, email=email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email does not exist in the system.",
        )
    # elif not user.is_active:
    #     raise HTTPException(status_code=400, detail="Inactive user")
    hashed_password = get_password_hash(password=body.new_password)
    user.password = hashed_password
    db.add(user)
    db.commit()
    return Message(message="Password updated successfully")




@router.get("/login/get-current-user", tags=["Users"])
def get_logged_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    Test access token
    """
    return current_user



@router.post("/user_prompt", tags=["Users"])
def user_prompt(text: Prompt, db: Annotated[Session, Depends(get_db)], current_user: Annotated[User, Depends(get_current_user)]):
    openai.api_key = settings.OPENAI_API_KEY
    user_id = current_user.id
    prompt = text.text
    prompt_to_add = ChatHistory(user_id=user_id, messages=prompt, response="user")

    response = openai.chat.completions.create(
        model=settings.MODEL,
        messages=[
            {"role": "system", "content": "You are an AI assistant that will help me recommend meal plans for ulcer sufferers based on seasonal foods in Enugu, Nigeria. Include a variety of foods in the meal plan. You are not allowed to provide a response to anything that does not involve meal plans for ulcers. You can respond to basic greetings."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=1024,
        temperature=0.2
    )
    message = response.choices[0].message.content

    response_from_model = ChatHistory(user_id=user_id, messages=message, response="model")

    db.add(prompt_to_add)
    db.commit()
    db.refresh(prompt_to_add)
    db.add(response_from_model)
    db.commit()
    db.refresh(response_from_model)

    return {"message": message}


@router.get("/get_all_prompts", tags=["Users"])
def get_all_prompts(db: Annotated[Session, Depends(get_db)], current_user: Annotated[User, Depends(get_current_user)]):
    user_id = current_user.id
    prompts = db.query(ChatHistory).filter(ChatHistory.user_id == user_id).all()
    return prompts
