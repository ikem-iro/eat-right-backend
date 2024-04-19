from pydantic import EmailStr
from sqlmodel import Field, SQLModel

class ContactUs(SQLModel):
    full_name: str
    email: str
    subject: str
    message: str


