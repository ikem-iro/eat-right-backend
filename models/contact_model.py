from sqlmodel import SQLModel

class ContactUs(SQLModel):
    full_name: str
    email: str
    subject: str
    message: str


