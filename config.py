import secrets
from pydantic import AnyUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_ignore_empty=True, extra="ignore")
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    API_V1_STR: str = "/api/v1"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    RESET_PASSWORD: str = secrets.token_urlsafe(32)
    MODEL: str = "gpt-3.5-turbo"
    OPENAI_API_KEY: str 

    PROJECT_NAME: str = "EAT RIGHT"
    FRONTEND_URL: AnyUrl = "http://localhost:9000/api/v1/"
    EMAIL_RESET_PASSWORD_EXPIRE_MINUTES: int = 10
    EMAILS_FROM_NAME: str = "EAT RIGHT"
    EMAILS_FROM_EMAIL: str = ""


    SMTP_PORT: int = 465
    SMTP_ALT_PORT: int = 587
    SMTP_SERVER: str = "smtp.zeptomail.com"
    SMTP_USER: str = "emailapikey"
    SMTP_PASS:str


settings = Settings() 


