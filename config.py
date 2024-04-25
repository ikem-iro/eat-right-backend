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
    # PORT = 465

    PROJECT_NAME: str = "EAT RIGHT"
    FRONTEND_URL: AnyUrl = "http://localhost:9000/api/v1/"
    EMAIL_RESET_PASSWORD_EXPIRE_MINUTES: int = 10
    EMAILS_FROM_NAME: str = "EAT RIGHT"
    EMAILS_FROM_EMAIL: str = ""


    SMTP_TLS: bool = True
    SMTP_SSL: bool = False
    SMTP_PORT: int = 2525
    SMTP_HOST: str = 'smtp.mailtrap.io'
    SMTP_USER: str = 'b8d6b914ed3f45'
    SMTP_PASSWORD: str = '84a0e3214a45bd'

settings = Settings() 


