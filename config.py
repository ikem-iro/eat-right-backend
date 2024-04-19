import secrets
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    API_V1_STR: str = "/api/v1"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 
    RESET_PASSWORD: str = secrets.token_urlsafe(32)

settings = Settings() 