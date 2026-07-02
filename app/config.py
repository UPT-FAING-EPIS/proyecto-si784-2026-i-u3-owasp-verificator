from functools import lru_cache
from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()


class Settings(BaseModel):
    app_title: str = os.getenv("APP_TITLE", "OWASP Verificator")
    app_env: str = os.getenv("APP_ENV", "development")


@lru_cache
def get_settings() -> Settings:
    return Settings()
