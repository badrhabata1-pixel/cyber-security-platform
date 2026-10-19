import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PORT: int = 8003
    JWT_SECRET: str = "super-shared-secret-key-change-in-production"
    AUTH_DISABLED: bool = True
    USE_MOCKS: bool = True
    LOGS_SERVICE_URL: str = "http://localhost:8002"
    PLATFORM_SERVICE_URL: str = "http://localhost:8000"
    DATABASE_URL: str = "sqlite:///./p3_detection/detection.db"
    
    class Config:
        env_file = "p3_detection/.env"
        extra = "ignore"

settings = Settings()
