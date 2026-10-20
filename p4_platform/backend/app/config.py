import os

JWT_SECRET = os.getenv("JWT_SECRET", "dev_jwt_secret_change_in_prod")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./platform.db")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

TELEMETRY_URL = os.getenv("TELEMETRY_URL", "http://localhost:8002/ingest")
TELEMETRY_TIMEOUT = 1.5

CORS_ORIGINS = os.getenv(
    "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
).split(",")
