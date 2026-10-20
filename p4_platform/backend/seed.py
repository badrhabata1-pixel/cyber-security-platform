from app.database import SessionLocal, init_db
from app.models import User
from app.security import hash_password

PASSWORD = "Password123!"
USERS = [
    ("admin@test.com", "admin"),
    ("analyst@test.com", "analyst"),
    ("viewer@test.com", "viewer"),
]


def main() -> None:
    init_db()
    db = SessionLocal()
    try:
        for email, role in USERS:
            user = db.query(User).filter(User.email == email).first()
            if user is None:
                db.add(User(email=email, password_hash=hash_password(PASSWORD), role=role))
                print(f"created {email} ({role})")
            else:
                user.password_hash = hash_password(PASSWORD)
                user.role = role
                user.is_active = True
                user.failed_login_attempts = 0
                user.locked_until = None
                print(f"reset   {email} ({role})")
        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    main()
