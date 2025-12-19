
from sqlalchemy.orm import Session
from app.models.user import User


class UserRepository:

    def get_by_email(self, db: Session, email: str):
        return db.query(User).filter(User.email == email).first()

    def get_by_username(self, db: Session, username: str):
        return db.query(User).filter(User.username == username).first()

    # Removed get_by_username_or_email, not needed for username-only login

    def create(self, db: Session, user: User):
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
