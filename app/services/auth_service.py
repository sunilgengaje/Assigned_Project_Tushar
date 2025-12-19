from app.repositories.user_repository import UserRepository
from app.core.security import hash_password, verify_password, create_access_token
from app.models.user import User

class AuthService:

    def logout(self, db, username):
        user = self.repo.get_by_username(db, username)
        if not user:
            raise Exception("User not found")
        user.is_logged_in = 'N'
        db.commit()
        return True

    def __init__(self):
        self.repo = UserRepository()

    def register(self, db, username, email, password):
        if self.repo.get_by_email(db, email):
            raise Exception("User already exists (email)")
        # Optionally, add a get_by_username check for uniqueness
        hashed = hash_password(password)
        # Initialize password history with the first password
        import json
        user = User(
            username=username,
            email=email,
            password=hashed,
            password_history=json.dumps([hashed])
        )
        return self.repo.create(db, user)

    def login(self, db, username, password):
        user = self.repo.get_by_username(db, username)
        if not user or not verify_password(password, user.password):
            raise Exception("Invalid credentials")
        if user.is_logged_in == 'Y':
            raise Exception("User is already logged in from another session.")
        user.is_logged_in = 'Y'
        db.commit()
        return create_access_token({"sub": user.username})

    def reset_password(self, db, username, email, old_password, new_password):
        import json
        user = None
        if username:
            user = self.repo.get_by_username(db, username)
        elif email:
            user = self.repo.get_by_email(db, email)
        if not user:
            raise Exception("User not found")
        if not verify_password(old_password, user.password):
            raise Exception("Old password is incorrect")
        # Check password history (last 3)
        try:
            history = json.loads(user.password_history)
        except Exception:
            history = []
        # Only check the last 3 passwords
        last_3_hashes = history[-3:] if len(history) >= 3 else history
        for old_hash in last_3_hashes:
            if verify_password(new_password, old_hash):
                raise Exception("New password must not match any of the last 3 passwords.")
        # Update password and history
        new_hashed = hash_password(new_password)
        history.append(new_hashed)
        if len(history) > 3:
            history = history[-3:]
        user.password = new_hashed
        user.password_history = json.dumps(history)
        db.commit()
