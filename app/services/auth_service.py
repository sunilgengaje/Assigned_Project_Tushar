
from datetime import datetime, timedelta, time
from app.core.security import hash_password, verify_password, create_access_token
from app.models.manage_aggregator import ManageAggregator

class AuthService:

    def logout(self, db, username):
        user = db.query(ManageAggregator).filter(ManageAggregator.email == username).first()
        if not user:
            return {"error": "User not found", "error_code": "USER_NOT_FOUND"}
        user.is_logged_in = 'N'
        db.commit()
        return {"success": True}

    def register(self, db, username, email, password):
        import json
        if db.query(ManageAggregator).filter(ManageAggregator.email == email).first():
            return {"error": "User already exists (email)", "error_code": "USER_EXISTS"}
        hashed = hash_password(password)
        user = ManageAggregator(
            aggregatorName=username,  # or set as needed
            contactPersonName=username,  # or set as needed
            email=email,
            password=hashed,
            password_history=json.dumps([hashed]),
            is_logged_in='N',
            failed_login_attempts=0,
            lockout_until=None,
            mobileNo='',
            location='',
            services='',
            isDeleted=False,
            status='Created'
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"user": user}

    def login(self, db, username, password):
        from datetime import datetime, timedelta, time
        user = db.query(ManageAggregator).filter(ManageAggregator.email == username).first()
        now = datetime.utcnow()
        if user and user.lockout_until:
            lockout_time = None
            try:
                lockout_time = datetime.fromisoformat(user.lockout_until)
            except Exception:
                return {"error": f"Account locked until {user.lockout_until}", "error_code": "ACCOUNT_LOCKED"}
            if now < lockout_time:
                return {"error": f"Account locked until {user.lockout_until}", "error_code": "ACCOUNT_LOCKED"}
        stored_password = user.password if user else None
        if user:
            try:
                verify_result = verify_password(password, stored_password)
            except Exception as e:
                verify_result = False
        else:
            verify_result = False
        if not user or not verify_result:
            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= 3:
                    tomorrow = now.date() + timedelta(days=1)
                    midnight = datetime.combine(tomorrow, time(0, 0))
                    user.lockout_until = midnight.isoformat()
                    db.commit()
                    return {"error": f"Account locked due to 3 failed attempts. Try after {user.lockout_until}", "error_code": "ACCOUNT_LOCKED"}
                db.commit()
            return {"error": "Invalid credentials", "error_code": "INVALID_CREDENTIALS"}
        user.failed_login_attempts = 0
        user.lockout_until = None
        if user.is_logged_in == 'Y':
            return {"already_logged_in": True, "message": "User is already logged in from another session."}
        user.is_logged_in = 'Y'
        db.commit()
        return {"access_token": create_access_token({"sub": user.email})}

    def unlock_user(self, db, username):
        user = db.query(ManageAggregator).filter(ManageAggregator.email == username).first()
        if not user:
            return {"error": "User not found", "error_code": "USER_NOT_FOUND"}
        user.failed_login_attempts = 0
        user.lockout_until = None
        db.commit()
        return {"success": True}

    def reset_password(self, db, username, email, old_password, new_password):
        import json
        user = None
        if username:
            user = db.query(ManageAggregator).filter(ManageAggregator.email == username).first()
        elif email:
            user = db.query(ManageAggregator).filter(ManageAggregator.email == email).first()
        if not user:
            return {"error": "User not found", "error_code": "USER_NOT_FOUND"}
        stored_password = user.password if user.password else None
        if not verify_password(old_password, stored_password):
            return {"error": "Old password is incorrect", "error_code": "INCORRECT_OLD_PASSWORD"}
        try:
            history = json.loads(user.password_history)
        except Exception:
            history = []
        last_3_hashes = history[-3:] if len(history) >= 3 else history
        for old_hash in last_3_hashes:
            if verify_password(new_password, old_hash):
                return {"error": "New password must not match any of the last 3 passwords.", "error_code": "PASSWORD_REUSE"}
        new_hashed = hash_password(new_password)
        history.append(new_hashed)
        if len(history) > 3:
            history = history[-3:]
        user.password = new_hashed
        user.password_history = json.dumps(history)
        db.commit()
        return {"success": True}
