from sqlalchemy.orm import Session as DBSession
import os
import time
import bcrypt
import secrets

from models.models import (
    User,
    RecoveryTokens,
    Organization,
    Session
)


class AuthService:
    def __init__(self, db: DBSession):
        self.db = db
        self.rp_id = os.getenv("RP_ID", "localhost")
        self.rp_name = os.getenv("RP_NAME", "SShare")
        self.origin = os.getenv("ORIGIN", "https://localhost:8443")
        self.challenge_timeout = 300

    def _validate_code(self, code: str, username) -> tuple[User | None, RecoveryTokens | None]:
        """Validates if code is still valid for user"""
        from utils.funcs import sha256

        user: User | None = self.db.query(User).filter(
            User.username == username).first()
        if not user:
            # user does not exist
            return None, None

        hashed_code = sha256(code)
        token: RecoveryTokens | None = self.db.query(RecoveryTokens).filter(
            RecoveryTokens.user_id == user.id,
            RecoveryTokens.hashed_value == hashed_code,
            RecoveryTokens.is_used == False
        ).first()

        return user, token

    def activate(self, username: str, password: str, activation_code: str, public_key: str, private_key_blob: str):

        user, token = self._validate_code(activation_code, username)
        if not token or not user:
            # check if token is valid
            return None

        # store user password with bcrypt
        user.password_hash = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()).decode()
        user.is_active = True

        # store cryptographic keys (required)
        user.public_key = public_key.encode('utf-8')
        user.private_key_blob = private_key_blob.encode('utf-8')

        token.is_used = True
        self.db.commit()

        organization = self.db.query(Organization).filter(
            Organization.admin_id == user.id
        ).first()

        if organization:
            # Grant admin role to this user
            from services.organization_service import OrganizationService
            try:
                OrganizationService.finalize_admin_role(
                    self.db, user.id, organization.id)
                print(
                    f"[DEBUG] Granted admin role for organization {organization.id} to user {user.id}")
            except Exception as e:
                print(f"[ERROR] Failed to grant admin role: {e}")
                # Don't fail registration if role assignment fails
                pass

        return {"success": True, "user_id": user.id, "username": username}

    def validate(self, username, password):
        user: User | None = self.db.query(User).filter(
            User.username == username).first()
        if not user:
            print(f"[ERROR] User not found: {username}")
            return None

        if not user.is_active:
            print(f"[ERROR] User not activated: {username}")
            return None

        if not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
            print(f"Wrong user password for {username}")
            return None

        # Generate cryptographically secure session token (64 bytes = 128 hex chars)
        session_token = secrets.token_urlsafe(64)

        # Session expires in 8 hours
        session_expiry = int(time.time()) + (8 * 3600)

        # Create session in database
        session = Session(
            user_id=user.id,
            session_token=session_token,
            created_at=int(time.time()),
            expires_at=session_expiry
        )

        self.db.add(session)
        self.db.commit()

        print(f"[INFO] Created session for user {username} (expires in 8 hours)")

        return {
            "success": True,
            "user_id": user.id,
            "username": username,
            "access_token": session_token,
            "token_type": "bearer"
        }

    def logout(self, token: str):
        # Find and delete the session
        session = self.db.query(Session).filter(
            Session.session_token == token
        ).first()

        if not session:
            return None

        # Delete the session from database
        self.db.delete(session)
        self.db.commit()

        print(f"[INFO] Deleted session for user_id {session.user_id}")

        return {"success": True, "message": "Logged out successfully"}

    def validate_session(self, token: str):
        # Find session in database
        session = self.db.query(Session).filter(
            Session.session_token == token
        ).first()

        if not session:
            return None

        # Check if session is expired
        current_time = int(time.time())
        if session.expires_at < current_time:
            # Session expired, delete it
            self.db.delete(session)
            self.db.commit()
            print(f"[INFO] Deleted expired session for user_id {session.user_id}")
            return None

        # Get user info
        user = self.db.query(User).filter(User.id == session.user_id).first()
        if not user or not user.is_active:
            return None

        return {
            "valid": True,
            "user_id": user.id,
            "username": user.username,
            "organization_id": user.organization_id
        }

    @staticmethod
    def cleanup_expired_sessions(db: DBSession):
        """
        Clean up all expired sessions from database.
        Call this on server startup or periodically.
        """
        current_time = int(time.time())

        expired_sessions = db.query(Session).filter(
            Session.expires_at < current_time
        ).all()

        count = len(expired_sessions)

        for session in expired_sessions:
            db.delete(session)

        db.commit()

        print(f"[INFO] Cleaned up {count} expired sessions")
        return count
