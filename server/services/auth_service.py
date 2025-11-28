from sqlalchemy.orm import Session
import os
import time
from utils.funcs import sha256
from utils.jwt_utils import create_access_token, verify_token

from models.models import (
    User,
    RecoveryTokens,
    Organization
)

class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.rp_id =    os.getenv("RP_ID", "localhost")
        self.rp_name =  os.getenv("RP_NAME", "SShare")
        self.origin =   os.getenv("ORIGIN", "https://localhost:8443")
        self.challenge_timeout = 300

    def _validate_code(self, code:str, username) -> tuple[User|None,RecoveryTokens|None]:
        """Validates if code is still valid for user"""

        user:User|None = self.db.query(User).filter(User.username == username).first()
        if not user:
            # user does not exist
            return None,None

        hashed_code = sha256(code)
        token:RecoveryTokens|None = self.db.query(RecoveryTokens).filter(
            RecoveryTokens.user_id == user.id,
            RecoveryTokens.hashed_value == hashed_code,
            RecoveryTokens.is_used == False
        ).first()

        return user, token

    def activate(self, username:str, password:str, activation_code:str, public_key:str, private_key_blob:str):

        user,token = self._validate_code(activation_code,username)
        if not token or not user:
            # check if token is valid
            return None

        # store user password
        user.password_hash = sha256(password)
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
                OrganizationService.finalize_admin_role(self.db, user.id, organization.id)
                print(f"[DEBUG] Granted admin role for organization {organization.id} to user {user.id}")
            except Exception as e:
                print(f"[ERROR] Failed to grant admin role: {e}")
                # Don't fail registration if role assignment fails
                pass


        return {"success": True, "user_id":user.id, "username":username}

    def validate(self, username, password):
        user: User|None = self.db.query(User).filter(User.username == username).first()
        if not user:
            print(f"[ERROR] User not found: {username}")
            return None

        if not user.is_active:
            print(f"[ERROR] User not activated: {username}")
            return None

        if not user.password_hash == sha256(password):
            print(f"Wrong user password for {username}")
            return None

        token_data = {
            "sub": user.id,
            "username": username,
            "organization_id": user.organization_id
        }
        access_token = create_access_token(token_data)

        return {
            "success": True,
            "user_id": user.id,
            "username": username,
            "access_token": access_token,
            "token_type": "bearer"
        }

    def logout(self, token: str):
        payload = verify_token(token)
        if not payload:
            return None

        return {"success": True, "message": "Logged out successfully"}

    def validate_session(self, token: str):
        payload = verify_token(token)
        if not payload:
            return None

        user = self.db.query(User).filter(User.id == payload.get("sub")).first()
        if not user:
            return None

        return {
            "valid": True,
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "organization_id": payload.get("organization_id")
        }
