from sqlalchemy.orm import Session
import os
import time
import json
import secrets
import base64
from utils.funcs import sha256

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from models.models import (
    User,
    RecoveryTokens,
    WebAuthnCredential,
    WebAuthnChallenge,
    Session as SessionModel,
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
        )

        return user, token

    def _cleanup_expired_challenges(self, username: str):
        """Clean up all expired tokens of the user"""
        current_time = int(time.time())

        # filter challenges for this user and remove the expired
        self.db.query(WebAuthnChallenge).filter(
            WebAuthnChallenge.username == username,
            WebAuthnChallenge.expires_at < current_time
        ).delete()

        self.db.commit()

    def generate_registration_challenge(self, username: str, activation_code: str):
        """Generate WebAuth registration options for user"""

        # validate token
        user,token = self._validate_code(activation_code,username)
        #user always exists if token exists but I added here to not have pyright errors
        if not token or not user:
            return None

        self._cleanup_expired_challenges(username)

        existing_credentials = self.db.query(WebAuthnCredential).filter(
            WebAuthnCredential.user_id == user.id
        ).all()

        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=str(user.id),
            user_name=str(user.username),
            exclude_credentials=[
                {"id": cred.id, "transports": cred.transports, "type": "public-key"}
                for cred in existing_credentials
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
                user_verification=UserVerificationRequirement.PREFERRED
            ),
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )

        current_time = int(time.time())
        new_challenge = WebAuthnChallenge(
            username = username,
            challenge= options.challenge,
            expires_at= current_time+self.challenge_timeout,
            challenge_type="registration",
            is_used=False
        )

        self.db.add(new_challenge)
        self.db.commit()

        # return json with options
        return options_to_json(options)

    def complete_registration(self, username: str, credential_data: dict, activation_code:str, origin: str = None):
        """Verify and store WebAuth credential"""
        user,token = self._validate_code(activation_code,username)
        #user always exists if token exists but I added here to not have pyright errors
        if not token or not user:
            print(f"[ERROR] Invalid token or user not found for username: {username}")
            return None

        self._cleanup_expired_challenges(username)

        # get the lattest challenge
        challenge_record = self.db.query(WebAuthnChallenge).filter(
            WebAuthnChallenge.username == username,
            WebAuthnChallenge.challenge_type == "registration",
            WebAuthnChallenge.is_used == False,
        ).order_by(WebAuthnChallenge.expires_at.desc()).first()

        if not challenge_record:
            print(f"[ERROR] No valid challenge found for username: {username}")
            return None

        expected_origin = origin if origin else self.origin

        try:
            credential = RegistrationCredential.parse_raw(json.dumps(credential_data))
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=challenge_record.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=expected_origin,
            )

            print(f"[DEBUG] Verification successful!")
        except Exception as e:
            # Verification failed
            print(f"[ERROR] Verification failed: {type(e).__name__}: {str(e)}")
            return None

        # create new credential
        new_credential = WebAuthnCredential(
            user_id = user.id,
            credential_id = verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )

        self.db.add(new_credential)

        # mark data
        challenge_record.is_used = True
        user.is_active = True
        token.is_used = True

        self.db.commit()

        # Check if this user is designated as admin of an organization
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

        return {"verified": True, "user_id":user.id, "username":username}

    def generate_authentication_challenge(self, username: str):
        """Generate WebAuthn authentication options for a user"""
        user: User|None = self.db.query(User).filter(User.username == username).first()
        if not user:
            print(f"[ERROR] User not found: {username}")
            return None

        if not user.is_active:
            print(f"[ERROR] User not activated: {username}")
            return None

        self._cleanup_expired_challenges(username)

        # Get user's credentials
        credentials = self.db.query(WebAuthnCredential).filter(
            WebAuthnCredential.user_id == user.id
        ).all()

        if not credentials:
            print(f"[ERROR] No credentials found for user: {username}")
            return None

        # Generate authentication options
        options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    type="public-key",
                    id=cred.credential_id,
                    transports=["usb", "nfc", "ble", "internal", "hybrid"]
                )
                for cred in credentials
            ],
            user_verification=UserVerificationRequirement.PREFERRED
        )

        # Store challenge
        current_time = int(time.time())
        new_challenge = WebAuthnChallenge(
            username=username,
            challenge=options.challenge,
            expires_at=current_time + self.challenge_timeout,
            challenge_type="authentication",
            is_used=False
        )

        self.db.add(new_challenge)
        self.db.commit()

        return options_to_json(options)

    def complete_authentication(self, username: str, credential_data: dict, origin: str = None):
        """Verify WebAuthn credential and create session"""
        user: User|None = self.db.query(User).filter(User.username == username).first()
        if not user:
            print(f"[ERROR] User not found: {username}")
            return None

        if not user.is_active:
            print(f"[ERROR] User not activated: {username}")
            return None

        self._cleanup_expired_challenges(username)

        # Get the latest challenge
        challenge_record = self.db.query(WebAuthnChallenge).filter(
            WebAuthnChallenge.username == username,
            WebAuthnChallenge.challenge_type == "authentication",
            WebAuthnChallenge.is_used == False,
        ).order_by(WebAuthnChallenge.expires_at.desc()).first()

        if not challenge_record:
            print(f"[ERROR] No valid authentication challenge found for username: {username}")
            return None

        # Use provided origin or fall back to environment variable
        expected_origin = origin if origin else self.origin

        try:
            print(f"[DEBUG] Authentication credential data received: {json.dumps(credential_data, indent=2)}")
            print(f"[DEBUG] Expected challenge: {challenge_record.challenge}")
            print(f"[DEBUG] Expected RP ID: {self.rp_id}")
            print(f"[DEBUG] Expected origin: {expected_origin}")

            # Get the credential from database
            credential_id_base64 = credential_data.get("rawId") or credential_data.get("id")
            # Decode from base64 to bytes
            try:
                credential_id_bytes = base64.b64decode(credential_id_base64)
            except Exception as e:
                print(f"[ERROR] Failed to decode credential_id from base64: {e}")
                return None

            stored_credential = self.db.query(WebAuthnCredential).filter(
                WebAuthnCredential.user_id == user.id,
                WebAuthnCredential.credential_id == credential_id_bytes
            ).first()

            if not stored_credential:
                print(f"[ERROR] Credential not found for user")
                return None

            credential = AuthenticationCredential.parse_raw(json.dumps(credential_data))
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=challenge_record.challenge,
                expected_rp_id=self.rp_id,
                expected_origin=expected_origin,
                credential_public_key=stored_credential.public_key,
                credential_current_sign_count=stored_credential.sign_count,
            )

            print(f"[DEBUG] Authentication verification successful!")

            # Update sign count
            stored_credential.sign_count = verification.new_sign_count

            # Mark challenge as used
            challenge_record.is_used = True

            # Create session
            session_token = secrets.token_urlsafe(32)
            current_time = int(time.time())
            session_expires = current_time + (24 * 60 * 60)  # 24 hours

            new_session = SessionModel(
                user_id=user.id,
                session_token=session_token,
                expires_at=session_expires
            )

            self.db.add(new_session)
            self.db.commit()

            return {
                "success": True,
                "user_id": user.id,
                "username": username,
                "session_token": session_token
            }

        except Exception as e:
            print(f"[ERROR] Authentication failed: {type(e).__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def logout(self, session_token: str):
        """Invalidate a session"""
        session = self.db.query(SessionModel).filter(
            SessionModel.session_token == session_token
        ).first()

        if not session:
            print(f"[ERROR] Session not found")
            return None

        # delete the session
        self.db.delete(session)
        self.db.commit()

        print(f"[DEBUG] Session logged out successfully")
        return {"success": True, "message": "Logged out successfully"}

    def validate_session(self, session_token: str):
        """Check if a session is valid"""
        current_time = int(time.time())

        session = self.db.query(SessionModel).filter(
            SessionModel.session_token == session_token,
            SessionModel.expires_at > current_time
        ).first()

        if not session:
            return None

        user = self.db.query(User).filter(User.id == session.user_id).first()
        if not user:
            return None

        return {
            "valid": True,
            "user_id": user.id,
            "username": user.username,
            "expires_at": session.expires_at
        }
