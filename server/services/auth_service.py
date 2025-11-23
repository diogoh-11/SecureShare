from sqlalchemy.orm import Session
from models.models import User, RecoveryTokens, WebAuthnCredential, WebAuthnChallenge, Session as SessionModel
from utils.funcs import sha256, generate_codes
import secrets
import os
import time
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
)
from fido2 import cbor
from fido2.utils import websafe_decode, websafe_encode

# load configs
SESSION_EXPIRE_HOURS = int(os.getenv("SESSION_EXPIRE_HOURS", "1"))
CHALLENGE_EXPIRE_MINUTES = int(os.getenv("CHALLENGE_EXPIRE_MINUTES", "2"))
RP_ID = os.getenv("FIDO2_RP_ID", "localhost")
RP_NAME = os.getenv("FIDO2_RP_NAME", "SShare")
ORIGIN = os.getenv("FIDO2_ORIGIN", f"https://{RP_ID}:8443")

rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp, attestation="none")

def _encode_webauthn_options(options: dict) -> dict:
    """Convert bytes to base64 strings for JSON serialization"""
    encoded = {}
    for key, value in options.items():
        if isinstance(value, bytes):
            encoded[key] = websafe_encode(value)
        elif isinstance(value, dict):
            encoded[key] = _encode_webauthn_options(value)
        elif isinstance(value, list):
            encoded[key] = [
                _encode_webauthn_options(item) if isinstance(item, dict)
                else websafe_encode(item) if isinstance(item, bytes)
                else item
                for item in value
            ]
        else:
            encoded[key] = value
    return encoded

class AuthService:
    @staticmethod
    def generate_registration_challenge(db: Session, username: str, activation_code: str) -> dict:
        """
        Generate fido2 registration challenge for new credential.
        Args:
            db: session
            username: Username to register credential for
            activation_code: Activation code to validate
        Returns:
            dict with 'options' (WebAuthn PublicKeyCredentialCreationOptions)
        Raises:
            ValueError: If user not found, already activated, or invalid activation code
        """
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise ValueError("User not found")
        if user.is_active:
            raise ValueError("User already activated")
        # Validate activation code before generating challenge
        hashed_activation_code = sha256(activation_code)
        activation_token = db.query(RecoveryTokens).filter(
            RecoveryTokens.user_id == user.id,
            RecoveryTokens.hashed_value == hashed_activation_code,
            RecoveryTokens.is_used == False
        ).first()
        if not activation_token:
            raise ValueError("Invalid or already used activation code")
        user_entity = PublicKeyCredentialUserEntity(
            id=str(user.id).encode('utf-8'),
            name=username,
            display_name=username
        )
        # generate registration options
        registration_data, state = server.register_begin(
            user=user_entity,
            credentials=[],
            user_verification=UserVerificationRequirement.PREFERRED
        )
        # store challenge (convert to bytes if it's a string)
        challenge_bytes = state["challenge"]
        if isinstance(challenge_bytes, str):
            challenge_bytes = websafe_decode(challenge_bytes)
        challenge_record = WebAuthnChallenge(
            username=username,
            challenge=challenge_bytes,
            expires_at=int(time.time()) + (CHALLENGE_EXPIRE_MINUTES * 60),
            challenge_type="registration",
            is_used=False
        )
        db.add(challenge_record)
        db.commit()
        # Encode bytes to base64 for JSON serialization
        encoded_options = _encode_webauthn_options(registration_data)
        return {
            "options": encoded_options,
            "challenge_id": challenge_record.id
        }

    @staticmethod
    def verify_registration(
        db: Session,
        username: str,
        activation_code: str,
        challenge_id: int,
        credential_data: dict,
        public_key: bytes,
        private_key_blob: bytes
    ) -> dict:
        """
        Verify fido2 credential registration and activate user.
        Args:
            db: session
            username: Username
            activation_code: Activation code to validate
            challenge_id: Challenge ID from registration challenge
            credential_data: Attestation response from authenticator
            public_key: User's public key for file encryption
            private_key_blob: Encrypted private key blob
        Returns:
            dict with 'user' and 'recovery_codes'
        Raises:
            ValueError: If verification fails
        """
        # validate challenge
        challenge_record = db.query(WebAuthnChallenge).filter(
            WebAuthnChallenge.id == challenge_id,
            WebAuthnChallenge.username == username,
            WebAuthnChallenge.challenge_type == "registration",
            WebAuthnChallenge.is_used == False
        ).first()
        # validate
        if not challenge_record:
            raise ValueError("Invalid or expired challenge")
        # check if challenge expired
        if int(time.time()) > challenge_record.expires_at:
            raise ValueError("Challenge expired")
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise ValueError("User not found")
        # Validate activation code
        hashed_activation_code = sha256(activation_code)
        activation_token = db.query(RecoveryTokens).filter(
            RecoveryTokens.user_id == user.id,
            RecoveryTokens.hashed_value == hashed_activation_code,
            RecoveryTokens.is_used == False
        ).first()
        if not activation_token:
            raise ValueError("Invalid or already used activation code")
        try:
            # Prepare response object for fido2 library (pass the complete credential structure)
            auth_data = server.register_complete(
                state={"challenge": challenge_record.challenge, "user_verification": "preferred"},
                response=credential_data
            )
            # store credential
            credential = WebAuthnCredential(
                user_id=user.id,
                credential_id=auth_data.credential_data.credential_id,
                public_key=cbor.encode(auth_data.credential_data.public_key),
                sign_count=auth_data.credential_data.sign_count,
                created_at=int(time.time())
            )
            db.add(credential)
            # mark challenge and activation token as used
            challenge_record.is_used = True
            activation_token.is_used = True
            user.is_active = True
            user.public_key = public_key
            user.private_key_blob = private_key_blob
            # TODO: add recovery method and use codes
            # gen recovery codes
            recovery_codes = generate_codes(count=10)
            for code in recovery_codes:
                token = RecoveryTokens(
                    user_id=user.id,
                    hashed_value=sha256(code),
                    is_used=False
                )
                db.add(token)
            db.commit()
            db.refresh(user)
            return {
                'user': user,
                'recovery_codes': recovery_codes
            }
        except Exception as e:
            db.rollback()
            raise ValueError(f"Registration verification failed: {str(e)}")

    @staticmethod
    def generate_auth_challenge(db: Session, username: str) -> dict:
        """
        Generate fido2 authentication challenge.
        Args:
            db: session
            username: user to authenticate
        Returns:
            dict with options
        Raises:
            ValueError: If user not found or no credentials registered
        """
        user = db.query(User).filter(User.username == username).first()
        if not user or not user.is_active:
            raise ValueError("User not found or not activated")
        # Get user's credentials
        credentials = db.query(WebAuthnCredential).filter(
            WebAuthnCredential.user_id == user.id
        ).all()
        if not credentials:
            raise ValueError("No credentials registered")
        # Generate authentication options (library auto-generates allowCredentials from credentials)
        auth_data, state = server.authenticate_begin(
            credentials=[
                cbor.decode(cred.public_key) for cred in credentials
            ],
            user_verification=UserVerificationRequirement.PREFERRED
        )
        # Store challenge (convert to bytes if it's a string)
        challenge_bytes = state["challenge"]
        if isinstance(challenge_bytes, str):
            challenge_bytes = websafe_decode(challenge_bytes)
        challenge_record = WebAuthnChallenge(
            username=username,
            challenge=challenge_bytes,
            expires_at=int(time.time()) + (CHALLENGE_EXPIRE_MINUTES * 60),
            challenge_type="authentication",
            is_used=False
        )
        db.add(challenge_record)
        db.commit()
        # Encode bytes to base64 for JSON serialization
        encoded_options = _encode_webauthn_options(auth_data)
        return {
            "options": encoded_options,
            "challenge_id": challenge_record.id
        }

    @staticmethod
    def verify_authentication(
        db: Session,
        username: str,
        challenge_id: int,
        credential_id: bytes,
        credential_data: dict
    ) -> dict:
        """
        Verify FIDO2 authentication assertion and create session.
        Args:
            db: session
            username: Username
            challenge_id: Challenge ID from auth challenge
            credential_id: Credential ID used for authentication
            credential_data: Assertion response from authenticator
        Returns:
            dict with 'user_id', 'username', 'session_token'
        Raises:
            ValueError: If verification fails or signature counter is invalid
        """
        # validate challenge
        challenge_record = db.query(WebAuthnChallenge).filter(
            WebAuthnChallenge.id == challenge_id,
            WebAuthnChallenge.username == username,
            WebAuthnChallenge.challenge_type == "authentication",
            WebAuthnChallenge.is_used == False
        ).first()
        if not challenge_record:
            raise ValueError("Invalid or expired challenge")
        # check if challenge expired
        if int(time.time()) > challenge_record.expires_at:
            raise ValueError("Challenge expired")
        # get credential
        credential = db.query(WebAuthnCredential).filter(
            WebAuthnCredential.credential_id == credential_id
        ).first()
        if not credential:
            raise ValueError("Credential not found")
        user = db.query(User).filter(User.id == credential.user_id).first()
        if not user or not user.is_active:
            raise ValueError("User not found or inactive")
        try:
            # verify authentication
            credential_obj = cbor.decode(credential.public_key)
            # Prepare response object for fido2 library
            response = {
                "credentialId": credential_id,
                "clientDataJSON": credential_data["clientDataJSON"],
                "authenticatorData": credential_data["authenticatorData"],
                "signature": credential_data["signature"]
            }
            auth_data = server.authenticate_complete(
                state={"challenge": challenge_record.challenge, "user_verification": "preferred"},
                credentials=[credential_obj],
                response=response
            )
            # TODO: validate this
            new_sign_count = auth_data.new_sign_count
            if new_sign_count <= credential.sign_count:
                raise ValueError(
                    "Invalid signature counter!"
                )
            # update info
            credential.sign_count = new_sign_count
            challenge_record.is_used = True
            session_token = secrets.token_urlsafe(32)
            session = SessionModel(
                user_id=user.id,
                session_token=session_token,
                created_at=int(time.time()),
                expires_at=int(time.time()) + (SESSION_EXPIRE_HOURS * 3600)
            )
            db.add(session)
            db.commit()
            return {
                "user_id": user.id,
                "username": user.username,
                "session_token": session_token
            }
        except Exception as e:
            db.rollback()
            raise ValueError(f"Authentication failed: {str(e)}")

    @staticmethod
    def cleanup_expired_challenges(db: Session) -> int:
        """
        Delete expired challenges from database.
        Should be run periodically as a background task.
        Args:
            db: session
        Returns:
            int: Number of challenges deleted
        """
        # delete expired challenges
        count = db.query(WebAuthnChallenge).filter(
            WebAuthnChallenge.expires_at < int(time.time())
        ).delete()
        db.commit()
        return count
