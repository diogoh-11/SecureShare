from fastapi import APIRouter, HTTPException, Depends, Response, Header
from sqlalchemy.orm import Session
from database import get_db
from services.auth_service import AuthService
from middlewares.auth_middleware import delete_session
import base64

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/activate")
async def activate(request: dict, db: Session = Depends(get_db)):
    """
    Verify fido2 credential registration and activate user account.
    Request body:
        - username: str
        - activation_code: str
        - challenge_id: int
        - credential_data: dict
        - public_key: str (base64 encryp)
        - private_key_blob: str (base64 encryp)
    Returns:
        - user_id: int
        - username: str
        - recovery_codes: list[str]
    """
    try:
        # Decode base64 credential data to bytes and build complete credential structure
        credential_data = {
            "id": request["credential_data"]["id"],
            "rawId": base64.b64decode(request["credential_data"]["rawId"]),
            "response": {
                "clientDataJSON": base64.b64decode(request["credential_data"]["response"]["clientDataJSON"]),
                "attestationObject": base64.b64decode(request["credential_data"]["response"]["attestationObject"])
            },
            "type": request["credential_data"]["type"]
        }
        # Decode base64 public and private keys to bytes
        result = AuthService.verify_registration(
            db,
            username=request["username"],
            activation_code=request["activation_code"],
            challenge_id=request["challenge_id"],
            credential_data=credential_data,
            public_key=base64.b64decode(request["public_key"]),
            private_key_blob=base64.b64decode(request["private_key_blob"])
        )
        return {
            "user_id": result["user"].id,
            "username": result["user"].username,
            "recovery_codes": result["recovery_codes"]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing required field: {str(e)}")

@router.post("/login")
async def verify_login(request: dict, response: Response, db: Session = Depends(get_db)):
    """
    Verify fido2 authentication assertion and create session.
    Request body:
        - username: str
        - challenge_id: int
        - credential_id: str (base64)
        - credential_data: dict (assertion response from authenticator)
    Returns:
        - user_id: int
        - username: str
        - session_token: str (use in Authorization: Bearer <token>)
    """
    try:
        # Decode base64 credential data to bytes
        credential_data = {
            "clientDataJSON": base64.b64decode(request["credential_data"]["clientDataJSON"]),
            "authenticatorData": base64.b64decode(request["credential_data"]["authenticatorData"]),
            "signature": base64.b64decode(request["credential_data"]["signature"])
        }
        result = AuthService.verify_authentication(
            db,
            username=request["username"],
            challenge_id=request["challenge_id"],
            credential_id=base64.b64decode(request["credential_id"]),
            credential_data=credential_data
        )
        response.set_cookie(
            key="session_token",
            value=result["session_token"],
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=86400
        )
        return {
            "user_id": result["user_id"],
            "username": result["username"],
            "session_token": result["session_token"]
        }
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing required field: {str(e)}")

@router.post("/logout")
async def logout(
    response: Response,
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    """
    Logout current user.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    # delete session from server
    session_token = authorization[7:]
    deleted = delete_session(session_token, db)
    response.delete_cookie(key="session_token")
    if not deleted:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "logged out"}

# TODO: ask professor if can add more endpoints - vcnt
@router.get("/activate/challenge")
async def get_registration_challenge(username: str, activation_code: str, db: Session = Depends(get_db)):
    """
    Generate fido2 registration challenge for new user activation.
    Args:
        username: user(name) :)
        activation_code: Activation code to validate
    Returns:
        WebAuthn PublicKeyCredentialCreationOptions
    """
    try:
        return AuthService.generate_registration_challenge(db, username, activation_code)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/login/challenge")
async def get_login_challenge(username: str, db: Session = Depends(get_db)):
    """
    Generate fido2 authentication challenge.
    Args:
        username: Username to authenticate
    Returns:
        WebAuthn PublicKeyCredentialRequestOptions
    """
    try:
        return AuthService.generate_auth_challenge(db, username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
