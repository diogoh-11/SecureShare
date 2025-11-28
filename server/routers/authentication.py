from fastapi import APIRouter, HTTPException, Depends, Response, Header, Request
from sqlalchemy.orm import Session
from database import get_db
from services.auth_service import AuthService
from utils.funcs import required

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/activate")
async def activate(request: dict, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    username = request.get("username")
    activation_code = request.get("activation_code")
    password = request.get("password")
    public_key = request.get("public_key")
    private_key_blob = request.get("private_key_blob")

    # invalid request if no username is provided
    required(username,"Username")
    required(activation_code,"Activation code")
    required(password, "Password")
    required(public_key, "Public key")
    required(private_key_blob, "Private key blob")

    result = auth_service.activate(username, password, activation_code, public_key, private_key_blob)

    # check if registration worked
    if not result:
        raise HTTPException(status_code=400, detail="Registration failed")
    return result

@router.post("/login")
async def verify_login(request: dict, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    username = request.get("username")
    password = request.get("password")

    required(username, "Username")
    required(password, "Password")

    result = auth_service.validate(username, password)
    if not result:
        raise HTTPException(status_code=400, detail="Login failed")

    return result

@router.post("/logout")
async def logout(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    auth_service = AuthService(db)

    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization

    result = auth_service.logout(token)

    if not result:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return result

@router.get("/validate")
async def validate_session(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    auth_service = AuthService(db)

    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization

    result = auth_service.validate_session(token)

    if not result:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return result
