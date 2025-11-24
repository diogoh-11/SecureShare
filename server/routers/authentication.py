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

    # invalid request if no username is provided
    required(username,"Username")
    required(activation_code,"Activation code")
    required(password, "Password")

    result = auth_service.activate(username, password, activation_code)

    # check if registration worked
    if not result:
        raise HTTPException(status_code=400, detail="Registration failed")
    return result

@router.post("/login")
async def verify_login(request: dict, response: Response, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    username = request.get("username")
    password = request.get("password")

    # invalid request if no username is provided
    required(username, "Username")
    required(password, "Password")

    result = auth_service.validate(username, password)
    if not result:
        raise HTTPException(status_code=400, detail="Login failed")

    response.set_cookie(key="session_token", value=result["session_token"], httponly=True, secure=True, samesite="strict")

    return result

@router.post("/logout")
async def logout(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    auth_service = AuthService(db)

    #extract session token
    session_token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization

    result = auth_service.logout(session_token)

    if not result:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    return result

@router.get("/validate")
async def validate_session(
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    auth_service = AuthService(db)

    #extract session token
    session_token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization

    result = auth_service.validate_session(session_token)

    if not result:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    return result
