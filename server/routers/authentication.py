from fastapi import APIRouter, HTTPException, Depends, Response, Header, Request
from sqlalchemy.orm import Session
from database import get_db
from services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/activate")
async def activate(request: dict, req: Request, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    username = request.get("username")
    activation_code = request.get("activation_code")

    # invalid request if no username is provided
    if not username:
        raise HTTPException(status_code=400, detail="Username required")
    if not activation_code:
        raise HTTPException(status_code=400, detail="Activation code required")

    # get origin
    origin = f"{req.url.scheme}://{req.headers.get('host')}"

    result = auth_service.complete_registration(username, request, activation_code, origin)

    # check if registration worked
    if not result:
        raise HTTPException(status_code=400, detail="Registration failed")
    return result

@router.post("/login")
async def verify_login(request: dict, req: Request, response: Response, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    username = request.get("username")

    # invalid request if no username is provided
    if not username:
        raise HTTPException(status_code=400, detail="Username required")

    # Get origin from request
    origin = f"{req.url.scheme}://{req.headers.get('host')}"

    result = auth_service.complete_authentication(username, request, origin)
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

# TODO: ask professor if can add more endpoints - vcnt
@router.get("/activate/challenge")
async def get_registration_challenge(username: str, activation_code: str, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    return auth_service.generate_registration_challenge(username,activation_code)

@router.get("/login/challenge")
async def get_login_challenge(username: str, db: Session = Depends(get_db)):
    auth_service = AuthService(db)
    return auth_service.generate_authentication_challenge(username)

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
