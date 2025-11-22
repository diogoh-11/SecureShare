from fastapi import APIRouter, HTTPException, Depends
from schemas.schemas import LoginRequest, ActivateRequest

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login")
async def login(request: LoginRequest):
    """
    Authenticates a user and returns a token/session.
    """
    # TODO: Validate credentials
    # TODO: Generate JWT token
    # TODO: Return token
    pass


@router.post("/logout")
async def logout():
    """
    Logs out the current user.
    """
    # TODO: Invalidate session/token if needed
    pass


@router.post("/activate")
async def activate(request: ActivateRequest):
    """
    Activates a new account into the system, using an already created
    username and one time password.
    """
    # TODO: Verify one-time password
    # TODO: Set user password
    # TODO: Store public key
    # TODO: Mark user as activated
    pass
