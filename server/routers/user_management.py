from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
from schemas.schemas import (
    CreateUserRequest,
    UpdateRoleRequest,
    ClearanceRequest,
    UpdateUserInfoRequest,
    VaultRequest
)
from services.user_management_service import UserManagementService

router = APIRouter(prefix="/users", tags=["User Management"])


@router.post("")
async def create_user(request: CreateUserRequest, db: Session = Depends(get_db)):
    """
    Creates a new user to the system. Sets username and activation code.
    Authorization: Administrator
    """
    # TODO: Verify role
    try:
        result = UserManagementService.create_user(db, request.username)
        return {
            "user_id": result["user"].id,
            "username": result["user"].username,
            "activation_code": result["activation_code"]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("")
async def get_users(db: Session = Depends(get_db)):
    """
    Retrieves all users in the system.
    Authorization: Administrator, Security Officer
    """
    # TODO: Verify role
    users = UserManagementService.get_all_users(db)
    return [{"id": u.id, "username": u.username, "is_active": u.is_active} for u in users]


@router.delete("/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    """
    Removes a user from the system.
    Authorization: Administrator
    """
    # TODO: Verify role
    success = UserManagementService.delete_user(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "deleted"}


@router.put("/{user_id}/role")
async def update_user_role(user_id: int, request: UpdateRoleRequest):
    """
    Updates a user's role (e.g., promote to Trusted Officer).
    Authorization: Security Officer, Administrator
    """
    # TODO: Verify role (Security Officer or Administrator)
    # TODO: Verify signed token
    # TODO: Update role in DB
    pass


@router.get("/{user_id}/clearance")
async def get_user_clearance(user_id: int):
    """
    Gets the clearance tokens for the specified user.
    Authorization: Security Officer, Authenticated User (own clearances)
    """
    # TODO: Verify authorization
    # TODO: Fetch clearance tokens from DB
    pass


@router.put("/{user_id}/clearance")
async def add_user_clearance(user_id: int, request: ClearanceRequest):
    """
    Adds a clearance token for the specified user.
    Authorization: Security Officer
    """
    # TODO: Verify Security Officer role
    # TODO: Verify signed clearance token
    # TODO: Store clearance in DB
    pass


@router.put("/{user_id}/revoke/{token_id}")
async def revoke_token(user_id: int, token_id: int):
    """
    Adds a revocation token for the specified user.
    Authorization: Security Officer
    """
    # TODO: Verify Security Officer role
    # TODO: Create and store revocation token
    pass


@router.get("/{user_id}/key")
async def get_user_public_key(user_id: int, db: Session = Depends(get_db)):
    """
    Retrieves a user's public key for encryption.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    try:
        public_key = UserManagementService.get_user_public_key(db, user_id)
        return {"user_id": user_id, "public_key": public_key.decode()}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/me/vault")
async def upload_vault(request: VaultRequest):
    """
    Uploads or updates the current user's password-encrypted private key blob.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    # TODO: Store encrypted private key blob
    pass


@router.get("/me/vault")
async def get_vault():
    """
    Retrieves the current user's password-encrypted private key blob.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    # TODO: Fetch encrypted private key blob
    pass


@router.get("/me/info")
async def get_current_user_info():
    """
    Get current user information.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    # TODO: Return user information
    pass


@router.post("/me/info")
async def update_current_user_info(request: UpdateUserInfoRequest):
    """
    Updates existing information, such as the password.
    Authorization: Authenticated User
    """
    # TODO: Verify authentication
    # TODO: Update user information (e.g., password)
    pass
