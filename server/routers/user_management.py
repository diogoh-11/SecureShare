from fastapi import APIRouter, HTTPException, Depends, Header
from sqlalchemy.orm import Session
from database import get_db
from utils.rbac import require_role, get_current_user
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
async def create_user(
    request: CreateUserRequest,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Administrator"]))
):
    user, _ = user_db

    if not user.organization_id:
        raise HTTPException(status_code=400, detail="Admin user has no organization")

    try:
        result = UserManagementService.create_user(
            db=db,
            username=request.username,
            issuer_id=user.id,
            organization_id=user.organization_id
        )
        return {
            "user_id": result["user"].id,
            "username": result["user"].username,
            "activation_code": result["activation_code"]
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("")
async def get_users(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Administrator", "Security Officer"]))
):
    user, _ = user_db
    users = UserManagementService.get_all_users(db)
    return [{"id": u.id, "username": u.username, "is_active": u.is_active} for u in users]


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Administrator"]))
):
    from services.audit_service import AuditService
    user, _ = user_db

    success = UserManagementService.delete_user(db, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")

    AuditService.log_action(db, user.id, "DELETE_USER", {"deleted_user_id": user_id})

    return {"status": "deleted"}


@router.put("/{user_id}/role")
async def update_user_role(
    user_id: int,
    request: UpdateRoleRequest,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Security Officer", "Administrator"]))
):
    from services.clearance_service import RoleService
    from services.audit_service import AuditService
    user, _ = user_db

    try:
        role_token = RoleService.assign_role(db, user.id, user_id, request.role, expires_in_days=365)
        AuditService.log_action(db, user.id, "ASSIGN_ROLE", {"target_user_id": user_id, "role": request.role})

        return {
            "success": True,
            "role_token_id": role_token.id,
            "role": request.role,
            "target_user_id": user_id
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{user_id}/clearance")
async def get_user_clearance(
    user_id: int,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from services.clearance_service import ClearanceService
    user, _ = user_db

    if user.id != user_id:
        from utils.rbac import get_active_user_roles
        roles = get_active_user_roles(db, user.id)
        if "Security Officer" not in roles and "Administrator" not in roles:
            raise HTTPException(status_code=403, detail="Can only view own clearances")

    clearances = ClearanceService.get_user_clearances(db, user_id)
    return {"clearances": clearances}


@router.put("/{user_id}/clearance")
async def add_user_clearance(
    user_id: int,
    request: ClearanceRequest,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Security Officer"]))
):
    from services.clearance_service import ClearanceService
    from services.audit_service import AuditService
    user, _ = user_db

    try:
        clearance = ClearanceService.create_clearance_token(
            db, user.id, user_id, request.clearance_level, request.departments
        )
        AuditService.log_action(
            db, user.id, "ASSIGN_CLEARANCE",
            {"target_user_id": user_id, "level": request.clearance_level, "departments": request.departments}
        )

        return {
            "success": True,
            "clearance_id": clearance.id,
            "user_id": user_id
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/{user_id}/revoke/{token_id}")
async def revoke_token(
    user_id: int,
    token_id: int,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Security Officer"]))
):
    from services.clearance_service import RoleService
    from services.audit_service import AuditService
    user, _ = user_db

    try:
        RoleService.revoke_role(db, user.id, token_id)
        AuditService.log_action(db, user.id, "REVOKE_ROLE", {"user_id": user_id, "token_id": token_id})

        return {"success": True, "message": "Role revoked"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{user_id}/key")
async def get_user_public_key(
    user_id: int,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user, _ = user_db
    try:
        public_key = UserManagementService.get_user_public_key(db, user_id)
        return {"user_id": user_id, "public_key": public_key.decode()}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/me/vault")
async def upload_vault(
    request: VaultRequest,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from models.models import User
    user, _ = user_db

    user.private_key_blob = request.encrypted_private_key_blob.encode('utf-8')
    db.commit()

    return {"success": True, "message": "Vault updated"}


@router.get("/me/vault")
async def get_vault(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user, _ = user_db

    if not user.private_key_blob:
        raise HTTPException(status_code=404, detail="No vault found")

    return {"encrypted_private_key_blob": user.private_key_blob.decode()}


@router.get("/me/info")
async def get_current_user_info(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from services.clearance_service import RoleService
    user, _ = user_db

    roles = RoleService.get_user_roles(db, user.id)

    return {
        "id": user.id,
        "username": user.username,
        "is_active": user.is_active,
        "organization_id": user.organization_id,
        "roles": roles,
        "private_key_blob": user.private_key_blob.decode() if user.private_key_blob else None,
        "public_key": user.public_key.decode() if user.public_key else None
    }


@router.post("/me/info")
async def update_current_user_info(
    request: UpdateUserInfoRequest,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from utils.funcs import sha256
    user, _ = user_db

    if request.password:
        user.password_hash = sha256(request.password)
        db.commit()

    return {"success": True, "message": "User info updated"}
