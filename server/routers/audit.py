from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
from utils.rbac import require_role, get_current_user
from services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit"])

@router.get("/log")
async def get_audit_log(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Auditor"]))
):
    user, _ = user_db
    audit_log = AuditService.get_audit_log(db)
    return {"entries": audit_log}

@router.get("/verify")
async def verify_audit_chain(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Auditor"]))
):
    user, _ = user_db
    result = AuditService.verify_chain(db)
    return result

@router.put("/validate")
async def add_verification(
    request: dict,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Auditor"]))
):
    user, _ = user_db

    entry_id = request.get("entry_id")
    signature = request.get("signature")

    if not entry_id or not signature:
        raise HTTPException(status_code=400, detail="entry_id and signature required")

    try:
        verification = AuditService.add_verification(db, user.id, entry_id, signature)
        return {
            "success": True,
            "verification_id": verification.id,
            "auditor_id": user.id,
            "entry_id": entry_id
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
