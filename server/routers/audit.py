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
    user,_ = user_db
    audit_log = AuditService.get_audit_log(db,organization_id=user.organization_id)
    return {"entries": audit_log}


@router.get("/verify")
async def verify_audit_chain(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Auditor"]))
):
    """
    Verify the entire audit chain from the beginning.

    This endpoint performs a FULL verification of all entries, regardless of
    previous verifications. This is useful for:
    - Manual inspection by auditors
    - Testing and debugging
    - Detecting if old entries were tampered with after being signed
    """
    user,_ = user_db
    # Full verification (no from_entry_id)
    result = AuditService.verify_chain(db, organization_id=user.organization_id)
    return result


@router.put("/validate")
async def add_verification(
    request: dict,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Auditor"]))
):
    """
    Validate the audit log up to the latest entry and add a new verification.
    Basically, the auditor signs the current state of the audit log.
    So its a incremental verification from the last signed checkpoint.
    """

    user, _ = user_db

    signature = request.get("signature")

    if not signature:
        raise HTTPException(status_code=400, detail="signature required")

    try:
        verification = AuditService.add_verification(db, user.id, signature)
        return {
            "success": True,
            "verification_id": verification.id,
            "auditor_id": user.id,
            "verified_up_to_entry": verification.audit_log_entry_id,
            "timestamp": verification.timestamp.isoformat()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/verifications")
async def get_verifications(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Auditor"]))
):
    """Get all audit verifications history"""
    user, _ = user_db
    verifications = AuditService.get_all_verifications(db,organization_id=user.organization_id)
    return {"verifications": verifications}


@router.get("/latest-entry")
async def get_latest_entry(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Auditor"]))
):
    """Get the latest audit log entry for verification"""
    from models.models import AuditLog, User
    user, _ = user_db
    last_entry = db.query(AuditLog).join(
        User, AuditLog.actor_id == User.id
    ).filter(
        User.organization_id == user.organization_id
    ).order_by(AuditLog.id.desc()).first()
    if not last_entry:
        raise HTTPException(status_code=404, detail="No audit entries found")

    return {
        "id": last_entry.id,
        "entryHash": last_entry.entryHash,
        "action": last_entry.action,
        "timestamp": last_entry.timestamp.isoformat()
    }
