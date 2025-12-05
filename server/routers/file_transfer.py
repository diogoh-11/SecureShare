from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Response, Form, Header
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional
from database import get_db
from utils.rbac import get_current_user, require_role
from utils.mls_utils import check_transfer_read_access, check_transfer_write_access, is_trusted_officer
from services.transfer_service import TransferService
from services.audit_service import AuditService
from datetime import datetime
import json
import base64
import io


router = APIRouter(tags=["File Transfers"])


@router.get("/transfers")
async def list_transfers(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Standard User"]))
):
    user, _ = user_db
    transfers = TransferService.get_user_transfers(db, user.id)
    return {"transfers": transfers}


@router.post("/transfers")
async def create_transfer(
    file: UploadFile = File(...),
    classification_level: str = Form(...),
    departments: str = Form("[]"),
    expiration_days: int = Form(7),
    transfer_mode: str = Form("user"),
    recipients: str = Form("[]"),
    x_acting_clearance: Optional[str] = Header(None),
    x_acting_role: Optional[str] = Header(None),
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Standard User","Trusted Officer"]))
):
    """
    Create a file transfer.
    Use X-Acting-Clearance header to specify which clearance token to use.
    If not specified, user is treated as having no clearance.
    """
    user, _ = user_db

    # Get acting role (defaults to Standard User)
    acting_role = x_acting_role or "Standard User"

    # Parse clearance token ID if provided
    clearance_token_id = None
    if x_acting_clearance:
        try:
            clearance_token_id = int(x_acting_clearance)
        except ValueError:
            raise HTTPException(status_code=400, detail="X-Acting-Clearance must be a valid clearance token ID")

    try:
        dept_list = json.loads(departments) if departments else []
        recipients_dict = json.loads(recipients) if recipients else {}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in departments or recipients")

    decoded_recipients = {}

    for user_id, key_b64 in recipients_dict.items():
        decoded_recipients[int(user_id)] = base64.b64decode(key_b64)

    if not classification_level:
        raise HTTPException(status_code=400, detail="classification_level required")

    # MLS enforcement: Only check for PUBLIC transfers
    # User-specific transfers are not bound by classification/departments
    trusted = is_trusted_officer(db, user.id, acting_role)
    if not trusted and transfer_mode == "public":
        can_upload = check_transfer_write_access(db, user.id, classification_level, dept_list, clearance_token_id)
        if not can_upload:
            raise HTTPException(
                status_code=403,
                detail="Your clearance does not allow writing at this classification level. Use --with <clearance_token_id>."
            )

    file_content = await file.read()

    try:
        transfer = TransferService.create_transfer_with_key_encryption(
            db, user.id, file_content,
            classification_level, dept_list, expiration_days,
            transfer_mode, decoded_recipients
        )

        AuditService.log_action(
            db, user.id, "CREATE_TRANSFER",
            {"transfer_id": transfer["id"], "classification": classification_level, "mode": transfer_mode}
        )

        response = {
            "transfer_id": transfer["id"],
            "classification_level": classification_level,
            "recipients_count": len(transfer.get("recipient_ids", []))
        }

        # Include public access token for public transfers
        if transfer.get("public_access_token"):
            response["public_access_token"] = transfer["public_access_token"]
            response["is_public"] = transfer.get("is_public", True)

        return response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/transfers/{transfer_id}")
async def get_transfer(
    transfer_id: int,
    justification: str = None,
    x_acting_role: Optional[str] = Header(None),
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Standard User","Trusted Officer"]))
):
    user, _ = user_db

    # Get acting role (defaults to Standard User)
    acting_role = x_acting_role or "Standard User"

    trusted = is_trusted_officer(db, user.id, acting_role)
    if not trusted:
        can_access = check_transfer_read_access(db, user.id, transfer_id)
        if not can_access:
            raise HTTPException(
                status_code=403,
                detail="User clearance does not allow reading this classification level"
            )
    else:
        if justification:
            AuditService.log_action(
                db, user.id, "TRUSTED_OFFICER_ACCESS",
                {"transfer_id": transfer_id, "justification": justification}
            )
        else:
            raise HTTPException(
                status_code = 403,
                detail= "Cannot bypass MLS without justification"
            )

    transfer = TransferService.get_transfer(db, transfer_id, user.id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    return transfer


@router.delete("/transfers/{transfer_id}")
async def delete_transfer(
    transfer_id: int,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Standard User"]))
):
    user, _ = user_db

    success = TransferService.delete_transfer(db, transfer_id, user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Transfer not found or not owned by user")

    AuditService.log_action(db, user.id, "DELETE_TRANSFER", {"transfer_id": transfer_id})

    return {"status": "deleted"}


@router.get("/public/{access_token}")
async def download_public_transfer(
    access_token: str,
    x_acting_clearance: Optional[str] = Header(None),
    x_acting_role: Optional[str] = Header(None),
    authorization: str = Header(...),
    db: Session = Depends(require_role(["Standard User","Trusted Officer"]))
):
    """
    Public download endpoint - requires authentication and MLS clearance verification.
    For public transfers, Bell-LaPadula model is enforced - users need proper clearance to access.
    Returns encrypted file, client must decrypt with key from URL fragment.
    """
    from models.models import Transfer, Session as SessionModel, User

    # Get user from session (require_role already validated the session)
    token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
    session = db.query(SessionModel).filter(SessionModel.session_token == token).first()
    user = db.query(User).filter(User.id == session.user_id).first()

    # Get acting role (defaults to Standard User)
    acting_role = x_acting_role or "Standard User"

    transfer = db.query(Transfer).filter(
        Transfer.public_access_token == access_token
    ).first()

    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found or invalid token")

    # Check expiration
    if transfer.expiration_time and transfer.expiration_time < datetime.utcnow():
        raise HTTPException(status_code=410, detail="Transfer has expired")

    # ENFORCE MLS: Check if user has proper clearance to access this transfer
    # Trusted Officers can bypass MLS checks
    trusted = is_trusted_officer(db, user.id, acting_role)
    if not trusted:
        # Non-trusted users must provide clearance
        clearance_token_id = None
        if x_acting_clearance:
            try:
                clearance_token_id = int(x_acting_clearance)
            except ValueError:
                raise HTTPException(status_code=400, detail="X-Acting-Clearance must be a valid clearance token ID")
        else:
            raise HTTPException(
                status_code=403,
                detail="Public transfers require clearance. Use --with <clearance_token_id> to specify your clearance."
            )

        can_access = check_transfer_read_access(db, user.id, transfer.id, clearance_token_id)
        if not can_access:
            raise HTTPException(
                status_code=403,
                detail="Your clearance does not allow downloading this file."
            )

    result = TransferService.get_transfer_file(db, transfer.id)
    if not result:
        raise HTTPException(status_code=404, detail="Transfer file not found")

    file_content, _ = result

    AuditService.log_action(db, user.id, "DOWNLOAD_PUBLIC_TRANSFER", {"transfer_id": transfer.id, "access_token": access_token})

    return StreamingResponse(
        io.BytesIO(file_content),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": 'attachment; filename="encrypted_file.enc"'
        }
    )


@router.get("/download/{transfer_id}")
async def download_transfer(
    transfer_id: int,
    justification: str = None,
    x_acting_clearance: Optional[str] = Header(None),
    x_acting_role: Optional[str] = Header(None),
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Standard User"]))
):
    """
    Download a user-specific file transfer.
    For user-specific transfers, MLS is NOT enforced - target users can access regardless of clearance.
    """
    from models.models import TransferKey
    user, _ = user_db

    # Get acting role (defaults to Standard User)
    acting_role = x_acting_role or "Standard User"

    # Check if user is a recipient of this transfer
    is_recipient = db.query(TransferKey).filter(
        TransferKey.transfer_id == transfer_id,
        TransferKey.user_id == user.id
    ).first() is not None

    trusted = is_trusted_officer(db, user.id, acting_role)

    if not is_recipient and not trusted:
        raise HTTPException(
            status_code=403,
            detail="You are not a recipient of this transfer"
        )

    if trusted and not is_recipient:
        # Trusted officer accessing someone else's transfer - requires justification
        if justification:
            AuditService.log_action(
                db, user.id, "TRUSTED_OFFICER_DOWNLOAD",
                {"transfer_id": transfer_id, "justification": justification}
            )

    result = TransferService.get_transfer_file(db, transfer_id)
    if not result:
        raise HTTPException(status_code=404, detail="Transfer file not found")

    file_content, _ = result

    AuditService.log_action(db, user.id, "DOWNLOAD_TRANSFER", {"transfer_id": transfer_id})

    return StreamingResponse(
        io.BytesIO(file_content),
        media_type="application/octet-stream",
        headers={"Content-Disposition": 'attachment; filename="encrypted_file.enc"'}
    )
