from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Response, Form
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from database import get_db
from utils.rbac import get_current_user
from utils.mls_utils import check_transfer_read_access, check_transfer_write_access, is_trusted_officer
from services.transfer_service import TransferService
from services.audit_service import AuditService
from datetime import datetime
import json
import io

router = APIRouter(tags=["File Transfers"])


@router.get("/transfers")
async def list_transfers(
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
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
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user, _ = user_db

    try:
        dept_list = json.loads(departments) if departments else []
        recipients_dict = json.loads(recipients) if recipients else {}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in departments or recipients")

    if not classification_level:
        raise HTTPException(status_code=400, detail="classification_level required")

    trusted = is_trusted_officer(db, user.id)
    if not trusted:
        can_upload = check_transfer_write_access(db, user.id, classification_level, dept_list)
        if not can_upload:
            raise HTTPException(
                status_code=403,
                detail="User clearance does not allow writing at this classification level"
            )

    file_content = await file.read()

    try:
        transfer = TransferService.create_transfer_with_key_encryption(
            db, user.id, file_content, file.filename,
            classification_level, dept_list, expiration_days,
            transfer_mode, recipients_dict
        )

        AuditService.log_action(
            db, user.id, "CREATE_TRANSFER",
            {"transfer_id": transfer["id"], "classification": classification_level, "mode": transfer_mode}
        )

        return {
            "transfer_id": transfer["id"],
            "original_filename": transfer["original_filename"],
            "classification_level": classification_level,
            "recipients_count": len(transfer.get("recipient_ids", []))
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/transfers/{transfer_id}")
async def get_transfer(
    transfer_id: int,
    justification: str = None,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user, _ = user_db

    trusted = is_trusted_officer(db, user.id)
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

    transfer = TransferService.get_transfer(db, transfer_id, user.id)
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    return transfer


@router.delete("/transfers/{transfer_id}")
async def delete_transfer(
    transfer_id: int,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
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
    db: Session = Depends(get_db)
):
    """
    Public download endpoint - no authentication required
    Returns encrypted file, client must decrypt with key from URL fragment
    """
    from models.models import Transfer

    transfer = db.query(Transfer).filter(
        Transfer.public_access_token == access_token
    ).first()

    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found or invalid token")

    # Check expiration
    if transfer.expiration_time and transfer.expiration_time < datetime.utcnow():
        raise HTTPException(status_code=410, detail="Transfer has expired")

    result = TransferService.get_transfer_file(db, transfer.id)
    if not result:
        raise HTTPException(status_code=404, detail="Transfer file not found")

    file_content, filename = result

    return StreamingResponse(
        io.BytesIO(file_content),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


@router.get("/download/{transfer_id}")
async def download_transfer(
    transfer_id: int,
    justification: str = None,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user, _ = user_db

    trusted = is_trusted_officer(db, user.id)
    if not trusted:
        can_access = check_transfer_read_access(db, user.id, transfer_id)
        if not can_access:
            raise HTTPException(
                status_code=403,
                detail="User clearance does not allow downloading this file"
            )
    else:
        if justification:
            AuditService.log_action(
                db, user.id, "TRUSTED_OFFICER_DOWNLOAD",
                {"transfer_id": transfer_id, "justification": justification}
            )

    result = TransferService.get_transfer_file(db, transfer_id)
    if not result:
        raise HTTPException(status_code=404, detail="Transfer file not found")

    file_content, filename = result

    AuditService.log_action(db, user.id, "DOWNLOAD_TRANSFER", {"transfer_id": transfer_id})

    return StreamingResponse(
        io.BytesIO(file_content),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )
