from sqlalchemy.orm import Session
from sqlalchemy import text
from models.models import Transfer, TransferKey, ClearanceLevel, Department, User
from datetime import datetime, timedelta
from typing import List
import os
import base64
import uuid
from utils.mls_utils import same_organization

UPLOAD_DIR = "uploads"

class TransferService:

    @staticmethod
    def create_transfer_with_key_encryption(
        db: Session,
        sender_id: int,
        file_content: bytes,
        classification_level: str,
        departments: List[str],
        strategy : str,
        nonce : str,
        expiration_days: int = 7,
        transfer_mode: str = "user",
        recipients: dict[str,str] = None
    ):
        """
        Create transfer and automatically encrypt file key for recipients based on mode:
        - organization: all active users in organization
        - department: all active users in specified departments
        - user: specific user IDs

        Note: Server generates UUID-based filename for privacy - original filename is not stored
        """
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # Get sender's organization
        sender:User = db.query(User).filter(User.id == sender_id).first()
        if not sender:
            raise ValueError("Sender not found")

        clearance = db.query(ClearanceLevel).filter(
            ClearanceLevel.label == classification_level
        ).first()

        if not clearance:
            raise ValueError(f"Classification level '{classification_level}' not found")

        # Generate UUID-based filename for privacy
        file_uuid = str(uuid.uuid4())

        # Create transfer
        transfer = Transfer(
            sender_id=sender_id,
            classification_level_id=clearance.id,
            expiration_time=datetime.utcnow() + timedelta(days=expiration_days),
            file_path="",
            original_filename=file_uuid,  # Store UUID instead of original filename
            created_at=datetime.utcnow(),
            strategy = strategy,
            nonce = nonce
        )

        db.add(transfer)
        db.flush()

        file_path = os.path.join(UPLOAD_DIR, f"{file_uuid}.enc")
        transfer.file_path = file_path

        # Add departments
        for dept_label in departments:
            dept:Department = db.query(Department).filter(Department.label == dept_label).first()
            if not( dept and dept.organization_id == sender.organization_id):
                raise ValueError(f"Cannot sahre file to department {dept_label} - does not exist or is from another organization")
            db.execute(
                text("INSERT INTO transfer_department (transfer_id, department_id) VALUES (:transfer_id, :dept_id)"),
                {"transfer_id": transfer.id, "dept_id": dept.id}
            )

        # Handle public transfers differently
        if transfer_mode == "public":
            # Generate secure random token for public access
            import secrets
            public_token = secrets.token_urlsafe(32)
            transfer.public_access_token = public_token

            db.commit()
            db.refresh(transfer)

            with open(file_path, "wb") as f:
                f.write(file_content)

            return {
                "id": transfer.id,
                "public_access_token": public_token,
                "is_public": True
            }


        recipient_ids = set()

        # Encrypt file key for each recipient
        for user_id, user_encrypted_key in recipients.items():
            user = db.query(User).filter(User.id == user_id).first()
            if not user or not user.public_key:
                continue

            # SECURITY: Verify recipient is in same organization as sender
            if not same_organization(sender_id, int(user_id), db):
                raise ValueError(f"Cannot share with user {user_id} - different organization")

            transfer_key = TransferKey(
                transfer_id=transfer.id,
                user_id=user_id,
                encrypted_key=user_encrypted_key
            )
            recipient_ids.add(user_id)
            db.add(transfer_key)

        if not recipient_ids:
            raise ValueError("Cannot create user specific share without recipients")

        db.commit()
        db.refresh(transfer)

        with open(file_path, "wb") as f:
            f.write(file_content)

        return {
            "id": transfer.id,
            "recipient_ids": list(recipient_ids),
            "is_public": False
        }

    @staticmethod
    def get_user_transfers(db: Session, user_id: int):
        """
        Get transfers accessible to user (where user has an encrypted key)
        """
        # Get transfers where user has encrypted key (is a recipient)
        transfers = db.query(Transfer).filter(
            Transfer.sender_id == user_id
        ).all()

        result = []
        for transfer, classification in transfers:
            departments = db.execute(
                text("SELECT d.label FROM departments d "
                     "JOIN transfer_department td ON d.id = td.department_id "
                     "WHERE td.transfer_id = :transfer_id"),
                {"transfer_id": transfer.id}
            ).fetchall()

            result.append({
                "id": transfer.id,
                "classification_level": classification.label,
                "departments": [d[0] for d in departments],
                "created_at": transfer.created_at.isoformat(),
                "expires_at": transfer.expiration_time.isoformat() if transfer.expiration_time else None
            })

        return result

    @staticmethod
    def get_transfer(db: Session, transfer_id: int, user_id: int):
        """
        Get transfer info only if user has access (has encrypted key for it)
        """
        transfer = db.query(Transfer, ClearanceLevel).join(
            ClearanceLevel, Transfer.classification_level_id == ClearanceLevel.id
        ).filter(
            Transfer.id == transfer_id
        ).first()

        if not transfer:
            return None

        transfer_obj, classification = transfer
        if not same_organization(user_id, transfer_obj.sender_id, db):
            return None

        # Check if user has encrypted key (is a recipient)
        # TODO: check if trusted officer can bypass
        encrypted_key_obj = db.query(TransferKey).filter(
            TransferKey.transfer_id == transfer_id,
            TransferKey.user_id == user_id
        ).first()

        # User doesn't have access if no encrypted key
        if not encrypted_key_obj:
            return None

        departments = db.execute(
            text("SELECT d.label FROM departments d "
                 "JOIN transfer_department td ON d.id = td.department_id "
                 "WHERE td.transfer_id = :transfer_id"),
            {"transfer_id": transfer_id}
        ).fetchall()

        # Encode encrypted key as base64 for transmission (encrypted data is binary, not UTF-8 text)
        encrypted_key = base64.b64encode(encrypted_key_obj.encrypted_key).decode('utf-8')

        return {
            "id": transfer_obj.id,
            "file_uuid": transfer_obj.original_filename,  # UUID for local filename
            "classification_level": classification.label,
            "departments": [d[0] for d in departments],
            "created_at": transfer_obj.created_at.isoformat(),
            "expires_at": transfer_obj.expiration_time.isoformat() if transfer_obj.expiration_time else None,
            "sender_id": transfer_obj.sender_id,
            "encrypted_key": encrypted_key
        }

    @staticmethod
    def get_transfer_file(db: Session, transfer_id: int):
        transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
        if not transfer or not os.path.exists(transfer.file_path):
            return None

        with open(transfer.file_path, "rb") as f:
            content = f.read()

        return content, transfer.original_filename, transfer.strategy, transfer.nonce

    @staticmethod
    def get_transfer_metadata(db: Session, transfer_id: int):
        """
        Return metadata for a transfer in the exact format expected by the client.
        Format:
            metadata = {
                'classification_level': classification_level,
                'departments': json.dumps(departments),
                'expiration_days': str(expiration_days),
                'transfer_mode': transfer_mode,
                'recipients': json.dumps(encoded_recipients),
                'nonce' : base64.b64encode(nonce).decode("ascii"),
                'strategy' : strategy
            }

        Notes: This method builds a best-effort metadata payload using values stored
        in the database. Some fields (like expiration_days, transfer_mode, recipients)
        are only available at creation-time; when not available we fall back to
        reasonable defaults or empty values to preserve the client's expected shape.
        """
        import json as _json

        transfer = db.query(Transfer, ClearanceLevel).join(
            ClearanceLevel, Transfer.classification_level_id == ClearanceLevel.id
        ).filter(Transfer.id == transfer_id).first()

        if not transfer:
            return None

        transfer_obj, classification = transfer

        # departments stored in join table
        departments_rows = db.execute(
            text("SELECT d.label FROM departments d "
                 "JOIN transfer_department td ON d.id = td.department_id "
                 "WHERE td.transfer_id = :transfer_id"),
            {"transfer_id": transfer_id}
        ).fetchall()

        departments = [d[0] for d in departments_rows]

        # expiration_days is not stored explicitly; try to compute from created_at and expiration_time
        expiration_days = ""
        if transfer_obj.expiration_time and transfer_obj.created_at:
            try:
                delta = transfer_obj.expiration_time - transfer_obj.created_at
                # Use ceiling of days to avoid off-by-one when partial days exist
                total_seconds = delta.total_seconds()
                days = int((total_seconds + 86399) // 86400)  # ceil without math.ceil
                expiration_days = str(days)
            except Exception:
                expiration_days = ""

        # transfer_mode and recipients are not stored for non-public transfers in current schema
        transfer_mode = "public" if transfer_obj.public_access_token else "user"

        # recipients: we'll try to list the user_ids that have TransferKey entries and encode as base64 keys placeholder
        encoded_recipients = {}
        try:
            rows = db.execute(text("SELECT user_id, encrypted_key FROM transfer_keys WHERE transfer_id = :transfer_id"), {"transfer_id": transfer_id}).fetchall()
            for user_id, encrypted_key in rows:
                # encrypted_key is binary; base64-encode to ascii for JSON transport
                encoded_recipients[user_id] = base64.b64encode(encrypted_key).decode("ascii")
        except Exception:
            encoded_recipients = {}

        # nonce stored in DB — return exactly as stored so metadata matches what client used
        nonce_field = transfer_obj.nonce if transfer_obj.nonce is not None else ""

        metadata = {
            'classification_level': classification.label,
            'departments': _json.dumps(departments),
            'expiration_days': expiration_days,
            'transfer_mode': transfer_mode,
            'recipients': _json.dumps(encoded_recipients),
            'nonce': nonce_field,
            'strategy': transfer_obj.strategy
        }

        return metadata

    @staticmethod
    def delete_transfer(db: Session, transfer_id: int, user_id: int):
        transfer = db.query(Transfer).filter(
            Transfer.id == transfer_id,
            Transfer.sender_id == user_id
        ).first()

        if not transfer:
            return False

        if os.path.exists(transfer.file_path):
            os.remove(transfer.file_path)

        db.query(TransferKey).filter(TransferKey.transfer_id == transfer_id).delete()

        db.execute(text("DELETE FROM transfer_department WHERE transfer_id = :transfer_id"), {"transfer_id": transfer_id})

        db.delete(transfer)
        db.commit()

        return True
