from sqlalchemy.orm import Session
from sqlalchemy import text
from models.models import Transfer, TransferKey, ClearanceLevel, Department, User
from datetime import datetime, timedelta
from typing import List
import os
import shutil
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

UPLOAD_DIR = "uploads"

class TransferService:
    @staticmethod
    def create_transfer(
        db: Session,
        sender_id: int,
        file_content: bytes,
        original_filename: str,
        classification_level: str,
        departments: List[str],
        encrypted_keys: dict,
        expiration_days: int = 7
    ):
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        clearance = db.query(ClearanceLevel).filter(
            ClearanceLevel.label == classification_level
        ).first()

        if not clearance:
            raise ValueError(f"Classification level '{classification_level}' not found")

        transfer = Transfer(
            sender_id=sender_id,
            classification_level_id=clearance.id,
            expiration_time=datetime.utcnow() + timedelta(days=expiration_days),
            file_path="",
            original_filename=original_filename,
            created_at=datetime.utcnow()
        )

        db.add(transfer)
        db.flush()

        file_path = os.path.join(UPLOAD_DIR, f"transfer_{transfer.id}_{original_filename}")
        transfer.file_path = file_path

        with open(file_path, "wb") as f:
            f.write(file_content)

        for dept_label in departments:
            dept = db.query(Department).filter(Department.label == dept_label).first()
            if dept:
                db.execute(
                    text("INSERT INTO transfer_department (transfer_id, department_id) VALUES (:transfer_id, :dept_id)"),
                    {"transfer_id": transfer.id, "dept_id": dept.id}
                )

        for user_id_str, encrypted_key in encrypted_keys.items():
            user_id = int(user_id_str)
            transfer_key = TransferKey(
                transfer_id=transfer.id,
                user_id=user_id,
                encrypted_key=encrypted_key.encode('utf-8') if isinstance(encrypted_key, str) else encrypted_key
            )
            db.add(transfer_key)

        db.commit()
        db.refresh(transfer)

        return transfer

    @staticmethod
    def create_transfer_with_key_encryption(
        db: Session,
        sender_id: int,
        file_content: bytes,
        original_filename: str,
        classification_level: str,
        departments: List[str],
        file_key_b64: str,
        expiration_days: int = 7,
        transfer_mode: str = "user",
        recipient_list: List[str] = None
    ):
        """
        Create transfer and automatically encrypt file key for recipients based on mode:
        - organization: all active users in organization
        - department: all active users in specified departments
        - user: specific user IDs
        """
        os.makedirs(UPLOAD_DIR, exist_ok=True)

        # Get sender's organization
        sender = db.query(User).filter(User.id == sender_id).first()
        if not sender:
            raise ValueError("Sender not found")

        clearance = db.query(ClearanceLevel).filter(
            ClearanceLevel.label == classification_level
        ).first()

        if not clearance:
            raise ValueError(f"Classification level '{classification_level}' not found")

        # Create transfer
        transfer = Transfer(
            sender_id=sender_id,
            classification_level_id=clearance.id,
            expiration_time=datetime.utcnow() + timedelta(days=expiration_days),
            file_path="",
            original_filename=original_filename,
            created_at=datetime.utcnow()
        )

        db.add(transfer)
        db.flush()

        file_path = os.path.join(UPLOAD_DIR, f"transfer_{transfer.id}_{original_filename}")
        transfer.file_path = file_path

        with open(file_path, "wb") as f:
            f.write(file_content)

        # Add departments
        for dept_label in departments:
            dept = db.query(Department).filter(Department.label == dept_label).first()
            if dept:
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

            return {
                "id": transfer.id,
                "original_filename": transfer.original_filename,
                "public_access_token": public_token,
                "is_public": True
            }

        # Expand recipients based on mode (for non-public transfers)
        recipient_ids = set()

        if transfer_mode == "organization":
            # All active users in organization
            users = db.query(User).filter(
                User.organization_id == sender.organization_id,
                User.is_active == True
            ).all()
            recipient_ids = set(u.id for u in users)

        elif transfer_mode == "department":
            # All active users in specified departments
            for dept_label in departments:
                dept = db.query(Department).filter(Department.label == dept_label).first()
                if dept:
                    # Find users with clearance in this department
                    users = db.execute(
                        text("""
                            SELECT DISTINCT u.id
                            FROM users u
                            JOIN clearance_tokens ct ON ct.user_id = u.id
                            JOIN clearance_department cd ON cd.clearance_token_id = ct.id
                            WHERE cd.department_id = :dept_id AND u.is_active = 1
                        """),
                        {"dept_id": dept.id}
                    ).fetchall()
                    recipient_ids.update(u[0] for u in users)

        elif transfer_mode == "user":
            # Specific users
            if recipient_list:
                recipient_ids = set(int(uid) for uid in recipient_list)

        # Decrypt file key
        file_key = base64.b64decode(file_key_b64)

        # Encrypt file key for each recipient
        for user_id in recipient_ids:
            user = db.query(User).filter(User.id == user_id).first()
            if not user or not user.public_key:
                continue

            # Load recipient's public key
            try:
                public_key = serialization.load_pem_public_key(
                    user.public_key,
                    backend=default_backend()
                )

                # Encrypt file key with recipient's public key
                encrypted_key = public_key.encrypt(
                    file_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # Store encrypted key
                transfer_key = TransferKey(
                    transfer_id=transfer.id,
                    user_id=user_id,
                    encrypted_key=encrypted_key
                )
                db.add(transfer_key)

            except Exception as e:
                print(f"[WARNING] Could not encrypt key for user {user_id}: {e}")
                continue

        db.commit()
        db.refresh(transfer)

        return {
            "id": transfer.id,
            "original_filename": transfer.original_filename,
            "recipient_ids": list(recipient_ids),
            "is_public": False
        }

    @staticmethod
    def get_user_transfers(db: Session, user_id: int):
        """
        Get transfers accessible to user (where user has an encrypted key)
        """
        # Get transfers where user has encrypted key (is a recipient)
        transfers = db.query(Transfer, ClearanceLevel).join(
            ClearanceLevel, Transfer.classification_level_id == ClearanceLevel.id
        ).join(
            TransferKey, Transfer.id == TransferKey.transfer_id
        ).filter(
            TransferKey.user_id == user_id
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
                "original_filename": transfer.original_filename,
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

        # Check if user has encrypted key (is a recipient)
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

        encrypted_key = encrypted_key_obj.encrypted_key.decode()

        return {
            "id": transfer_obj.id,
            "original_filename": transfer_obj.original_filename,
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

        return content, transfer.original_filename

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
