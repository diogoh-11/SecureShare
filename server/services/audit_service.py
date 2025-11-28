from sqlalchemy.orm import Session
from models.models import AuditLog, AuditVerification, User
from datetime import datetime
from utils.funcs import sha256
import json

class AuditService:
    @staticmethod
    def log_action(db: Session, actor_id: int, action: str, details: dict = None):
        previous_entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        previous_hash = previous_entry.entryHash if previous_entry else "0" * 64

        timestamp = datetime.utcnow()
        entry_data = {
            "timestamp": timestamp.isoformat(),
            "actor_id": actor_id,
            "action": action,
            "details": details or {},
            "previous_hash": previous_hash
        }

        entry_json = json.dumps(entry_data, sort_keys=True)
        entry_hash = sha256(entry_json)

        audit_entry = AuditLog(
            previousHash=previous_hash,
            entryHash=entry_hash,
            timestamp=timestamp,
            action=f"{action}: {json.dumps(details)}" if details else action,
            actor_id=actor_id
        )

        db.add(audit_entry)
        db.commit()

        return audit_entry

    @staticmethod
    def get_audit_log(db: Session, limit: int = None):
        query = db.query(AuditLog).order_by(AuditLog.id.asc())
        if limit:
            query = query.limit(limit)

        entries = query.all()

        return [
            {
                "id": entry.id,
                "timestamp": entry.timestamp.isoformat(),
                "action": entry.action,
                "actor_id": entry.actor_id,
                "previous_hash": entry.previousHash,
                "entry_hash": entry.entryHash
            }
            for entry in entries
        ]

    @staticmethod
    def verify_chain(db: Session):
        entries = db.query(AuditLog).order_by(AuditLog.id.asc()).all()

        if not entries:
            return {"valid": True, "message": "No entries to verify"}

        for i, entry in enumerate(entries):
            if i == 0:
                if entry.previousHash != "0" * 64:
                    return {
                        "valid": False,
                        "message": f"First entry previous hash is invalid",
                        "entry_id": entry.id
                    }
            else:
                expected_previous = entries[i - 1].entryHash
                if entry.previousHash != expected_previous:
                    return {
                        "valid": False,
                        "message": f"Hash chain broken at entry {entry.id}",
                        "entry_id": entry.id,
                        "expected": expected_previous,
                        "actual": entry.previousHash
                    }

        return {"valid": True, "message": "Hash chain is valid"}

    @staticmethod
    def add_verification(db: Session, auditor_id: int, entry_id: int, signature: str):
        entry = db.query(AuditLog).filter(AuditLog.id == entry_id).first()
        if not entry:
            raise ValueError("Audit entry not found")

        auditor = db.query(User).filter(User.id == auditor_id).first()
        if not auditor:
            raise ValueError("Auditor not found")

        verification = AuditVerification(
            timestamp=datetime.utcnow(),
            verifiedUpToHash=entry.entryHash,
            signature=signature,
            audit_log_entry_id=entry_id,
            auditor_id=auditor_id
        )

        db.add(verification)
        db.commit()

        return verification
