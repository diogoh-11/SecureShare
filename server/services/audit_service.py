from sqlalchemy.orm import Session
from models.models import AuditLog, AuditVerification, User
from models.models import RoleToken, Role, RoleRevocation, ClearanceToken, ClearanceLevel, ClearanceRevocation
from datetime import datetime
from utils.funcs import sha256
import json


class AuditService:
    @staticmethod
    def log_action(db: Session, actor_id: int, action: str, details: dict = None):
        previous_entry = db.query(AuditLog).order_by(
            AuditLog.id.desc()).first()
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
    def verify_chain(db: Session, from_entry_id: int | None = None):
        """
        Verify audit log chain integrity.

        Args:
            from_entry_id: If provided, only verify entries AFTER the last verified entry.
                          This enables incremental verification.
        """
        query = db.query(AuditLog).order_by(AuditLog.id.asc())

        # Incremental verification: start from last verified entry
        if from_entry_id:
            query = query.filter(AuditLog.id > from_entry_id)

        entries = query.all()

        if not entries:
            return {
                "valid": True,
                "message": "No new entries to verify" if from_entry_id else "No entries to verify"
            }

        # If incremental, verify link to previous verified entry
        if from_entry_id:
            previous_entry = db.query(AuditLog).filter(
                AuditLog.id == from_entry_id
            ).first()

            if not previous_entry:
                return {
                    "valid": False,
                    "message": f"Previous verified entry {from_entry_id} not found"
                }

            # First new entry must point to last verified entry
            if entries[0].previousHash != previous_entry.entryHash:
                return {
                    "valid": False,
                    "message": f"Chain broken: Entry {entries[0].id} does not link to verified entry {from_entry_id}",
                    "entry_id": entries[0].id,
                    "expected": previous_entry.entryHash,
                    "actual": entries[0].previousHash
                }

            # Verify remaining new entries among themselves
            for i in range(1, len(entries)):
                entry = entries[i]

                # Check hash chain link
                expected_previous = entries[i - 1].entryHash
                if entry.previousHash != expected_previous:
                    return {
                        "valid": False,
                        "message": f"Hash chain broken at entry {entry.id}",
                        "entry_id": entry.id,
                        "expected": expected_previous,
                        "actual": entry.previousHash
                    }

                # Verify entry content integrity (recalculate hash)
                # Extract details from action string (format: "ACTION: {...}")
                action_parts = entry.action.split(": ", 1)
                action_type = action_parts[0]

                # Try to parse JSON, if it fails the entry might be tampered
                try:
                    details = json.loads(action_parts[1]) if len(
                        action_parts) > 1 else {}
                except json.JSONDecodeError:
                    # If JSON parsing fails, use empty dict (will cause hash mismatch)
                    details = {}

                entry_data = {
                    "timestamp": entry.timestamp.isoformat(),
                    "actor_id": entry.actor_id,
                    "action": action_type,
                    "details": details,
                    "previous_hash": entry.previousHash
                }
                calculated_hash = sha256(
                    json.dumps(entry_data, sort_keys=True))

                if calculated_hash != entry.entryHash:
                    return {
                        "valid": False,
                        "message": f"Entry {entry.id} content has been tampered with",
                        "entry_id": entry.id,
                        "expected_hash": calculated_hash,
                        "stored_hash": entry.entryHash,
                        "tampering_type": "content_modification"
                    }
        else:
            # Full verification from beginning
            for i, entry in enumerate(entries):
                if i == 0:
                    if entry.previousHash != "0" * 64:
                        return {
                            "valid": False,
                            "message": "First entry previous hash is invalid",
                            "entry_id": entry.id
                        }
                else:
                    # Check hash chain link
                    expected_previous = entries[i - 1].entryHash
                    if entry.previousHash != expected_previous:
                        return {
                            "valid": False,
                            "message": f"Hash chain broken at entry {entry.id}",
                            "entry_id": entry.id,
                            "expected": expected_previous,
                            "actual": entry.previousHash
                        }

                # Verify entry content integrity (recalculate hash)
                # Extract details from action string (format: "ACTION: {...}")
                action_parts = entry.action.split(": ", 1)
                action_type = action_parts[0]

                # Try to parse JSON, if it fails the entry might be tampered
                try:
                    details = json.loads(action_parts[1]) if len(
                        action_parts) > 1 else {}
                except json.JSONDecodeError:
                    # If JSON parsing fails, use empty dict (will cause hash mismatch)
                    details = {}

                entry_data = {
                    "timestamp": entry.timestamp.isoformat(),
                    "actor_id": entry.actor_id,
                    "action": action_type,
                    "details": details,
                    "previous_hash": entry.previousHash
                }
                calculated_hash = sha256(
                    json.dumps(entry_data, sort_keys=True))

                if calculated_hash != entry.entryHash:
                    return {
                        "valid": False,
                        "message": f"Entry {entry.id} content has been tampered with",
                        "entry_id": entry.id,
                        "expected_hash": calculated_hash,
                        "stored_hash": entry.entryHash,
                        "tampering_type": "content_modification"
                    }

        verified_count = len(entries)
        last_verified_id = entries[-1].id if entries else None

        return {
            "valid": True,
            "message": f"Hash chain is valid ({verified_count} {'new ' if from_entry_id else ''}entries verified)",
            "verified_count": verified_count,
            "last_verified_entry_id": last_verified_id,
            "last_verified_hash": entries[-1].entryHash if entries else None
        }

    @staticmethod
    def add_verification(db: Session, auditor_id: int, signature: str):
        """
        Add an auditor verification for all available entries.

        The auditor verifies the chain from the last verification point (or from the beginning
        if this is the first verification) up to the most recent entry in the audit log.

        This ensures complete audit coverage - all entries are eventually verified sequentially.

        Args:
            db: Database session
            auditor_id: ID of the auditor performing verification
            signature: Digital signature of the last entry's hash (signed with auditor's private key)
                      This signature proves:
                      1. Authenticity - only this auditor could create this signature
                      2. Non-repudiation - auditor cannot deny having verified
                      3. Integrity - signature is invalid if hash is tampered with

        Returns:
            AuditVerification object

        Raises:
            ValueError: If auditor not found, lacks Auditor role, or chain is broken
        """
        auditor = db.query(User).filter(User.id == auditor_id).first()
        if not auditor:
            raise ValueError("Auditor not found")

        # Check if auditor has Auditor role
        from utils.rbac import get_active_user_roles
        roles = get_active_user_roles(db, auditor_id)
        if "Auditor" not in roles:
            raise ValueError("User does not have Auditor role")

        # Get the most recent entry in the audit log (this is what we'll verify up to)
        last_entry = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
        if not last_entry:
            raise ValueError("No audit entries to verify")

        # Get last verification to know where to start checking
        last_verification = AuditService.get_last_verification(db)
        from_entry = 0  # Initialize for scope

        if last_verification:
            # INCREMENTAL VERIFICATION APPROACH:
            # We TRUST the previous signature. The auditor's digital signature
            # guarantees that entries up to that point were valid at the time.
            #
            # If an attacker modifies entries AFTER they were signed, that's a
            # different security concern (physical/database security), not audit integrity.
            # The signature proves "at time T, entries 1-N were valid and I verified them".
            #
            # Therefore, we only need to verify:
            # 1. The checkpoint entry still matches what was signed (not modified)
            # 2. New entries form a valid chain from the checkpoint onwards

            previously_verified_entry = db.query(AuditLog).filter(
                AuditLog.id == last_verification.audit_log_entry_id
            ).first()

            if not previously_verified_entry:
                raise ValueError(
                    f"Previously verified entry {last_verification.audit_log_entry_id} has been deleted! "
                    "This indicates tampering with the audit log.")

            # CRITICAL: Verify the checkpoint entry hasn't been modified
            # The signature guarantees this entry was valid and had this specific hash
            if previously_verified_entry.entryHash != last_verification.verifiedUpToHash:
                raise ValueError(
                    f"CRITICAL: Previously verified entry {last_verification.audit_log_entry_id} has been tampered with! "
                    f"Expected hash: {last_verification.verifiedUpToHash}, "
                    f"Current hash: {previously_verified_entry.entryHash}. "
                    "The signed checkpoint has been compromised.")

            from_entry = last_verification.audit_log_entry_id

            # Check if there are new entries to verify
            if last_entry.id <= from_entry:
                raise ValueError(
                    f"No new entries to verify. Last verification was at entry {from_entry}, "
                    f"latest entry is {last_entry.id}")

            # INCREMENTAL: Verify only NEW entries (after the signed checkpoint)
            # The chain link between checkpoint and new entries guarantees integrity
            print(
                f"[INFO] Verifying new entries from {from_entry + 1} to {last_entry.id} (incremental)")
            verify_result = AuditService.verify_chain(
                db, from_entry_id=from_entry)
        else:
            # First verification: verify entire chain
            print(
                f"[INFO] First verification: verifying entire chain up to entry {last_entry.id}")
            verify_result = AuditService.verify_chain(db, from_entry_id=None)

        if not verify_result["valid"]:
            raise ValueError(
                f"Cannot verify: chain is broken - {verify_result['message']}")

        verification = AuditVerification(
            timestamp=datetime.utcnow(),
            verifiedUpToHash=last_entry.entryHash,
            signature=signature,
            audit_log_entry_id=last_entry.id,
            auditor_id=auditor_id
        )

        db.add(verification)
        db.commit()

        verified_range = f"entries {from_entry + 1}-{last_entry.id}" if last_verification else f"entries 1-{last_entry.id}"
        print(f"[INFO] Auditor {auditor_id} verified {verified_range}")

        return verification

    @staticmethod
    def get_last_verification(db: Session) -> AuditVerification | None:
        """Get the most recent audit verification"""
        return db.query(AuditVerification).order_by(
            AuditVerification.audit_log_entry_id.desc()
        ).first()

    @staticmethod
    def get_all_verifications(db: Session) -> list[dict]:
        """Get all audit verifications with auditor information"""
        verifications = db.query(AuditVerification).order_by(
            AuditVerification.timestamp.desc()
        ).all()

        result = []
        for v in verifications:
            auditor = db.query(User).filter(User.id == v.auditor_id).first()
            result.append({
                "id": v.id,
                "timestamp": v.timestamp.isoformat(),
                "verified_up_to_entry_id": v.audit_log_entry_id,
                "verified_up_to_hash": v.verifiedUpToHash,
                "signature": v.signature,
                "auditor_id": v.auditor_id,
                "auditor_username": auditor.username if auditor else "Unknown"
            })

        return result

    @staticmethod
    def verify_new_entries(db: Session) -> dict:
        """
        Verify only entries created after the last verification.
        This is the incremental verification workflow.
        """
        last_verification = AuditService.get_last_verification(db)

        if last_verification:
            print(
                f"[INFO] Last verification at entry {last_verification.audit_log_entry_id}")
            return AuditService.verify_chain(
                db,
                from_entry_id=last_verification.audit_log_entry_id
            )
        else:
            print("[INFO] No previous verification found, performing full verification")
            return AuditService.verify_chain(db)

    @staticmethod
    def get_verifications(db: Session, log_entry: AuditLog) -> dict:
        """
        Valida se uma ação era valida nesse momento 
        """

        action_timestamp = log_entry.timestamp
        actor_id = log_entry.actor_id
        action_type = log_entry.action

        # Detalhes da ação
        try:
            details = json.loads(log_entry.action.split(": ", 1)[
                                 1]) if ": " in log_entry.action else {}
        except (json.JSONDecodeError, IndexError):
            details = {}

        required_role = AuditService.get_required_role_for_action(action_type)
        if required_role:
            had_role = db.query(RoleToken).filter(
                RoleToken.target_id == actor_id,
                RoleToken.created_at <= action_timestamp,

                # Criado antes
                (RoleToken.expires_at > action_timestamp) |
                (RoleToken.expires_at.is_(None))
            ).join(Role).filter(
                Role.label == required_role
            ).first()

            if not had_role:
                return {
                    "valid": False,
                    "message": f"User did not have required role '{required_role}' for action at the time",
                    "action_id": log_entry.id,
                    "actor_id": actor_id,
                    "action": action_type
                }

            # Check se foi revogado antes da ação
            was_revoked = db.query(RoleRevocation).filter(
                RoleRevocation.role_token_id == had_role.id,
                RoleRevocation.revoked_at <= action_timestamp  # Revogado antes
            ).first()

            if was_revoked:
                return {
                    "valid": False,
                    "message": f"User's role '{required_role}' was revoked before the action time",
                    "action_id": log_entry.id,
                    "actor_id": actor_id,
                    "action": action_type
                }

        # VALIDAÇÃO 2: User tinha clearance necessária
        if action_type in ["UPLOAD_FILE", "DOWNLOAD_FILE"]:
            required_level = details.get("classification_level")

            had_clearance = db.query(ClearanceToken).filter(
                ClearanceToken.user_id == actor_id,
                ClearanceToken.created_at <= action_timestamp,
                # Criado antes
                (ClearanceToken.expiration_time > action_timestamp) |
                (ClearanceToken.expiration_time.is_(None))
            ).join(ClearanceLevel).filter(
                ClearanceLevel.label == required_level
            ).first()

            if not had_clearance:
                return {
                    "valid": False,
                    "message": f"User did not have clearance {required_level} at {action_timestamp}",
                    "action_id": log_entry.id,
                    "actor_id": actor_id,
                    "action": action_type
                }

            # Check revogação
            was_revoked = db.query(ClearanceRevocation).filter(
                ClearanceRevocation.clearance_token_id == had_clearance.id,
                ClearanceRevocation.revoked_at <= action_timestamp
            ).first()

            if was_revoked:
                return {
                    "valid": False,
                    "message": f"Clearance was revoked at {was_revoked.revoked_at}",
                    "action_id": log_entry.id,
                    "actor_id": actor_id,
                    "action": action_type
                }

        return {
            "valid": True,
            "message": "Action was legitimate",
            "action_id": log_entry.id,
            "actor_id": actor_id,
            "action": action_type
        }

    @staticmethod
    def get_required_role_for_action(action_type: str) -> str | None:
        """Mapeia ações para roles necessárias"""
        # Extract base action if it has details appended
        base_action = action_type.split(":")[0].strip()

        action_role_map = {
            "CREATE_USER": "Administrator",
            "ASSIGN_CLEARANCE": "Security Officer",
            "REVOKE_CLEARANCE": "Security Officer",
            "ASSIGN_ROLE": "Security Officer",
            "CREATE_DEPARTMENT": "Administrator",
            "TRUSTED_OFFICER_DOWNGRADE": "Trusted Officer",
        }
        return action_role_map.get(base_action)
