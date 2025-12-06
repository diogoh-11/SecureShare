from utils.rbac import role2user
from sqlalchemy.orm import Session
from sqlalchemy import text
from models.models import ClearanceToken, Department, ClearanceLevel, User, RoleToken, Role, RoleRevocation, ClearanceRevocation
from datetime import datetime, timedelta
from typing import List, Optional
import json
from enums import RoleEnum


class ClearanceService:
    @staticmethod
    def create_clearance_token(
        db: Session,
        issuer_id: int,
        user_id: int,
        clearance_level: str,
        departments: List[str],
        signature_b64: str,
        expires_at_iso: str,
        is_organizational: bool = False
    ):
        from services.user_management_service import UserManagementService
        from utils.crypto_utils import verify_signature

        clearance_obj = db.query(ClearanceLevel).filter(
            ClearanceLevel.label == clearance_level
        ).first()

        if not clearance_obj:
            raise ValueError(f"Clearance level '{clearance_level}' not found")

        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")

        department_objs = []
        for dept_label in departments:
            dept = db.query(Department).filter(
                Department.label == dept_label).first()
            if dept:
                department_objs.append(dept)

        # Parse the expiration time from the request
        expiration = datetime.fromisoformat(expires_at_iso.replace('Z', '+00:00'))

        # Build the same token data structure that the client signed
        token_data = {
            "clearance_level": clearance_level,
            "user_id": user_id,
            "issuer_id": issuer_id,
            "departments": sorted(departments),  # Sort for consistent signature
            "expires_at": expires_at_iso,
            "is_organizational": is_organizational
        }
        token_data_str = json.dumps(token_data, sort_keys=True)

        # Verify signature using issuer's public key
        issuer_public_key = UserManagementService.get_user_public_key(db, issuer_id)
        if not verify_signature(token_data_str, signature_b64, issuer_public_key):
            raise ValueError("Invalid signature on clearance token")

        # Convert signature to bytes for storage
        import base64
        signature_bytes = base64.b64decode(signature_b64)

        clearance_token = ClearanceToken(
            expiration_time=expiration,
            is_organizational=is_organizational,
            issuer_id=issuer_id,
            user_id=user_id,
            clearance_level_id=clearance_obj.id,
            signature=signature_bytes
        )

        db.add(clearance_token)
        db.flush()

        for dept in department_objs:
            db.execute(
                text(
                    "INSERT INTO clearance_department (clearance_token_id, department_id) VALUES (:token_id, :dept_id)"),
                {"token_id": clearance_token.id, "dept_id": dept.id}
            )

        db.commit()

        return clearance_token

    @staticmethod
    def get_user_clearances(db: Session, user_id: int):
        clearances = db.query(ClearanceToken, ClearanceLevel).join(
            ClearanceLevel, ClearanceToken.clearance_level_id == ClearanceLevel.id
        ).filter(
            ClearanceToken.user_id == user_id
        ).all()

        result = []
        for clearance_token, clearance_level in clearances:
            # Check if revoked
            is_revoked = db.query(ClearanceRevocation).filter(
                ClearanceRevocation.clearance_token_id == clearance_token.id
            ).first() is not None

            # Check if expired
            is_expired = False
            if clearance_token.expiration_time:
                is_expired = clearance_token.expiration_time < datetime.utcnow()

            is_active = not is_revoked and not is_expired

            departments = db.execute(
                text("SELECT d.label FROM departments d "
                     "JOIN clearance_department cd ON d.id = cd.department_id "
                     "WHERE cd.clearance_token_id = :token_id"),
                {"token_id": clearance_token.id}
            ).fetchall()

            result.append({
                "id": clearance_token.id,
                "clearance_level": clearance_level.label,
                "departments": [d[0] for d in departments],
                "is_organizational": clearance_token.is_organizational,
                "expires_at": clearance_token.expiration_time.isoformat() if clearance_token.expiration_time else None,
                "issuer_id": clearance_token.issuer_id,
                "is_active": is_active,
                "is_revoked": is_revoked,
                "is_expired": is_expired
            })

        return result

    @staticmethod
    def revoke_clearance(db: Session, revoker_id: int, clearance_token_id: int):
        """Revoke a clearance token"""
        clearance_token = db.query(ClearanceToken).filter(
            ClearanceToken.id == clearance_token_id
        ).first()

        if not clearance_token:
            raise ValueError("Clearance token not found")

        # Check if already revoked
        existing_revocation = db.query(ClearanceRevocation).filter(
            ClearanceRevocation.clearance_token_id == clearance_token_id
        ).first()

        if existing_revocation:
            raise ValueError("Clearance token already revoked")

        # Create revocation record
        revocation = ClearanceRevocation(
            clearance_token_id=clearance_token_id,
            revoker_id=revoker_id
        )

        db.add(revocation)
        db.commit()

        print(
            f"[INFO] Revoked clearance token {clearance_token_id} for user {clearance_token.user_id}")

        return revocation


class RoleService:
    @staticmethod
    def assign_role(
        db: Session,
        issuer_id: int,
        target_id: int,
        role_label: str,
        signature_b64: str,
        expires_at_iso: Optional[str] = None
    ):
        from services.user_management_service import UserManagementService
        from utils.crypto_utils import verify_signature

        role: Role | None = db.query(Role).filter(
            Role.label == role_label).first()
        if not role:
            raise ValueError(f"Role '{role_label}' not found")

        # PROTECTION: Cannot assign Administrator or Standard User role via this endpoint
        if role.label == RoleEnum.ADMINISTRATOR:
            raise ValueError(f"Cannot assign {role.label} - Administrators can only be created during organization setup")

        if role.label == RoleEnum.STANDARD_USER:
            raise ValueError("Cannot assign Standard User - everyone is Standard User by default")

        target_user = db.query(User).filter(User.id == target_id).first()
        if not target_user:
            raise ValueError("Target user not found")

        from utils.rbac import get_active_user_roles
        target_roles = get_active_user_roles(db, target_id)
        if RoleEnum.ADMINISTRATOR.value in target_roles:
            raise ValueError("Cannot modify Administrator role")

        # Check what roles the issuer has
        issuer_roles = get_active_user_roles(db, issuer_id)

        if RoleEnum.ADMINISTRATOR.value in issuer_roles :
            if role_label != RoleEnum.SECURITY_OFFICER.value:
                raise ValueError(f"Administrators can only assign Security Officer role, not '{role_label}'")

        elif RoleEnum.SECURITY_OFFICER.value in issuer_roles:
            if role_label not in [RoleEnum.TRUSTED_OFFICER.value, RoleEnum.AUDITOR.value]:
                raise ValueError(f"Security Officers can only assign Trusted Officer or Auditor roles, not '{role_label}'")

        else:
            raise ValueError("You do not have permission to assign roles")

        privileged_roles = [r for r in target_roles if r != RoleEnum.STANDARD_USER.value]
        if privileged_roles:
            raise ValueError(f"User already has privileged role '{privileged_roles[0]}'.")

        # Parse expiration if provided
        expiration = None
        if expires_at_iso:
            expiration = datetime.fromisoformat(expires_at_iso.replace('Z', '+00:00'))

        # Build the same token data structure that the client signed
        token_data = {
            "role": role_label,
            "target_id": target_id,
            "issuer_id": issuer_id,
            "expires_at": expires_at_iso
        }
        token_data_str = json.dumps(token_data, sort_keys=True)

        # Verify signature using issuer's public key
        issuer_public_key = UserManagementService.get_user_public_key(db, issuer_id)
        if not verify_signature(token_data_str, signature_b64, issuer_public_key):
            raise ValueError("Invalid signature on role token")

        # Convert signature to bytes for storage
        import base64
        signature_bytes = base64.b64decode(signature_b64)

        role_token = role2user(
            db,
            signature_bytes,
            role_label,
            expires_at=expiration,
            target_id=target_id,
            issuer_id=issuer_id
        )

        print(f"[INFO] Assigned role '{role_label}' to user {target_id}")

        return role_token

    @staticmethod
    def revoke_role(db: Session, revoker_id: int, role_token_id: int):
        role_token = db.query(RoleToken, Role).join(
            Role, RoleToken.role_id == Role.id
        ).filter(
            RoleToken.id == role_token_id
        ).first()

        if not role_token:
            raise ValueError("Role token not found")

        _, role = role_token

        # PROTECTION: Cannot revoke Administrator roles
        if role.label in [RoleEnum.ADMINISTRATOR.value, RoleEnum.SECURITY_OFFICER.value]:
            raise ValueError(f"Cannot revoke {role.label} role")

        existing_revocation = db.query(RoleRevocation).filter(
            RoleRevocation.role_token_id == role_token_id
        ).first()

        if existing_revocation:
            raise ValueError("Role token already revoked")

        revocation = RoleRevocation(
            role_token_id=role_token_id,
            revoker_id=revoker_id
        )

        db.add(revocation)
        db.commit()

        return revocation

    @staticmethod
    def get_user_roles(db: Session, user_id: int):
        from utils.rbac import get_active_user_roles

        active_roles = get_active_user_roles(db, user_id)

        role_tokens = db.query(RoleToken, Role).join(
            Role, RoleToken.role_id == Role.id
        ).filter(
            RoleToken.target_id == user_id
        ).all()

        result = []
        for role_token, role in role_tokens:
            is_revoked = db.query(RoleRevocation).filter(
                RoleRevocation.role_token_id == role_token.id
            ).first() is not None

            result.append({
                "id": role_token.id,
                "role": role.label,
                "is_active": role.label in active_roles,
                "is_revoked": is_revoked,
                "expires_at": role_token.expires_at.isoformat() if role_token.expires_at else None,
                "issuer_id": role_token.issuer_id
            })

        return result
