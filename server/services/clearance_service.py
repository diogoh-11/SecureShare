from sqlalchemy.orm import Session
from sqlalchemy import text
from models.models import ClearanceToken, Department, ClearanceLevel, User, RoleToken, Role, RoleRevocation
from utils.jwt_utils import sign_data, verify_signature
from datetime import datetime, timedelta
from typing import List, Optional
import json

class ClearanceService:
    @staticmethod
    def create_clearance_token(
        db: Session,
        issuer_id: int,
        user_id: int,
        clearance_level: str,
        departments: List[str],
        expires_in_days: int = 30,
        is_organizational: bool = False
    ):
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
            dept = db.query(Department).filter(Department.label == dept_label).first()
            if dept:
                department_objs.append(dept)

        expiration = datetime.utcnow() + timedelta(days=expires_in_days)

        clearance_token = ClearanceToken(
            expiration_time=expiration,
            is_organizational=is_organizational,
            issuer_id=issuer_id,
            user_id=user_id,
            clearance_level_id=clearance_obj.id
        )

        db.add(clearance_token)
        db.flush()

        for dept in department_objs:
            db.execute(
                text("INSERT INTO clearance_department (clearance_token_id, department_id) VALUES (:token_id, :dept_id)"),
                {"token_id": clearance_token.id, "dept_id": dept.id}
            )

        db.commit()

        return clearance_token

    @staticmethod
    def get_user_clearances(db: Session, user_id: int):
        clearances = db.query(ClearanceToken, ClearanceLevel).join(
            ClearanceLevel, ClearanceToken.clearance_level_id == ClearanceLevel.id
        ).filter(
            ClearanceToken.user_id == user_id,
            (ClearanceToken.expiration_time > datetime.utcnow()) | (ClearanceToken.expiration_time == None)
        ).all()

        result = []
        for clearance_token, clearance_level in clearances:
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
                "issuer_id": clearance_token.issuer_id
            })

        return result

class RoleService:
    @staticmethod
    def assign_role(
        db: Session,
        issuer_id: int,
        target_id: int,
        role_label: str,
        expires_in_days: Optional[int] = None
    ):
        role = db.query(Role).filter(Role.label == role_label).first()
        if not role:
            raise ValueError(f"Role '{role_label}' not found")

        target_user = db.query(User).filter(User.id == target_id).first()
        if not target_user:
            raise ValueError("Target user not found")

        expiration = None
        if expires_in_days:
            expiration = datetime.utcnow() + timedelta(days=expires_in_days)

        token_data = {
            "role": role_label,
            "target_id": target_id,
            "issuer_id": issuer_id,
            "expires_at": expiration.isoformat() if expiration else None
        }

        signature = sign_data(json.dumps(token_data, sort_keys=True).encode())

        role_token = RoleToken(
            role_id=role.id,
            signature=signature,
            expires_at=expiration,
            target_id=target_id,
            issuer_id=issuer_id
        )

        db.add(role_token)
        db.commit()

        return role_token

    @staticmethod
    def revoke_role(db: Session, revoker_id: int, role_token_id: int):
        role_token = db.query(RoleToken).filter(RoleToken.id == role_token_id).first()
        if not role_token:
            raise ValueError("Role token not found")

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
