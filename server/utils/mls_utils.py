from sqlalchemy.orm import Session
from sqlalchemy import text
from models.models import ClearanceToken, ClearanceLevel, Department, Transfer, User, ClearanceRevocation
from typing import List, Set, Optional
from datetime import datetime
from enums import ClearanceLevelEnum

CLEARANCE_HIERARCHY = {
    ClearanceLevelEnum.UNCLASSIFIED: 0,
    ClearanceLevelEnum.CONFIDENTIAL: 1,
    ClearanceLevelEnum.SECRET: 2,
    ClearanceLevelEnum.TOP_SECRET: 3
}

def get_clearance_level_value(level: str) -> int:
    for enum_val, numeric_val in CLEARANCE_HIERARCHY.items():
        if enum_val.value == level:
            return numeric_val
    return 0

def get_specific_clearance(db: Session, user_id: int, clearance_token_id: int) -> tuple[str, Set[str]]:
    """
    Get clearance for a specific token ID.
    Returns (clearance_level, departments) or None if token not found/invalid.
    """
    clearance = db.query(ClearanceToken, ClearanceLevel).join(
        ClearanceLevel, ClearanceToken.clearance_level_id == ClearanceLevel.id
    ).filter(
        ClearanceToken.id == clearance_token_id,
        ClearanceToken.user_id == user_id
    ).first()

    if not clearance:
        return None, None

    clearance_token, clearance_level = clearance

    # Check if revoked
    is_revoked = db.query(ClearanceRevocation).filter(
        ClearanceRevocation.clearance_token_id == clearance_token.id
    ).first() is not None

    if is_revoked:
        return None, None

    # Check if expired
    if clearance_token.expiration_time and clearance_token.expiration_time < datetime.utcnow():
        return None, None

    # Get departments
    departments = db.execute(
        text("SELECT d.label FROM departments d "
             "JOIN clearance_department cd ON d.id = cd.department_id "
             "WHERE cd.clearance_token_id = :token_id"),
        {"token_id": clearance_token.id}
    ).fetchall()

    dept_set = {dept[0] for dept in departments}

    return clearance_level.label, dept_set

def get_user_max_clearance(db: Session, user_id: int) -> tuple[str, Set[str]]:
    clearances = db.query(ClearanceToken, ClearanceLevel).join(
        ClearanceLevel, ClearanceToken.clearance_level_id == ClearanceLevel.id
    ).filter(
        ClearanceToken.user_id == user_id,
        (ClearanceToken.expiration_time > datetime.utcnow()) | (ClearanceToken.expiration_time == None)
    ).all()

    if not clearances:
        return ClearanceLevelEnum.UNCLASSIFIED.value, set()

    max_level = ClearanceLevelEnum.UNCLASSIFIED.value
    all_departments = set()

    for clearance_token, clearance_level in clearances:
        # CRITICAL: Check if clearance is revoked
        is_revoked = db.query(ClearanceRevocation).filter(
            ClearanceRevocation.clearance_token_id == clearance_token.id
        ).first() is not None

        if is_revoked:
            # Skip revoked clearances
            continue

        level_value = get_clearance_level_value(clearance_level.label)
        if level_value > get_clearance_level_value(max_level):
            max_level = clearance_level.label

        departments = db.execute(
            text("SELECT d.label FROM departments d "
                 "JOIN clearance_department cd ON d.id = cd.department_id "
                 "WHERE cd.clearance_token_id = :token_id"),
            {"token_id": clearance_token.id}
        ).fetchall()

        for dept in departments:
            all_departments.add(dept[0])

    return max_level, all_departments

def get_transfer_classification(db: Session, transfer_id: int) -> tuple[str, Set[str]]:
    transfer = db.query(Transfer, ClearanceLevel).join(
        ClearanceLevel, Transfer.classification_level_id == ClearanceLevel.id
    ).filter(
        Transfer.id == transfer_id
    ).first()

    if not transfer:
        return None, None

    transfer_obj, classification = transfer

    departments = db.execute(
        text("SELECT d.label FROM departments d "
             "JOIN transfer_department td ON d.id = td.department_id "
             "WHERE td.transfer_id = :transfer_id"),
        {"transfer_id": transfer_id}
    ).fetchall()

    dept_set = {dept[0] for dept in departments}

    return classification.label, dept_set

def can_read(user_level: str, user_depts: Set[str], object_level: str, object_depts: Set[str]) -> bool:
    user_level_value = get_clearance_level_value(user_level)
    object_level_value = get_clearance_level_value(object_level)

    if user_level_value < object_level_value:
        return False

    if not object_depts.issubset(user_depts):
        return False

    return True

def can_write(user_level: str, user_depts: Set[str], object_level: str, object_depts: Set[str]) -> bool:
    user_level_value = get_clearance_level_value(user_level)
    object_level_value = get_clearance_level_value(object_level)

    # No Write Down: can only write at or above clearance level
    if user_level_value > object_level_value:
        return False

    # Compartments: user must have clearance in ALL departments the object requires
    if not object_depts.issubset(user_depts):
        return False

    return True

def check_transfer_read_access(db: Session, user_id: int, transfer_id: int, clearance_token_id: Optional[int] = None) -> bool:
    """
    Check if user can read a transfer.
    If clearance_token_id is provided, use that specific clearance.
    If not provided, user has no clearance (Unclassified only).
    """
    if clearance_token_id:
        user_level, user_depts = get_specific_clearance(db, user_id, clearance_token_id)
        if user_level is None:
            # Invalid or revoked clearance token
            return False
    else:
        # No clearance specified - user has no clearance
        user_level = ClearanceLevelEnum.UNCLASSIFIED.value
        user_depts = set()

    transfer_level, transfer_depts = get_transfer_classification(db, transfer_id)

    if transfer_level is None:
        return False

    if transfer_depts is None:
        transfer_depts = set()

    return can_read(user_level, user_depts, transfer_level, transfer_depts)

def check_transfer_write_access(
    db: Session,
    user_id: int,
    classification_level: str,
    departments: List[str],
    clearance_token_id: Optional[int] = None
) -> bool:
    """
    Check if user can write at the specified classification level.
    If clearance_token_id is provided, use that specific clearance.
    If not provided, user has no clearance (Unclassified only).
    """
    if clearance_token_id:
        user_level, user_depts = get_specific_clearance(db, user_id, clearance_token_id)
        if user_level is None:
            # Invalid or revoked clearance token
            return False
    else:
        # No clearance specified - user has no clearance
        user_level = ClearanceLevelEnum.UNCLASSIFIED.value
        user_depts = set()

    dept_set = set(departments)

    return can_write(user_level, user_depts, classification_level, dept_set)

def is_trusted_officer(db: Session, user_id: int) -> bool:
    from utils.rbac import get_active_user_roles

    roles = get_active_user_roles(db, user_id)
    return "Trusted Officer" in roles
