import time
from sqlalchemy.orm import Session
from typing import Optional
from fastapi import HTTPException, Header, Depends
from database import get_db
from models.models import Role, RoleToken

def role2user(db: Session, signature: bytes, role: str, expires_at: Optional[int], target_id: int, issuer_id: int):
    """
    Assign a role to a user.

    Args:
        db: Database session
        signature: Signature bytes for the role token
        role: Role label (e.g., "Standard User", "Administrator")
        expires_at: Expiration timestamp (None for no expiration)
        target_id: User ID receiving the role
        issuer_id: User ID granting the role
        organization_id: Organization ID
    """
    role_obj = db.query(Role).filter(Role.label == role).first()
    if not role_obj:
        raise ValueError(f"Role '{role}' not found in database")

    # Create RoleToken
    role_token = RoleToken(
        role_id=role_obj.id,
        signature=signature,
        expires_at=expires_at,
        target_id=target_id,
        issuer_id=issuer_id,
    )

    db.add(role_token)
    db.commit()

def require_role(required_roles: list[str]):
    """
    FastAPI dependency to check if the authenticated user has any of the required roles.
    Raises HTTPException if unauthorized.

    Args:
        required_roles: List of required role labels

    Returns:
        Database session if authorized

    """

    def role_checker(
        authorization: str = Header(...),
        db: Session = Depends(get_db)
    ):
        from models.models import Session as SessionModel, User

        # Extract session token
        session_token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization

        # Get user from session token
        session = db.query(SessionModel).filter(
            SessionModel.session_token == session_token,
            SessionModel.expires_at > int(time.time())
        ).first()

        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")

        user = db.query(User).filter(User.id == session.user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        # Get user's active roles
        user_roles = get_active_user_roles(db, user.id)

        # Check if user has any of the required roles
        if not any(role in user_roles for role in required_roles):
            raise HTTPException(
                status_code=403,
                detail=f"Required role: {' or '.join(required_roles)}"
            )

        return db

    return role_checker

def get_active_user_roles(db: Session, user_id: int) -> set[str]:
    """
    Get all active (non-expired, non-revoked) roles for a user.

    Args:
        db: Database session
        user_id: ID of the user

    Returns:
        Set of role labels the user has

    Example:
        roles = get_active_user_roles(db, user_id=1)
        # Returns: {"Administrator", "Security Officer"}
    """
    from models.models import RoleToken, Role, RoleRevocation, User

    response = set()

    # Get user's organization
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.organization_id:
        return response

    current_time = time.time()

    # Query all role tokens for this user
    role_tokens = db.query(RoleToken, Role).join(
        Role, RoleToken.role_id == Role.id
    ).filter(
        RoleToken.target_id == user_id,
        RoleToken.organization_id == user.organization_id
    ).all()

    for role_token, role in role_tokens:
        # Check if expired
        if role_token.expires_at is not None:
            token_expiry = role_token.expires_at.timestamp() if hasattr(role_token.expires_at, 'timestamp') else role_token.expires_at
            if token_expiry < current_time:
                continue

        # Check if revoked
        revocation = db.query(RoleRevocation).filter(
            RoleRevocation.role_token_id == role_token.id
        ).first()

        if revocation:
            continue

        response.add(role.label)

    return response
