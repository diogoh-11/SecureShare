from sqlalchemy.orm import Session
from models.models import User, RecoveryTokens
from utils.funcs import sha256, generate_codes
from utils.rbac import role2user

class UserManagementService:

    @staticmethod
    def create_user(db: Session, username: str, issuer_id: int, organization_id: int) -> dict:
        """
        Create a new user with 1 activation code and assign Standard User role.

        Args:
            db: Database session
            username: Username for the new user
            issuer_id: ID of the admin creating this user
            organization_id: Organization ID to assign the user to

        Returns:
            dict with 'user' and 'activation_code'
        """

        # check if user exists
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            raise ValueError("Username already exists")

        # create new user
        user = User(
            username=username,
            is_active=False,
            organization_id=organization_id
        )
        db.add(user)
        db.flush()

        # gen the activation code
        activation_code = generate_codes(1)[0]

        # store token
        token = RecoveryTokens(
            user_id=user.id,
            hashed_value=sha256(activation_code),
            is_used=False
        )
        db.add(token)

        db.commit()
        db.refresh(user)

        # Assign Standard User role
        from enums import RoleEnum
        role2user(
            db=db,
            signature=b"admin_created",
            role=RoleEnum.STANDARD_USER.value,
            expires_at=None,  # No expiration
            target_id=user.id,
            issuer_id=issuer_id,
        )

        return {
            'user': user,
            'activation_code': activation_code
        }

    @staticmethod
    def get_all_users(db: Session, organization_id:int) -> list[User]:
        """Get all users"""
        return db.query(User).filter(User.organization_id == organization_id).all()

    @staticmethod
    def delete_user(db: Session, user_id: int) -> bool:
        """Delete user and associated data"""
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        # clear tokens
        db.query(RecoveryTokens).filter(RecoveryTokens.user_id == user_id).delete()
        db.delete(user)
        db.commit()
        return True

    @staticmethod
    def get_user_public_key(db: Session, user_id: int) -> bytes:
        """Get user's public key for file encryption"""
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise ValueError("User not found")
        if not user.public_key:
            raise ValueError("User has not activated their account")
        return user.public_key
