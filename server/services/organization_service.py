from sqlalchemy.orm import Session
from models.models import Organization, User, Role, RoleToken, RecoveryTokens
from schemas.schemas import CreateOrganizationRequest
from enums import RoleEnum
import secrets
from utils.funcs import generate_codes, sha256
from utils.rbac import role2user


class OrganizationService:

    @staticmethod
    def create_organization(db: Session, request: CreateOrganizationRequest) -> dict:
        """
        Creates a new organization with an inactive admin user.
        Generates an activation code for the admin to complete FIDO2 registration.

        Args:
            db: Database session
            request: Organization creation request with admin username and org name

        Returns:
            Dict with organization info and activation code

        Raises:
            ValueError: If username or organization name already exists
        """
        # Check if username already exists
        existing_user = db.query(User).filter(User.username == request.admin_username).first()
        if existing_user:
            raise ValueError("Username already exists")

        # Check if organization name already exists
        existing_org = db.query(Organization).filter(Organization.name == request.org_name).first()
        if existing_org:
            raise ValueError("Organization name already exists")

        # Create organization FIRST (without admin_id for now)
        organization = Organization(
            admin_id=None,  # Will be set after user activates
            name=request.org_name
        )

        db.add(organization)
        db.flush()  # Flush to get organization ID

        # Create inactive admin user (will be activated after FIDO2 registration)
        admin_user = User(
            username=request.admin_username,
            public_key=None,
            private_key_blob=None,
            is_active=False,  # User must complete FIDO2 registration
            organization_id=organization.id  # Associate with the organization
        )

        db.add(admin_user)
        db.flush()

        # Generate activation code
        activation_code = generate_codes(1)[0]
        hashed_code = sha256(activation_code)

        # Store activation token
        recovery_token = RecoveryTokens(
            user_id=admin_user.id,
            hashed_value=hashed_code,
            is_used=False
        )
        db.add(recovery_token)

        # Store a reference that this user should become admin of this org
        # We'll use the organization's admin_id field, but keep user inactive
        organization.admin_id = admin_user.id

        db.commit()
        db.refresh(organization)

        return {
            "organization": organization,
            "activation_code": activation_code,
            "username": request.admin_username
        }

    @staticmethod
    def finalize_admin_role(db: Session, user_id: int, organization_id: int):
        """
        Creates the admin role token after user completes FIDO2 registration.
        This should be called from the auth service after successful registration.

        Args:
            db: Database session
            user_id: ID of the newly activated user
            organization_id: ID of the organization to grant admin rights for
        """
        role2user(
            db,
            b"bootstrap",
            RoleEnum.ADMINISTRATOR.value,
            None,
            user_id,
            user_id
        )
