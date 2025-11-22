from sqlalchemy.orm import Session
from models.models import Organization, User
from schemas.schemas import CreateOrganizationRequest
import hashlib


class OrganizationService:

    @staticmethod
    def create_organization(db: Session, request: CreateOrganizationRequest) -> Organization:
        """
        Creates a new organization with an admin user.
        Creates both the admin user and organization in a single transaction.

        Args:
            db: Database session
            request: Organization creation request with admin details

        Returns:
            Created Organization object

        Raises:
            ValueError: If username already exists
        """
        existing_user = db.query(User).filter(User.username == request.admin_username).first()
        if existing_user:
            raise ValueError("Username already exists")

        password_hash = hashlib.sha256(request.admin_password.encode()).hexdigest()

        admin_user = User(
            username=request.admin_username,
            password_hash=password_hash,
            public_key=request.admin_public_key.encode(),
            private_key_blob=request.admin_private_key_blob.encode(),
            is_active=True
        )

        db.add(admin_user)
        db.flush()

        organization = Organization(
            admin_id=admin_user.id,
            name = request.org_name
        )

        db.add(organization)
        db.commit()
        db.refresh(organization)

        return organization
