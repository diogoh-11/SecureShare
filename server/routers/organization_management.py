from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
from schemas.schemas import CreateOrganizationRequest, OrganizationCreationResponse
from services.organization_service import OrganizationService
from services.audit_service import AuditService

router = APIRouter(prefix="/organizations", tags=["Organization Management"])


@router.post("", response_model=OrganizationCreationResponse)
async def create_organization(request: CreateOrganizationRequest, db: Session = Depends(get_db)):
    """
    Creates a new organization with an inactive admin user.
    Returns an activation code that the admin must use to complete FIDO2 registration.

    Flow:
    1. User requests organization creation with username and org name
    2. System creates inactive user and organization, generates activation code
    3. User uses activation code to register FIDO2 credential at /api/auth/activate/challenge
    4. After successful FIDO2 registration, user becomes admin of the organization
    """
    try:
        result = OrganizationService.create_organization(db, request)
        
        # Log organization creation (use the new admin user's ID)
        from models.models import User
        admin_user = db.query(User).filter(User.username == result["username"]).first()
        if admin_user:
            AuditService.log_action(db, admin_user.id, "CREATE_ORGANIZATION", {
                "organization_name": result["organization"].name,
                "admin_username": result["username"]
            })
        
        return OrganizationCreationResponse(
            success=True,
            message=f"Organization created. Please activate the admin [{result["username"]}] account.",
            username=result["username"],
            activation_code=result["activation_code"],
            org_name=result["organization"].name
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
