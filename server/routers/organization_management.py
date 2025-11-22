from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
from schemas.schemas import CreateOrganizationRequest, OrganizationResponse
from services.organization_service import OrganizationService

router = APIRouter(prefix="/organizations", tags=["Organization Management"])


@router.post("", response_model=OrganizationResponse)
async def create_organization(request: CreateOrganizationRequest, db: Session = Depends(get_db)):
    """
    Creates a new organization with an admin user.
    Creates both the admin user and organization in a single transaction.
    """
    try:
        organization = OrganizationService.create_organization(db, request)
        return OrganizationResponse(
            id=organization.id,
            admin_id=organization.admin_id
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
