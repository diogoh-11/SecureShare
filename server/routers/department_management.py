from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from database import get_db
from schemas.schemas import CreateDepartmentRequest
from models.models import Department, User
from utils.rbac import require_role, get_current_user
from services.audit_service import AuditService

router = APIRouter(prefix="/departments", tags=["Department Management"])


@router.post("")
async def create_department(
    request: CreateDepartmentRequest,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Administrator"]))
):
    user, _ = user_db

    existing = db.query(Department).filter(Department.label == request.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Department already exists")

    if not user.organization_id:
        raise HTTPException(status_code=400, detail="User has no organization")

    department = Department(
        label=request.name,
        organization_id=user.organization_id
    )

    db.add(department)
    db.commit()
    db.refresh(department)

    AuditService.log_action(db, user.id, "CREATE_DEPARTMENT", {"department": request.name})

    return {"id": department.id, "label": department.label}


@router.get("")
async def get_departments(db: Session = Depends(get_db)):
    departments = db.query(Department).all()
    return [{"id": d.id, "label": d.label} for d in departments]


@router.delete("/{dept_id}")
async def delete_department(
    dept_id: int,
    user_db: tuple = Depends(get_current_user),
    db: Session = Depends(require_role(["Administrator"]))
):
    user, _ = user_db

    department = db.query(Department).filter(Department.id == dept_id).first()
    if not department:
        raise HTTPException(status_code=404, detail="Department not found")

    db.delete(department)
    db.commit()

    AuditService.log_action(db, user.id, "DELETE_DEPARTMENT", {"department_id": dept_id})

    return {"status": "deleted"}
