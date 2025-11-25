from fastapi import APIRouter, HTTPException, Depends
from schemas.schemas import CreateDepartmentRequest

router = APIRouter(prefix="/departments", tags=["Department Management"])


@router.post("")
async def create_department(request: CreateDepartmentRequest):
    """
    Creates a new department.
    Authorization: Administrator only
    """
    # TODO: Verify Administrator role
    # TODO: Create department in DB
    pass


@router.get("")
async def get_departments():
    """
    Retrieves a list of all departments.
    """
    # TODO: Fetch all departments from DB
    # TODO: Return list
    pass


@router.delete("/{dept_id}")
async def delete_department(dept_id: int):
    """
    Deletes a department.
    Authorization: Administrator only
    """
    # TODO: Verify Administrator role
    # TODO: Check if department is in use
    # TODO: Delete department from DB
    pass
