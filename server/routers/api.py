from fastapi import APIRouter
from routers import authentication, user_management, department_management, file_transfer, organization_management, audit

api_router = APIRouter()

api_router.include_router(organization_management.router)
api_router.include_router(authentication.router)
api_router.include_router(user_management.router)
api_router.include_router(department_management.router)
api_router.include_router(file_transfer.router)
api_router.include_router(audit.router)


@api_router.get("/health")
async def health_check():
    return {"status": "healthy"}
