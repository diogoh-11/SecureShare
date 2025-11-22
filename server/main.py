from fastapi import FastAPI
import uvicorn

from database import engine, Base
from models.models import (
    Organization, User, Department, ClearanceLevel,
    Transfer, TransferKey, Role, RoleToken, RoleRevocation, ClearanceToken
)

from routers import authentication, user_management, department_management, file_transfer

app = FastAPI(
    title="SShare API",
    description="Secure file sharing system with MLS access control",
    version="1.0.0"
)

# init db
@app.on_event("startup")
async def startup_event():
    """Create database tables on startup"""
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully!")

# include routers
app.include_router(authentication.router)
app.include_router(user_management.router)
app.include_router(department_management.router)
app.include_router(file_transfer.router)

@app.get("/")
async def root():
    return {"status": "ok", "message": "SShare API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
