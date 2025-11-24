from fastapi import FastAPI
import uvicorn

from database import engine, Base, SessionLocal
from models.models import (
    Organization, User, Department, ClearanceLevel,
    Transfer, TransferKey, Role, RoleToken, RoleRevocation,
    ClearanceToken, Session, RecoveryTokens
)

from routers import api, ui
from services.seed_service import SeedService

app = FastAPI(
    title="SShare",
    description="SIO 25/26 university project",
    version="1.0.0",
)

# init db
@app.on_event("startup")
async def startup_event():
    """Create database tables and seed initial data on startup"""
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully!")

    db = SessionLocal()
    try:
        SeedService.seed_all(db)
    finally:
        db.close()

# include routers
app.include_router(api.api_router, prefix="/api")
app.include_router(ui.router)


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="certs/key.pem",
        ssl_certfile="certs/cert.pem",
        reload=True
    )
