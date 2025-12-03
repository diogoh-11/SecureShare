from fastapi import FastAPI
import uvicorn

from database import engine, Base, SessionLocal
from models.models import (
    Organization, User, Department, ClearanceLevel,
    Transfer, TransferKey, Role, RoleToken, RoleRevocation,
    ClearanceToken, Session, RecoveryTokens
)

from routers import api
from services.seed_service import SeedService
from utils.jwt_utils import init_signing_keys

app = FastAPI(
    title="SShare",
    description="SIO 25/26 university project",
    version="1.0.0",
)

@app.on_event("startup")
async def startup_event():
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully!")

    init_signing_keys()
    print("Signing keys initialized successfully!")

    db = SessionLocal()
    try:
        SeedService.seed_all(db)

        # Clean up expired sessions on startup
        from services.auth_service import AuthService
        AuthService.cleanup_expired_sessions(db)
        print("Session cleanup completed!")
    finally:
        db.close()

# include routers
app.include_router(api.api_router, prefix="/api")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="certs/key.pem",
        ssl_certfile="certs/cert.pem",
        reload=True
    )
