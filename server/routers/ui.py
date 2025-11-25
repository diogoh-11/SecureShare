from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(prefix="/ui", tags=["UI"])


@router.get("/register")
async def register_page():
    """Serve simple black/white registration page for TUI"""
    return FileResponse("static/ui/register.html")

@router.get("/login")
async def login_page():
    """Serve simple black/white login page for TUI"""
    return FileResponse("static/ui/login.html")
