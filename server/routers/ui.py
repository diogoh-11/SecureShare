from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(prefix="/ui", tags=["UI"])


@router.get("/test")
async def test_page():
    """Serve FIDO2 test page"""
    return FileResponse("static/test-register.html")

@router.get("/test/res")
async def test_page_res():
    """Serve FIDO2 test page"""
    return FileResponse("static/test-login.html")
