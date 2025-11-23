from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(prefix="/ui", tags=["UI"])


@router.get("/test")
async def test_page():
    """Serve FIDO2 test page"""
    return FileResponse("/app/static/ui/test-fido2.html")
