import hashlib
import secrets
from fastapi import HTTPException



def sha256(code: str) -> str:
    """Hash using SHA-256"""
    return hashlib.sha256(code.encode()).hexdigest()

def generate_codes(count: int = 10, size:int = 12) -> list[str]:
    """Generate cryptographically secure codes"""
    return ["C"+secrets.token_urlsafe(size) for _ in range(count)]

def required(v, t):
    if not v:
        raise HTTPException(status_code=400, detail=f"{t} required")
