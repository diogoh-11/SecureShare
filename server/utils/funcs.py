import hashlib
import secrets



def sha256(code: str) -> str:
    """Hash using SHA-256"""
    return hashlib.sha256(code.encode()).hexdigest()

def generate_codes(count: int = 10, size:int = 12) -> list[str]:
    """Generate cryptographically secure codes"""
    return [secrets.token_urlsafe(size) for _ in range(count)]
