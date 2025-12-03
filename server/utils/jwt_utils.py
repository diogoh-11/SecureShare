import jwt
import time
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from typing import Optional, Dict, Any

JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 1

SIGNING_PRIVATE_KEY = None
SIGNING_PUBLIC_KEY = None

def init_signing_keys():
    global SIGNING_PRIVATE_KEY, SIGNING_PUBLIC_KEY

    private_key_path = "certs/signing_key.pem"
    public_key_path = "certs/signing_key.pub"

    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, "rb") as f:
            SIGNING_PRIVATE_KEY = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(public_key_path, "rb") as f:
            SIGNING_PUBLIC_KEY = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
    else:
        SIGNING_PRIVATE_KEY = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )
        SIGNING_PUBLIC_KEY = SIGNING_PRIVATE_KEY.public_key()

        os.makedirs("certs", exist_ok=True)
        with open(private_key_path, "wb") as f:
            f.write(SIGNING_PRIVATE_KEY.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(public_key_path, "wb") as f:
            f.write(SIGNING_PUBLIC_KEY.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

def create_access_token(data: Dict[str, Any], expires_delta: Optional[int] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = int(time.time()) + expires_delta
    else:
        expire = int(time.time()) + (JWT_EXPIRATION_HOURS * 3600)

    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])

    to_encode.update({"exp": expire, "iat": int(time.time())})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

def verify_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM], options={"verify_signature": True})
        if "sub" in payload:
            payload["sub"] = int(payload["sub"])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def sign_data(data: bytes) -> bytes:
    if SIGNING_PRIVATE_KEY is None:
        init_signing_keys()
    return SIGNING_PRIVATE_KEY.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(data: bytes, signature: bytes) -> bool:
    if SIGNING_PUBLIC_KEY is None:
        init_signing_keys()
    try:
        SIGNING_PUBLIC_KEY.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def get_signing_public_key_pem() -> bytes:
    if SIGNING_PUBLIC_KEY is None:
        init_signing_keys()
    return SIGNING_PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
