"""Cryptographic utilities for signature verification"""
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import base64


def verify_signature(data: str, signature_b64: str, public_key_pem: bytes) -> bool:
    """
    Verify RSA-PSS signature with SHA-256

    Args:
        data: Original data that was signed (string)
        signature_b64: Base64-encoded signature
        public_key_pem: Public key in PEM format (bytes)

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        # Decode signature
        signature = base64.b64decode(signature_b64)

        # Verify signature
        public_key.verify(
            signature,
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        # Signature verification failed
        return False
