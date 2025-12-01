from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os

class KeyManager:
    """Manages asymmetric RSA and symmetric AES keys"""

    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keypair(self) -> tuple[str, bytes]:
        """
        Generate RSA-4096 keypair
        Returns:
            (public_key_pem, private_key_bytes)
        """
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )

        # Extract public key
        self.public_key = self.private_key.public_key()

        # Serialize public key (PEM)
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        # Serialize private key (DER - binary format)
        private_der = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return public_pem, private_der

    def encrypt_with_public_key(self,file_key: bytes, public_key_pem: str) -> bytes:
        """
        Encrypts a symmetric file_key using an RSA public key (PEM format).
        Returns encrypted bytes.
        """

        # Load the public key object from PEM text
        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        # Encrypt using RSA-OAEP + SHA256
        encrypted_key = public_key.encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return encrypted_key

    def create_encrypted_blob(self, private_key_der: bytes, password: str) -> str:
        """
        Encrypt private key with user password (AES-256 via Fernet)
        Returns: Base64 blob
        """
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        # Encrypt with Fernet (AES-128-CBC + HMAC)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(private_key_der)

        # Return salt + encrypted
        blob = salt + encrypted
        return base64.b64encode(blob).decode('utf-8')

    def decrypt_blob(self, blob_b64: str, password: str) -> bytes:
        """
        Decrypt blob and return private key DER
        """
        blob = base64.b64decode(blob_b64)
        salt = blob[:16]
        encrypted = blob[16:]

        # Re-derive key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        fernet = Fernet(key)
        private_key_der = fernet.decrypt(encrypted)

        # Load private key
        self.private_key = serialization.load_der_private_key(
            private_key_der,
            password=None,
            backend=default_backend()
        )

        return private_key_der

    def load_public_key_from_pem(self, public_pem: str):
        """Load public key from PEM string"""
        self.public_key = serialization.load_pem_public_key(
            public_pem.encode('utf-8'),
            backend=default_backend()
        )
        return self.public_key

    def encrypt_file_key(self, file_key: bytes, recipient_public_pem: str) -> bytes:
        """
        Encrypt a file symmetric key with recipient's public RSA key
        """
        public_key = serialization.load_pem_public_key(
            recipient_public_pem.encode('utf-8'),
            backend=default_backend()
        )

        encrypted_key = public_key.encrypt(
            file_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def decrypt_file_key(self, encrypted_key: bytes) -> bytes:
        """
        Decrypt file symmetric key with private RSA key
        """
        if not self.private_key:
            raise ValueError("Private key not loaded")

        file_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return file_key

    def generate_file_key(self) -> bytes:
        """Generate random AES key for file encryption"""
        return Fernet.generate_key()

    def encrypt_file(self, file_data: bytes, file_key: bytes) -> bytes:
        """Encrypt file data with symmetric key"""
        fernet = Fernet(file_key)
        return fernet.encrypt(file_data)

    def decrypt_file(self, encrypted_data: bytes, file_key: bytes) -> bytes:
        """Decrypt file data with symmetric key"""
        fernet = Fernet(file_key)
        return fernet.decrypt(encrypted_data)
