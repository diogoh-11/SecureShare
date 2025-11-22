from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

class KeyManager:
    """Gestão de chaves assimétricas RSA e simétricas AES"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_keypair(self) -> tuple[str, bytes]:
        """
        Gera par de chaves RSA-4096
        Returns:
            (public_key_pem, private_key_bytes)
        """
        # Gerar chave privada
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Extrair chave pública
        self.public_key = self.private_key.public_key()
        
        # Serializar chave pública (PEM)
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Serializar chave privada (DER - formato binário)
        private_der = self.private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        return public_pem, private_der
    

    def create_encrypted_blob(self, private_key_der: bytes, password: str) -> str:
        """
        Encripta chave privada com password do utilizador (AES-256)
        Returns: Base64 blob
        """
        # Derivar chave AES da password (usando PBKDF2)
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Encriptar com Fernet (AES-128-CBC + HMAC)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(private_key_der)
        
        # Retornar salt + encrypted
        blob = salt + encrypted
        return base64.b64encode(blob).decode('utf-8')
    

    
    def decrypt_blob(self, blob_b64: str, password: str) -> bytes:
        """
        Desencripta blob e retorna chave privada DER
        """
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        blob = base64.b64decode(blob_b64)
        salt = blob[:16]
        encrypted = blob[16:]
        
        # Re-derivar chave
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
        
        # Carregar chave privada
        self.private_key = serialization.load_der_private_key(
            private_key_der,
            password=None,
            backend=default_backend()
        )
        
        return private_key_der
        


# Exemplo de uso
if __name__ == "__main__":
    km = KeyManager()
    
    # 1. Gerar keypair
    public_pem, private_der = km.generate_keypair()
    print("Public Key:")
    print(public_pem)
    
    # 2. Criar blob encriptado
    password = "minha_password_segura"
    blob = km.create_encrypted_blob(private_der, password)
    print(f"\nEncrypted Blob (primeiros 50 chars): {blob[:50]}...")
    
    # 3. Desencriptar blob
    km2 = KeyManager()
    km2.decrypt_blob(blob, password)
    print("\n✅ Blob desencriptado com sucesso!")
    
   