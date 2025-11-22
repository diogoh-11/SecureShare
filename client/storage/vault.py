import json
import os
from pathlib import Path

class Vault:
    """Armazenamento local de blobs encriptados"""
    
    def __init__(self, vault_path: str = "~/.sshare_vault.json"):
        self.vault_path = Path(vault_path).expanduser()
        self.data = self._load()
    


    def _load(self) -> dict:
        """Carrega vault do disco"""
        if self.vault_path.exists():
            with open(self.vault_path, 'r') as f:
                return json.load(f)
        return {}
    

    def _save(self):
        """Guarda vault no disco"""
        with open(self.vault_path, 'w') as f:
            json.dump(self.data, f, indent=2)
        # Permissões: apenas owner pode ler/escrever
        os.chmod(self.vault_path, 0o600)
    


    def save_private_key_blob(self, username: str, blob: str):
        """Guarda blob encriptado da chave privada"""
        self.data[username] = {"private_key_blob": blob}
        self._save()
        print(f"Private key blob saved for {username}")
    


    def get_private_key_blob(self, username: str) -> str:
        """Obtém blob encriptado"""
        return self.data.get(username, {}).get("private_key_blob")
    


    def delete_user(self, username: str):
        """Remove dados do utilizador"""
        if username in self.data:
            del self.data[username]
            self._save()

    def list_users(self) -> list[str]:
        """Lista utilizadores no vault"""
        return list(self.data.keys())