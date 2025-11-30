import requests
import json
from typing import Optional
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIClient:
    def __init__(self, base_url: str, token: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.verify = False

    def _headers(self):
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def post(self, path: str, data: dict = None, files: dict = None):
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        if files:
            response = self.session.post(self._url(path), headers=headers, data=data, files=files)
        else:
            headers["Content-Type"] = "application/json"
            response = self.session.post(self._url(path), headers=headers, json=data)

        return response

    def get(self, path: str, params: dict = None):
        response = self.session.get(self._url(path), headers=self._headers(), params=params)
        return response

    def put(self, path: str, data: dict = None):
        response = self.session.put(self._url(path), headers=self._headers(), json=data)
        return response

    def delete(self, path: str):
        response = self.session.delete(self._url(path), headers=self._headers())
        return response

    def create_organization(self, org_name: str, admin_username: str):
        return self.post("/api/organizations", {
            "org_name": org_name,
            "admin_username": admin_username
        })

    def activate(self, username: str, activation_code: str, password: str, public_key: str, private_key_blob: str):
        return self.post("/api/auth/activate", {
            "username": username,
            "activation_code": activation_code,
            "password": password,
            "public_key": public_key,
            "private_key_blob": private_key_blob
        })

    def login(self, username: str, password: str):
        return self.post("/api/auth/login", {
            "username": username,
            "password": password
        })

    def logout(self):
        return self.post("/api/auth/logout")

    def create_department(self, name: str):
        return self.post("/api/departments", {"name": name})

    def list_departments(self):
        return self.get("/api/departments")

    def delete_department(self, dept_id: int):
        return self.delete(f"/api/departments/{dept_id}")

    def create_user(self, username: str):
        return self.post("/api/users", {"username": username})

    def list_users(self):
        return self.get("/api/users")

    def delete_user(self, user_id: int):
        return self.delete(f"/api/users/{user_id}")

    def assign_role(self, user_id: int, role: str):
        return self.put(f"/api/users/{user_id}/role", {
            "role": role,
            "signed_role_token": "signature"
        })

    def assign_clearance(self, user_id: int, clearance_level: str, departments: list, expires_at: str = "2025-12-31"):
        return self.put(f"/api/users/{user_id}/clearance", {
            "clearance_level": clearance_level,
            "departments": departments,
            "expires_at": expires_at,
            "signed_token": "signature"
        })

    def get_clearance(self, user_id: int):
        return self.get(f"/api/users/{user_id}/clearance")

    def revoke_role(self, user_id: int, token_id: int):
        return self.put(f"/api/users/{user_id}/revoke/{token_id}")

    def get_user_key(self, user_id: int):
        return self.get(f"/api/users/{user_id}/key")

    def get_user_public_key(self, user_id: int):
        return self.get(f"/api/users/{user_id}/key")

    def get_user_private_key(self):
        return self.get("/api/users/me/vault")

    def get_user_info(self):
        return self.get("/api/users/me/info")

    def update_password(self, new_password: str):
        return self.post("/api/users/me/info", {"password": new_password})

    def upload_transfer(self, encrypted_file_data: bytes, original_filename: str, classification_level: str, departments: list, file_key: bytes, expiration_days: int = 7, transfer_mode: str = "user", recipients: dict = None):
        import base64
        files = {'file': (original_filename, encrypted_file_data)}
        data = {
            'classification_level': classification_level,
            'departments': json.dumps(departments),
            'file_key': base64.b64encode(file_key).decode('utf-8'),
            'expiration_days': str(expiration_days),
            'transfer_mode': transfer_mode,
            'recipients': recipients
        }
        return self.post("/api/transfers", data=data, files=files)

    def list_transfers(self):
        return self.get("/api/transfers")

    def get_transfer(self, transfer_id: int, justification: str = None):
        params = {"justification": justification} if justification else None
        return self.get(f"/api/transfers/{transfer_id}", params=params)

    def delete_transfer(self, transfer_id: int):
        return self.delete(f"/api/transfers/{transfer_id}")

    def download_transfer(self, transfer_id: int, output_path: Optional[str] = None, justification: str = None):
        params = {"justification": justification} if justification else None
        response = self.get(f"/api/download/{transfer_id}", params=params)

        if response.status_code == 200 and output_path:
            with open(output_path, 'wb') as f:
                f.write(response.content)
        return response

    def get_audit_log(self):
        return self.get("/api/audit/log")

    def verify_audit_chain(self):
        return self.get("/api/audit/verify")

    def add_audit_verification(self, entry_id: int, signature: str):
        return self.put("/api/audit/validate", {
            "entry_id": entry_id,
            "signature": signature
        })
