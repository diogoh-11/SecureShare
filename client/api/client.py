import os
import requests
from typing import Optional
import urllib3

# Desabilitar warnings de SSL (certificados self-signed)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class APIClient:
    """Cliente HTTP base com TLS"""

    def __init__(self, base_url: str = os.getenv("SERVER","https://localhost:8443/api")):
        self.base_url = base_url
        self.token: Optional[str] = None
        self.session = requests.Session()
        self.username = "unknown"
        # Desabilitar verificação SSL (self-signed certificates)
        self.session.verify = False
        self._output:str = ""

    @property
    def output(self):
        return self._output


    def _set_token(self, token: str):
        """Define JWT token para autenticação"""
        self.token = token
        self.session.headers.update({"Authorization": f"Bearer {token}"})



    def _post(self, endpoint: str, data: dict) -> dict:
        """POST request"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.post(url, json=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise



    def _get(self, endpoint: str) -> dict:
        """GET request"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise



    def _put(self, endpoint: str, data: dict) -> dict:
        """PUT request"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.put(url, json=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise

    def login(self, username:str, password:str) -> bool:
        try:
            data = {"username":username,
                    "password":password}
            res = self._post("/auth/login",data)

            # validate response
            if res.get("success") is True:

                # update state
                self.username = username
                token = res.get("session_token")
                if not token:
                    return False

                self._set_token(
                    token=token,
                )
                return True
            else:
                return False

        except Exception:
            return False

    def create_org(self,org_name:str,admin_name:str)->bool:
        try:
            data = {"org_name":org_name,
                    "admin_username":admin_name}
            res = self._post("/organizations",data)

            # validate response
            if res.get("success") is True:
                self._output = f"{res['message']}\nUsername: {res['username']}\nActivationCode: {res['activation_code']}\nOrgName: {res['org_name']}"
                return True
            else:
                return False

        except Exception:
            return False

    def create_user(self, username: str) -> bool:
        """Create a new user (requires Administrator role)"""
        try:
            data = {"username": username}
            res = self._post("/users", data)

            # validate response
            if res.get("user_id"):
                self._output = f"User created successfully\nUsername: {res['username']}\nActivation code: {res['activation_code']}"
                return True
            else:
                return False

        except Exception as e:
            self._output = f"Failed to create user: {str(e)}"
            return False

    def activate_user(self, username: str, activation_code: str, password: str, public_key: str, private_key_blob: str) -> bool:
        """Activate a user account with activation code, password, and keys"""
        try:
            data = {
                "username": username,
                "activation_code": activation_code,
                "password": password,
                "public_key": public_key,
                "private_key_blob": private_key_blob
            }
            res = self._post("/auth/activate", data)

            # validate response
            if res.get("success") is True:
                self._output = f"User activated successfully\nUsername: {res.get('username', username)}"
                return True
            else:
                return False

        except Exception as e:
            self._output = f"Activation failed: {str(e)}"
            return False

    def logout(self):
        try:
            self._post("/auth/logout", {})
            self.username = "unknown"
            self.token = None
            # Remove Authorization header
            if "Authorization" in self.session.headers:
                del self.session.headers["Authorization"]
            return True
        except Exception:
            return False
