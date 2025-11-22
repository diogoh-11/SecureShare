import requests
from typing import Optional
import urllib3

# Desabilitar warnings de SSL (certificados self-signed)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class APIClient:
    """Cliente HTTP base com TLS"""
    
    def __init__(self, base_url: str = "https://localhost:8443"):
        self.base_url = base_url
        self.token: Optional[str] = None
        self.session = requests.Session()
        # Desabilitar verificação SSL (self-signed certificates)
        self.session.verify = False
        


    def set_token(self, token: str):
        """Define JWT token para autenticação"""
        self.token = token
        self.session.headers.update({"Authorization": f"Bearer {token}"})
    


    def post(self, endpoint: str, data: dict) -> dict:
        """POST request"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.post(url, json=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise
    


    def get(self, endpoint: str) -> dict:
        """GET request"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise
    


    def put(self, endpoint: str, data: dict) -> dict:
        """PUT request"""
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.put(url, json=data, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise