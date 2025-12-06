import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".sshare"
CONFIG_FILE = CONFIG_DIR / "config.json"

def ensure_config_dir():
    """Ensure config directory exists with secure permissions (700)"""
    CONFIG_DIR.mkdir(exist_ok=True, mode=0o700)
    # Set permissions on existing directory too (in case it already existed)
    os.chmod(CONFIG_DIR, 0o700)

def _save_config_file(config: dict):
    """
    Save config to file with secure permissions (600).
    Only owner can read/write.
    """
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    # Set file permissions to 600 (read/write for owner only)
    os.chmod(CONFIG_FILE, 0o600)

def save_token(token: str):
    ensure_config_dir()
    config = load_config()
    config["token"] = token
    _save_config_file(config)

def load_token() -> str:
    config = load_config()
    return config.get("token")

def clear_token():
    ensure_config_dir()
    config = load_config()
    config.pop("token", None)
    _save_config_file(config)

def load_config() -> dict:
    ensure_config_dir()
    if CONFIG_FILE.exists():
        # Check file permissions and warn if too permissive
        file_mode = os.stat(CONFIG_FILE).st_mode & 0o777
        if file_mode != 0o600:
            print(f"Warning: Config file has insecure permissions {oct(file_mode)}. Fixing to 600...")
            os.chmod(CONFIG_FILE, 0o600)

        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_config(key: str, value: str):
    ensure_config_dir()
    config = load_config()
    config[key] = value
    _save_config_file(config)

def get_config(key: str, default=None):
    config = load_config()
    return config.get(key, default)
