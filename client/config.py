import json
import os
from pathlib import Path

CONFIG_DIR = Path.home() / ".sshare"
CONFIG_FILE = CONFIG_DIR / "config.json"

def ensure_config_dir():
    CONFIG_DIR.mkdir(exist_ok=True)

def save_token(token: str):
    ensure_config_dir()
    config = load_config()
    config["token"] = token
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def load_token() -> str:
    config = load_config()
    return config.get("token")

def clear_token():
    ensure_config_dir()
    config = load_config()
    config.pop("token", None)
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def load_config() -> dict:
    ensure_config_dir()
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_config(key: str, value: str):
    ensure_config_dir()
    config = load_config()
    config[key] = value
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

def get_config(key: str, default=None):
    config = load_config()
    return config.get(key, default)
