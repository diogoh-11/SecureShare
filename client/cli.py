#!/usr/bin/env python3
import asyncio
import os
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML, FormattedText
from prompt_toolkit.application import run_in_terminal
from prompt_toolkit import print_formatted_text
from prompt_toolkit.key_binding import KeyBindings
from api.client import APIClient
from crypto.key_manager import KeyManager
from storage.vault import Vault
import getpass

client = APIClient()
style = Style.from_dict({
    'prompt':   '#00aa00 bold',
    'username': '#44ccff',
    'error':    '#ff4444',
    'success':  '#44ff44',
})

# ------------------------------------------------------------------
# Key bindings
# ------------------------------------------------------------------
kb = KeyBindings()

@kb.add('c-c')
@kb.add('c-d')
def _(event):
    event.app.exit()

# ------------------------------------------------------------------
# Prompt
# ------------------------------------------------------------------
def get_prompt() -> FormattedText:
    return [
        ('class:username', f'({client.username}) '),
        ('class:prompt', '> '),
    ]

# ------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------

def auth_login(args):
    if args:
        username = args[0]
    else:
        username = input("Username: ").strip()
        if not username:
            return "Username required"

    # Always hide password
    password = getpass.getpass(f"Password for {username}: ")

    if client.login(username, password):
        return "Login successful"
    else:
        return "Login failed"

def auth_activate(args):
    if args and len(args) >= 2:
        username = args[0]
        activation_code = args[1]
    else:
        username = input("Username: ").strip()
        if not username:
            return "Username required"
        activation_code = input("Activation code: ").strip()
        if not activation_code:
            return "Activation code required"

    # Always hide password
    password = getpass.getpass(f"Password for {username}: ")
    if not password:
        return "Password required"

    # Confirm password
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        return "Passwords do not match"

    try:
        # Generate cryptographic keys
        print("Generating cryptographic keys...")
        km = KeyManager()
        public_pem, private_der = km.generate_keypair()

        # Encrypt private key with password
        print("Encrypting private key...")
        blob = km.create_encrypted_blob(private_der, password)

        # Activate user with keys
        print("Activating user...")
        if client.activate_user(username, activation_code, password, public_pem, blob):
            # Save encrypted private key to vault
            vault = Vault()
            vault.save_private_key_blob(username, blob)
            vault._save()
            return client.output
        else:
            return client.output if client.output else "Activation failed"
    except Exception as e:
        return f"Activation failed: {str(e)}"

def org_create(args):
    if args and len(args) ==2:
        org_name, admin_username = args
        client.create_org(org_name,admin_username)
        return client.output

    return "<org_name> <admin_username>"

def user_create(args):
    if args and len(args) == 1:
        username = args[0]
    else:
        username = input("Username: ").strip()
        if not username:
            return "Username required"

    if client.create_user(username):
        return client.output
    else:
        return client.output if client.output else "User creation failed"

def auth_logout(args):
    client.logout()

def clear(args):
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

# ------------------------------------------------------------------
# Command registry
# ------------------------------------------------------------------
COMMANDS = {
    "auth login":    (auth_login,    0),
    "auth activate": (auth_activate, 0),
    "org create":    (org_create,    2),
    "users create":   (user_create,   1),
    "auth logout":   (auth_logout,   0),
    "clear":         (clear,         0),
}

completer = NestedCompleter.from_nested_dict({
    "auth": {
        "login": None,
        "activate": None,
        "logout": None,
    },
    "org": {"create": None},
    "users": {"create": None},
    "clear": None,
})

# ------------------------------------------------------------------
# Session
# ------------------------------------------------------------------
session = PromptSession(
    message=get_prompt,
    completer=completer,
    style=style,
    key_bindings=kb,
    mouse_support=False,  # Disable to allow terminal text selection
    erase_when_done=False,  # Keep output visible for copying
    enable_system_prompt=True,
    enable_open_in_editor=True,
)

# ------------------------------------------------------------------
# Main loop
# ------------------------------------------------------------------
async def main():
    while True:
        try:
            user_input = await session.prompt_async()
        except (KeyboardInterrupt, EOFError):
            print("\nBye!")
            break

        if not user_input.strip():
            continue

        parts = user_input.strip().split()
        command = None
        args = []

        for i in range(len(parts), 0, -1):
            candidate = " ".join(parts[:i])
            if candidate in COMMANDS:
                command = candidate
                args = parts[i:]
                break

        if not command:
            print(HTML('<error>Unknown command</error>'))
            continue

        handler, _ = COMMANDS[command]
        result = handler(args)
        if result is not None:
            if isinstance(result,tuple) and len(result) > 1:
                print_formatted_text(result[0],result[1], style=style)
            else:
                print(result)


if __name__ == "__main__":
    asyncio.run(main())
