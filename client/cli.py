#!/usr/bin/env python3
import argparse
import sys
import json
import getpass
import base64
import os
import zipfile
import tempfile
from api_client import APIClient
from config import save_token, load_token, clear_token, save_config, get_config
from crypto import KeyManager

# Tab completion support
try:
    import argcomplete
    ARGCOMPLETE_AVAILABLE = True
except ImportError:
    ARGCOMPLETE_AVAILABLE = False

DEFAULT_SERVER = "https://localhost:8443"

# Role name mapping: short names to full names
ROLE_ALIASES = {
    "ad": "Administrator",
    "so": "Security Officer",
    "to": "Trusted Officer",
    "au": "Auditor",
    "su": "Standard User"
}

def normalize_role_name(role):
    """Convert short role name to full name, or return as-is if already full."""
    if role is None:
        return None
    # If it's a short name, convert it
    if role.lower() in ROLE_ALIASES:
        return ROLE_ALIASES[role.lower()]
    # Otherwise return as-is (assume it's already a full name)
    return role

def get_client(acting_role=None, acting_clearance=None):
    """
    Get API client with acting role and clearance.

    If acting_role is provided:
        - Save it to config for future use
        - Use it for this request
    If acting_role is None:
        - Load saved role from config (if any)
        - Use it for this request

    If acting_clearance is provided:
        - Save it to config for future use
        - Use it for this request
    If acting_clearance is None:
        - Load saved clearance from config (if any)
        - Use it for this request
    """
    server = get_config("server", DEFAULT_SERVER)
    token = load_token()

    # If role specified, normalize and save it for future use
    if acting_role:
        acting_role = normalize_role_name(acting_role)
        save_config("acting_role", acting_role)
    else:
        # Load saved role from config
        acting_role = get_config("acting_role", None)

    # If clearance specified, save it for future use
    if acting_clearance is not None:
        save_config("acting_clearance", acting_clearance)
    else:
        # Load saved clearance from config
        acting_clearance = get_config("acting_clearance", None)

    return APIClient(server, token, acting_role, acting_clearance)


def handle_response(response, success_message=None):
    try:
        data = response.json()
        if response.status_code in [200, 201]:
            if success_message:
                print(success_message)
            print(json.dumps(data, indent=2))
            return data
        else:
            print(
                f"Error {response.status_code}: {data.get('detail', 'Unknown error')}")
            sys.exit(1)
    except json.JSONDecodeError:
        if response.status_code in [200, 201]:
            print(success_message or "Success")
        else:
            print(f"Error {response.status_code}: {response.text}")
            sys.exit(1)


def cmd_config(args):
    if args.action == "set-server":
        save_config("server", args.url)
        print(f"Server set to: {args.url}")
    elif args.action == "clear-role":
        from config import load_config, _save_config_file
        config = load_config()
        if "acting_role" in config:
            config.pop("acting_role")
            _save_config_file(config)
            print("Saved acting role cleared")
        else:
            print("No saved acting role to clear")
    elif args.action == "clear-clearance":
        from config import load_config, _save_config_file
        config = load_config()
        if "acting_clearance" in config:
            config.pop("acting_clearance")
            _save_config_file(config)
            print("Saved acting clearance cleared")
        else:
            print("No saved acting clearance to clear")
    elif args.action == "show":
        server = get_config("server", DEFAULT_SERVER)
        token = load_token()
        acting_role = get_config("acting_role", None)
        acting_clearance = get_config("acting_clearance", None)
        print(f"Server: {server}")
        print(f"Token: {'Set' if token else 'Not set'}")
        print(f"Acting Role: {acting_role if acting_role else 'Not set (defaults to Standard User)'}")
        print(f"Acting Clearance: {acting_clearance if acting_clearance else 'Not set (no clearance)'}")


def cmd_org_create(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.create_organization(args.name, args.admin)
    data = handle_response(response, "Organization created successfully")
    if data and "activation_code" in data:
        print(
            f"\nIMPORTANT: Save this activation code: {data['activation_code']}")


def cmd_activate(args):
    print("Generating RSA-4096 keypair...")
    km = KeyManager()
    public_pem, private_der = km.generate_keypair()

    print("Encrypting private key with your password...")
    encrypted_blob = km.create_encrypted_blob(private_der, args.password)

    print("Activating account...")
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.activate(args.username, args.code, args.password, public_pem, encrypted_blob)
    handle_response(response, "Account activated successfully\nYour encrypted private key has been stored on the server.")

def cmd_login(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.login(args.username, args.password)
    data = handle_response(response, "Login successful")
    if data and "access_token" in data:
        save_token(data["access_token"])
        print("\nToken saved. You are now authenticated.")


def cmd_logout(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.logout()
    handle_response(response)
    clear_token()
    print("Logged out. Token cleared.")


def cmd_dept_create(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.create_department(args.name)
    handle_response(response, "Department created successfully")


def cmd_dept_list(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.list_departments()
    handle_response(response)


def cmd_dept_delete(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.delete_department(args.id)
    handle_response(response, f"Department {args.id} deleted")


def cmd_user_create(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.create_user(args.username)
    data = handle_response(response, "User created successfully")
    if data and "activation_code" in data:
        print(
            f"\nIMPORTANT: Save this activation code: {data['activation_code']}")


def cmd_user_list(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.list_users()
    handle_response(response)


def cmd_user_delete(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.delete_user(args.id)
    handle_response(response, f"User {args.id} deleted")


def cmd_user_info(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.get_user_info()
    handle_response(response)


def cmd_user_update_password(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.update_password(args.password)
    handle_response(response, "Password updated successfully")


def cmd_role_assign(args):
    import json
    import getpass

    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))

    # Normalize role name (convert short names to full names)
    role = normalize_role_name(args.role)

    # Get current user info to get issuer_id and private key
    user_info_response = client.get("/api/users/me/info")
    if user_info_response.status_code != 200:
        print(f"Error: Failed to get user info: {user_info_response.text}")
        sys.exit(1)

    user_info = user_info_response.json()
    issuer_id = user_info.get("id")
    encrypted_blob = user_info.get("private_key_blob")

    if not encrypted_blob:
        print("Error: No private key found. Cannot sign role token.")
        sys.exit(1)

    # Prompt for password to decrypt private key
    password = getpass.getpass("Enter your password to sign role token: ")

    print("Decrypting private key...")
    km = KeyManager()
    try:
        km.decrypt_blob(encrypted_blob, password)
    except Exception as e:
        print(f"Error: Failed to decrypt private key. Wrong password? {e}")
        sys.exit(1)

    # Expiration is optional for roles (None means no expiration)
    expires_at_iso = None

    # Build token data structure (must match server-side verification)
    token_data = {
        "role": role,
        "target_id": args.user_id,
        "issuer_id": issuer_id,
        "expires_at": expires_at_iso
    }

    # Sign the token data
    token_data_str = json.dumps(token_data, sort_keys=True)
    print("Signing role token...")
    signature = km.sign_data(token_data_str)

    # Send to server
    response = client.assign_role(args.user_id, role, signature, expires_at_iso)
    handle_response(response, f"Role '{role}' assigned to user {args.user_id}")

def cmd_role_revoke(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.revoke_role(args.token_id)
    handle_response(response, f"Role token {args.token_id} revoked")

def cmd_clearance_assign(args):
    import json
    from datetime import datetime, timedelta
    import getpass

    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))

    # Get current user info to get issuer_id and private key
    user_info_response = client.get("/api/users/me/info")
    if user_info_response.status_code != 200:
        print(f"Error: Failed to get user info: {user_info_response.text}")
        sys.exit(1)

    user_info = user_info_response.json()
    issuer_id = user_info.get("id")
    encrypted_blob = user_info.get("private_key_blob")

    if not encrypted_blob:
        print("Error: No private key found. Cannot sign clearance token.")
        sys.exit(1)

    # Prompt for password to decrypt private key
    password = getpass.getpass("Enter your password to sign clearance token: ")

    print("Decrypting private key...")
    km = KeyManager()
    try:
        km.decrypt_blob(encrypted_blob, password)
    except Exception as e:
        print(f"Error: Failed to decrypt private key. Wrong password? {e}")
        sys.exit(1)

    # Parse departments
    departments = args.departments.split(",") if args.departments else []

    # Determine if organizational
    is_organizational = getattr(args, 'organizational', False)

    # Validation: organizational clearances should not have specific departments
    if is_organizational and departments:
        print("Warning: Organizational clearances apply to all departments. --departments will be ignored.")
        departments = []

    # Calculate expiration time (use provided or default to 30 days from now)
    if args.expires_at:
        expires_at_iso = args.expires_at
    else:
        expiration = datetime.utcnow() + timedelta(days=30)
        expires_at_iso = expiration.isoformat() + 'Z'

    # Build token data structure (must match server-side verification)
    token_data = {
        "clearance_level": args.level,
        "user_id": args.user_id,
        "issuer_id": issuer_id,
        "departments": sorted(departments),  # Sort for consistent signature
        "expires_at": expires_at_iso,
        "is_organizational": is_organizational
    }

    # Sign the token data
    token_data_str = json.dumps(token_data, sort_keys=True)
    print("Signing clearance token...")
    signature = km.sign_data(token_data_str)

    # Send to server
    response = client.assign_clearance(
        args.user_id, args.level, departments, expires_at_iso, signature, is_organizational)
    handle_response(response, f"Clearance assigned to user {args.user_id}")


def cmd_clearance_get(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.get_clearance(args.user_id)
    handle_response(response)


def cmd_clearance_revoke(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.revoke_clearance(args.token_id)
    handle_response(response, f"Clearance token {args.token_id} revoked")

def cmd_transfer_upload(args):
    """Upload user-specific transfer - no classification/departments needed"""
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))

    # User-specific transfer requires recipients
    recipients = args.recipients.split(",") if args.recipients else []
    if not recipients:
        print("Error: User-specific transfers require at least one recipient (--recipients)")
        sys.exit(1)

    strategy_encryption = args.strategy
    if strategy_encryption != "XChaCha" and strategy_encryption != "GCM":
        print(f"Error: Strategy {strategy_encryption} is invalid")
        print("The strategies available are XChaCha and GCM")
        sys.exit(1)

    # Handle multiple files - create zip if needed
    files = args.files.split(",") if args.files else []
    if not files:
        print("Error: No files specified")
        sys.exit(1)

    file_data = None

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
        zip_path = tmp_zip.name

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in files:
                if not os.path.exists(file_path):
                    print(f"Warning: File not found: {file_path}")
                    continue
                print(f"  Adding: {os.path.basename(file_path)}")
                zf.write(file_path, os.path.basename(file_path))

        with open(zip_path, "rb") as f:
            file_data = f.read()
    finally:
        if os.path.exists(zip_path):
            os.unlink(zip_path)

    # Generate symmetric key and encrypt file
    print("Encrypting file...")
    km = KeyManager()
    file_key = km.generate_file_key()
    nonce = km.generate_nonce()

    # Encrypt file key for each recipient
    recipients_dict = {}
    for r in recipients:
        res = client.get_user_key(r)
        key = res.json().get("public_key", None)
        if key is None:
            print(f"Warning: Could not get public key for user {r}")
            continue
        ekey = km.encrypt_with_public_key(file_key, key)
        recipients_dict[r] = ekey

    print(f"Uploading encrypted file to {len(recipients_dict)} recipients...")
    response = client.upload_transfer(
        file_data,
        file_key,
        nonce,
        strategy_encryption,
        "Unclassified",  # User-specific transfers don't need classification
        [],  # No departments
        args.expiration,
        "user",
        recipients_dict,
    )

    data = handle_response(response, "File uploaded successfully - recipients can download")

def cmd_transfer_upload_public(args):
    """Upload public transfer - requires classification and departments"""
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))

    # Public transfers require classification and departments
    departments = args.departments.split(",") if args.departments else []

    strategy_encryption = args.strategy
    if strategy_encryption != "XChaCha" and strategy_encryption != "GCM":
        print(f"Error: Strategy {strategy_encryption} is invalid")
        print("The strategies available are XChaCha and GCM")
        sys.exit(1)

    # Handle multiple files - create zip if needed
    files = args.files.split(",") if args.files else []
    if not files:
        print("Error: No files specified")
        sys.exit(1)

    file_data = None

    with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp_zip:
        zip_path = tmp_zip.name

    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in files:
                if not os.path.exists(file_path):
                    print(f"Warning: File not found: {file_path}")
                    continue
                print(f"  Adding: {os.path.basename(file_path)}")
                zf.write(file_path, os.path.basename(file_path))

        with open(zip_path, "rb") as f:
            file_data = f.read()
    finally:
        if os.path.exists(zip_path):
            os.unlink(zip_path)

    # Generate symmetric key and encrypt file
    print("Encrypting file...")
    km = KeyManager()
    file_key = km.generate_file_key()
    nonce = km.generate_nonce()

    print("Creating public transfer (anyone with proper clearance can download)...")
    response = client.upload_transfer(
        file_data,
        file_key,
        nonce,
        strategy_encryption,
        args.classification,
        departments,
        args.expiration,
        "public",
        {},  # No recipients for public transfers
    )

    data = handle_response(response, "Public transfer created successfully")

    # For public transfers, show the complete URL with key fragment
    if data and data.get("public_access_token"):
        server = get_config("server", DEFAULT_SERVER)
        file_key_b64 = base64.b64encode(file_key).decode('utf-8')
        public_url = f"{server}/api/public/{data['public_access_token']}#{file_key_b64}"
        print("\nPublic URL (share this link):")
        print(public_url)
        print("\nNote: The key is in the URL fragment (#) and never sent to the server.")


def cmd_transfer_list(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.list_transfers()
    handle_response(response)


def cmd_transfer_get(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.get_transfer(args.id, args.justification)
    handle_response(response)


def cmd_transfer_download(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))

    # Get transfer info to get encrypted keys
    print("Fetching transfer information...")
    info_response = client.get_transfer(args.id, args.justification)
    if info_response.status_code != 200:
        handle_response(info_response)
        return

    transfer_info = info_response.json()

    # Get current user info to know user_id
    user_info_response = client.get_user_info()
    if user_info_response.status_code != 200:
        print("Error: Could not get user information")
        handle_response(user_info_response)
        return

    user_info = user_info_response.json()
    user_id = user_info.get("id")

    # Get encrypted file key for this user
    encrypted_file_key_b64 = transfer_info.get("encrypted_key")
    if not encrypted_file_key_b64:
        print(f"Error: No encrypted key found for user {user_id}")
        print("You may not have access to this file.")
        sys.exit(1)

    encrypted_file_key = base64.b64decode(encrypted_file_key_b64)

    # Get encrypted private key blob from user info
    encrypted_blob = user_info.get("private_key_blob")

    if not encrypted_blob:
        print("Error: No private key found for user")
        sys.exit(1)

    # Prompt for password to decrypt private key
    password = getpass.getpass("Enter your password to decrypt private key: ")

    print("Decrypting private key...")
    km = KeyManager()
    try:
        km.decrypt_blob(encrypted_blob, password)
    except Exception as e:
        print(f"Error: Failed to decrypt private key. Wrong password? {e}")
        sys.exit(1)

    # Decrypt file key
    print("Decrypting file key...")
    try:
        file_key = km.decrypt_file_key(encrypted_file_key)
    except Exception as e:
        print(f"Error: Failed to decrypt file key: {e}")
        sys.exit(1)

    # Download encrypted file
    print("Downloading encrypted file...")
    response = client.download_transfer(args.id, None, args.justification)
    if response.status_code != 200:
        handle_response(response)
        return

    encrypted_file_data = response.content
    metadata = json.loads(response.headers["metadata"])
    # Decrypt file
    print("Decrypting file...")
    km = KeyManager()
    strategy = metadata["strategy"]
    nonce = base64.b64decode(metadata["nonce"])

    try:
        if strategy == "GCM":
            decrypted_file_data = km.decrypt_file_gcm(file_key, nonce, encrypted_file_data, metadata)
        elif strategy == "XChaCha":
            decrypted_file_data = km.decrypt_file_xshasha(file_key, nonce, encrypted_file_data, metadata)
    except Exception as e:
        print(f"Error: Failed to decrypt file: {e}")
        sys.exit(1)

    # Determine output filename
    if args.output:
        output_filename = args.output
    else:
        # Use UUID from server as filename
        file_uuid = transfer_info.get("file_uuid", f"transfer_{args.id}")
        output_filename = file_uuid

    # Write decrypted file
    with open(output_filename, "wb") as f:
        f.write(decrypted_file_data)

    print(f"File decrypted and saved to: {output_filename}")


def cmd_transfer_delete(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.delete_transfer(args.id)
    handle_response(response, f"Transfer {args.id} deleted")


def cmd_transfer_download_public(args):
    """
    Download public transfer using URL with key in fragment
    Example: https://server/api/public/TOKEN#KEY_BASE64
    Requires authentication and proper clearance (use --with <clearance_token_id>)
    """
    import urllib.parse

    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))

    # Parse URL
    parsed = urllib.parse.urlparse(args.url)

    if not parsed.fragment:
        print("Error: URL must include encryption key in fragment (#)")
        print("Example: https://server/api/public/TOKEN#KEY_BASE64")
        sys.exit(1)

    # Extract key from fragment
    file_key_b64 = parsed.fragment
    try:
        file_key = base64.b64decode(file_key_b64)
    except Exception as e:
        print(f"Error: Invalid key in URL fragment: {e}")
        sys.exit(1)

    # Extract the access token from the path
    # Path should be like /api/public/TOKEN
    path_parts = parsed.path.split('/')
    if 'public' not in path_parts:
        print("Error: Invalid public transfer URL")
        sys.exit(1)

    public_index = path_parts.index('public')
    if public_index + 1 >= len(path_parts):
        print("Error: No access token in URL")
        sys.exit(1)

    access_token = path_parts[public_index + 1]

    print(f"Downloading public transfer (token: {access_token})")

    # Download encrypted file with authentication and clearance
    try:
        response = client.get(f"/api/public/{access_token}")
        if response.status_code != 200:
            print(f"Error: {response.status_code}")
            try:
                error_data = response.json()
                print(error_data.get('detail', 'Unknown error'))
            except:
                print(response.text)
            sys.exit(1)

        encrypted_file_data = response.content
        metadata = json.loads(response.headers["metadata"])
    except Exception as e:
        print(f"Error downloading file: {e}")
        sys.exit(1)

    # Decrypt file
    print("Decrypting file...")
    km = KeyManager()
    strategy = metadata["strategy"]
    nonce = base64.b64decode(metadata["nonce"])
    print("Strategy:", strategy, "nonce:", nonce, "metadata:", metadata)
    if strategy == "GCM":
        decrypted_file_data = km.decrypt_file_gcm(file_key, nonce, encrypted_file_data, metadata)
    elif strategy == "XChaCha":
        decrypted_file_data = km.decrypt_file_xshasha(file_key, nonce, encrypted_file_data, metadata)

    # Determine output filename
    if args.output:
        output_filename = args.output
    else:
        # Extract token from URL for default filename
        token = parsed.path.split('/')[-1]
        output_filename = f"public_transfer_{token}"

    # Write decrypted file
    with open(output_filename, "wb") as f:
        f.write(decrypted_file_data)

    print(f"File decrypted and saved to: {output_filename}")


def cmd_audit_log(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.get_audit_log()
    handle_response(response)


def cmd_audit_verify(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))
    response = client.verify_audit_chain()
    handle_response(response)


def cmd_audit_verifications(args):
    """Show all audit verifications history"""
    client = get_client()
    response = client.get_audit_verifications()

    if response.status_code != 200:
        print(f"Error: {response.text}")
        return

    data = response.json()
    verifications = data.get("verifications", [])

    if not verifications:
        print("No verifications found.")
        return

    print("\n=== Audit Verification History ===")
    print(f"Total verifications: {len(verifications)}\n")

    for v in verifications:
        print(f"Verification ID: {v['id']}")
        print(f"  Timestamp: {v['timestamp']}")
        print(f"  Auditor: {v['auditor_username']} (ID: {v['auditor_id']})")
        print(f"  Verified up to entry: {v['verified_up_to_entry_id']}")
        print(f"  Entry hash: {v['verified_up_to_hash'][:50]}...")
        print(f"  Signature: {v['signature'][:50]}...")
        print()


def cmd_audit_validate(args):
    client = get_client(getattr(args, 'as_role', None), getattr(args, 'with_clearance', None))

    # Get latest entry to sign
    print("Fetching latest audit entry...")
    entry_response = client.get_latest_audit_entry()

    if entry_response.status_code != 200:
        print(f"Error: Failed to fetch latest entry - {entry_response.text}")
        return

    entry_data = entry_response.json()
    entry_hash = entry_data.get("entryHash")
    entry_id = entry_data.get("id")
    print(f"Latest entry ID: {entry_id}")
    print(f"Entry hash: {entry_hash}")

    # Get user info to retrieve private key
    user_info_response = client.get_user_info()
    if user_info_response.status_code != 200:
        print("Error: Failed to get user info")
        return

    user_info = user_info_response.json()
    encrypted_blob = user_info.get("private_key_blob")

    if not encrypted_blob:
        print("Error: No private key found for user")
        return

    # Prompt for password to decrypt private key
    import getpass
    password = getpass.getpass("Enter your password to sign verification: ")

    print("Decrypting private key...")
    from crypto import KeyManager
    km = KeyManager()
    try:
        km.decrypt_blob(encrypted_blob, password)
    except Exception as e:
        print(f"Error: Failed to decrypt private key. Wrong password? {e}")
        return

    # Sign the entry hash
    print("Signing entry hash...")
    try:
        signature = km.sign_data(entry_hash)
        print(f"Signature generated: {signature[:50]}...")
    except Exception as e:
        print(f"Error: Failed to sign data: {e}")
        return

    # Submit verification
    print("Submitting verification...")
    response = client.add_audit_verification(signature)
    handle_response(response, "Verification added to audit log")


def main():
    parser = argparse.ArgumentParser(
        description="SecureShare CLI - Secure file transfer with MLS and RBAC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Configuration
  sshare config set-server https://localhost:8443
  sshare config show                    # View current config including saved role/clearance
  sshare config clear-role              # Clear saved acting role
  sshare config clear-clearance         # Clear saved acting clearance

  # Organization and user setup
  sshare org create --name "ACME Corp" --admin admin
  sshare activate --username admin --code CODE --password pass123
  sshare login --username admin --password pass123

  # Role management - use short names [ad, so, to, au, su] or full names
  sshare user list --as ad                        # View users (using short "ad" for Administrator)
  sshare user create --username alice --as ad     # Saves "Administrator"
  sshare role assign --user-id 2 --role so        # Admin assigns Security Officer
  sshare role assign --user-id 3 --role au --as so  # SO assigns Auditor
  sshare role revoke --token-id 5 --as so        # Revoke role by token ID

  # Clearances and transfers
  sshare clearance assign --user-id 2 --level "Top Secret" --departments "Engineering,Finance" --as so
  sshare clearance revoke --token-id 10 --as so  # Revoke by token ID

  # User-specific transfer (no classification/MLS needed)
  sshare transfer upload --files doc.pdf,report.xlsx --recipients 2,3

  # Public transfer (requires classification and clearance)
  sshare transfer upload-public --files doc.pdf --classification "Secret" --departments "Engineering" --with 15
  sshare transfer download-public --url https://server/api/public/TOKEN#KEY --with 15

  sshare audit log --as au                       # View audit log as Auditor
        """
    )

    # Global arguments for specifying which role and clearance to act as
    parser.add_argument("--as", dest="as_role", help="Specify which role to act as. Use short names [ad, so, to, au, su] or full names. Saved for future commands. View with 'config show', clear with 'config clear-role'. Defaults to Standard User if not set.")
    parser.add_argument("--with", dest="with_clearance", type=int, help="Specify which clearance token ID to use. Saved for future commands. View with 'config show', clear with 'config clear-clearance'. If not set, user has no clearance.")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    config_parser = subparsers.add_parser(
        "config", help="Configure client settings")
    config_sub = config_parser.add_subparsers(dest="action")
    config_set = config_sub.add_parser("set-server", help="Set server URL")
    config_set.add_argument("url", help="Server URL")
    config_sub.add_parser("show", help="Show current configuration")
    config_sub.add_parser("clear-role", help="Clear saved acting role")
    config_sub.add_parser("clear-clearance", help="Clear saved acting clearance")
    config_parser.set_defaults(func=cmd_config)

    org_parser = subparsers.add_parser("org", help="Organization management")
    org_sub = org_parser.add_subparsers(dest="action")
    org_create = org_sub.add_parser("create", help="Create organization")
    org_create.add_argument("--name", required=True, help="Organization name")
    org_create.add_argument("--admin", required=True, help="Admin username")
    org_create.set_defaults(func=cmd_org_create)

    activate_parser = subparsers.add_parser(
        "activate", help="Activate user account (generates RSA-4096 keys)")
    activate_parser.add_argument("--username", required=True, help="Username")
    activate_parser.add_argument(
        "--code", required=True, help="Activation code")
    activate_parser.add_argument(
        "--password", required=True, help="Password (also used to encrypt private key)")
    activate_parser.set_defaults(func=cmd_activate)

    login_parser = subparsers.add_parser(
        "login", help="Login to get token")
    login_parser.add_argument("--username", required=True, help="Username")
    login_parser.add_argument("--password", required=True, help="Password")
    login_parser.set_defaults(func=cmd_login)

    logout_parser = subparsers.add_parser(
        "logout", help="Logout and clear token")
    logout_parser.set_defaults(func=cmd_logout)

    dept_parser = subparsers.add_parser("dept", help="Department management")
    dept_sub = dept_parser.add_subparsers(dest="action")
    dept_create = dept_sub.add_parser("create", help="Create department")
    dept_create.add_argument("--name", required=True, help="Department name")
    dept_create.set_defaults(func=cmd_dept_create)
    dept_list = dept_sub.add_parser("list", help="List departments")
    dept_list.set_defaults(func=cmd_dept_list)
    dept_delete = dept_sub.add_parser("delete", help="Delete department")
    dept_delete.add_argument(
        "--id", type=int, required=True, help="Department ID")
    dept_delete.set_defaults(func=cmd_dept_delete)

    user_parser = subparsers.add_parser("user", help="User management")
    user_sub = user_parser.add_subparsers(dest="action")
    user_create = user_sub.add_parser("create", help="Create user")
    user_create.add_argument("--username", required=True, help="Username")
    user_create.set_defaults(func=cmd_user_create)
    user_list = user_sub.add_parser("list", help="List users")
    user_list.set_defaults(func=cmd_user_list)
    user_delete = user_sub.add_parser("delete", help="Delete user")
    user_delete.add_argument("--id", type=int, required=True, help="User ID")
    user_delete.set_defaults(func=cmd_user_delete)
    user_info = user_sub.add_parser("info", help="Get current user info")
    user_info.set_defaults(func=cmd_user_info)
    user_passwd = user_sub.add_parser(
        "update-password", help="Update password")
    user_passwd.add_argument("--password", required=True, help="New password")
    user_passwd.set_defaults(func=cmd_user_update_password)

    role_parser = subparsers.add_parser("role", help="Role management")
    role_sub = role_parser.add_subparsers(dest="action")
    role_assign = role_sub.add_parser("assign", help="Assign privileged role to user")
    role_assign.add_argument("--user-id", type=int, required=True, help="User ID")
    role_assign.add_argument("--role", required=True, choices=["Security Officer", "Trusted Officer", "Auditor", "so", "to", "au"], help="Role name: so=Security Officer, to=Trusted Officer, au=Auditor (everyone is Standard User by default)")
    role_assign.set_defaults(func=cmd_role_assign)
    role_revoke = role_sub.add_parser("revoke", help="Revoke privileged role (user reverts to Standard User)")
    role_revoke.add_argument("--token-id", type=int, required=True, help="Role token ID (use 'user list' to see token IDs)")
    role_revoke.set_defaults(func=cmd_role_revoke)

    clearance_parser = subparsers.add_parser(
        "clearance", help="Clearance management")
    clearance_sub = clearance_parser.add_subparsers(dest="action")
    clearance_assign = clearance_sub.add_parser(
        "assign", help="Assign clearance to user")
    clearance_assign.add_argument(
        "--user-id", type=int, required=True, help="User ID")
    clearance_assign.add_argument("--level", required=True, choices=[
                                  "Unclassified", "Confidential", "Secret", "Top Secret"], help="Clearance level")
    clearance_assign.add_argument(
        "--departments", help="Comma-separated department names (not needed for organizational clearances)")
    clearance_assign.add_argument(
        "--expires-at", default="2025-12-31", help="Expiration date (YYYY-MM-DD)")
    clearance_assign.add_argument(
        "--organizational", action="store_true", help="Grant organizational clearance (access to all departments)")
    clearance_assign.set_defaults(func=cmd_clearance_assign)
    clearance_get = clearance_sub.add_parser("get", help="Get user clearances")
    clearance_get.add_argument(
        "--user-id", type=int, required=True, help="User ID")
    clearance_get.set_defaults(func=cmd_clearance_get)
    clearance_revoke = clearance_sub.add_parser("revoke", help="Revoke clearance token")
    clearance_revoke.add_argument("--token-id", type=int, required=True, help="Clearance token ID (use 'user list' to see token IDs)")
    clearance_revoke.set_defaults(func=cmd_clearance_revoke)

    transfer_parser = subparsers.add_parser(
        "transfer", help="File transfer management")
    transfer_sub = transfer_parser.add_subparsers(dest="action")

    # User-specific upload - no classification/departments needed
    transfer_upload = transfer_sub.add_parser("upload", help="Upload file(s) to specific users (no MLS enforcement)")
    transfer_upload.add_argument("--files", required=True, help="Comma-separated file paths (multiple files will be zipped)")
    transfer_upload.add_argument("--recipients", required=True, help="Comma-separated user IDs (target users)")
    transfer_upload.add_argument("--expiration", type=int, default=7, help="Expiration days (default: 7)")
    transfer_upload.add_argument("--strategy", type=str, default="GCM", help="Cypher used on encryption (either GCM or XChaCha) (default: GCM)")
    transfer_upload.set_defaults(func=cmd_transfer_upload)

    # Public upload - requires classification and departments
    transfer_upload_public = transfer_sub.add_parser("upload-public", help="Upload public file(s) with MLS enforcement")
    transfer_upload_public.add_argument("--files", required=True, help="Comma-separated file paths (multiple files will be zipped)")
    transfer_upload_public.add_argument("--classification", required=True, choices=["Unclassified", "Confidential", "Secret", "Top Secret"], help="Classification level")
    transfer_upload_public.add_argument("--departments", help="Comma-separated department names")
    transfer_upload_public.add_argument("--expiration", type=int, default=7, help="Expiration days (default: 7)")
    transfer_upload_public.add_argument("--strategy", type=str, default="GCM", help="Cypher used on encryption (either GCM or XChaCha) (default: GCM)")
    transfer_upload_public.set_defaults(func=cmd_transfer_upload_public)

    transfer_list = transfer_sub.add_parser("list", help="List transfers")
    transfer_list.set_defaults(func=cmd_transfer_list)
    transfer_get = transfer_sub.add_parser("get", help="Get transfer info")
    transfer_get.add_argument(
        "--id", type=int, required=True, help="Transfer ID")
    transfer_get.add_argument(
        "--justification", help="Justification for trusted officer access")
    transfer_get.set_defaults(func=cmd_transfer_get)
    transfer_download = transfer_sub.add_parser(
        "download", help="Download transfer file")
    transfer_download.add_argument(
        "--id", type=int, required=True, help="Transfer ID")
    transfer_download.add_argument(
        "--output", help="Output file path (default: uses server-generated UUID)")
    transfer_download.add_argument(
        "--justification", help="Justification for trusted officer access")
    transfer_download.set_defaults(func=cmd_transfer_download)
    transfer_delete = transfer_sub.add_parser("delete", help="Delete transfer")
    transfer_delete.add_argument(
        "--id", type=int, required=True, help="Transfer ID")
    transfer_delete.set_defaults(func=cmd_transfer_delete)
    transfer_public = transfer_sub.add_parser(
        "download-public", help="Download public transfer (no auth required)")
    transfer_public.add_argument(
        "--url", required=True, help="Public URL with key in fragment (e.g., https://server/api/public/TOKEN#KEY)")
    transfer_public.add_argument(
        "--output", help="Output file path (default: uses public token from URL)")
    transfer_public.set_defaults(func=cmd_transfer_download_public)

    audit_parser = subparsers.add_parser("audit", help="Audit log management")
    audit_sub = audit_parser.add_subparsers(dest="action")
    audit_log = audit_sub.add_parser("log", help="View audit log")
    audit_log.set_defaults(func=cmd_audit_log)
    audit_verify = audit_sub.add_parser(
        "verify", help="Verify audit chain integrity")
    audit_verify.set_defaults(func=cmd_audit_verify)
    audit_verifications = audit_sub.add_parser(
        "verifications", help="View all audit verifications history")
    audit_verifications.set_defaults(func=cmd_audit_verifications)
    audit_validate = audit_sub.add_parser(
        "validate", help="Add verification to audit log (signs with your private key)")
    audit_validate.set_defaults(func=cmd_audit_validate)

    # Enable tab completion if argcomplete is available
    if ARGCOMPLETE_AVAILABLE:
        argcomplete.autocomplete(parser)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
