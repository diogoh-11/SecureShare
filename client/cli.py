#!/usr/bin/env python3
import argparse
import sys
import json
import getpass
import base64
import os
from webbrowser import get
import zipfile
import tempfile
from api_client import APIClient
from config import save_token, load_token, clear_token, save_config, get_config
from crypto import KeyManager

DEFAULT_SERVER = "https://localhost:8443"

def get_client():
    server = get_config("server", DEFAULT_SERVER)
    token = load_token()
    return APIClient(server, token)

def handle_response(response, success_message=None):
    try:
        data = response.json()
        if response.status_code in [200, 201]:
            if success_message:
                print(success_message)
            print(json.dumps(data, indent=2))
            return data
        else:
            print(f"Error {response.status_code}: {data.get('detail', 'Unknown error')}")
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
    elif args.action == "show":
        server = get_config("server", DEFAULT_SERVER)
        token = load_token()
        print(f"Server: {server}")
        print(f"Token: {'Set' if token else 'Not set'}")

def cmd_org_create(args):
    client = get_client()
    response = client.create_organization(args.name, args.admin)
    data = handle_response(response, "Organization created successfully")
    if data and "activation_code" in data:
        print(f"\nIMPORTANT: Save this activation code: {data['activation_code']}")

def cmd_activate(args):
    print("Generating RSA-4096 keypair...")
    km = KeyManager()
    public_pem, private_der = km.generate_keypair()

    print("Encrypting private key with your password...")
    encrypted_blob = km.create_encrypted_blob(private_der, args.password)

    print("Activating account...")
    client = get_client()
    response = client.activate(args.username, args.code, args.password, public_pem, encrypted_blob)
    handle_response(response, "Account activated successfully\nYour encrypted private key has been stored on the server.")

def cmd_login(args):
    client = get_client()
    response = client.login(args.username, args.password)
    data = handle_response(response, "Login successful")
    if data and "access_token" in data:
        save_token(data["access_token"])
        print("\nToken saved. You are now authenticated.")

def cmd_logout(args):
    client = get_client()
    response = client.logout()
    handle_response(response)
    clear_token()
    print("Logged out. Token cleared.")

def cmd_dept_create(args):
    client = get_client()
    response = client.create_department(args.name)
    handle_response(response, "Department created successfully")

def cmd_dept_list(args):
    client = get_client()
    response = client.list_departments()
    handle_response(response)

def cmd_dept_delete(args):
    client = get_client()
    response = client.delete_department(args.id)
    handle_response(response, f"Department {args.id} deleted")

def cmd_user_create(args):
    client = get_client()
    response = client.create_user(args.username)
    data = handle_response(response, "User created successfully")
    if data and "activation_code" in data:
        print(f"\nIMPORTANT: Save this activation code: {data['activation_code']}")

def cmd_user_list(args):
    client = get_client()
    response = client.list_users()
    handle_response(response)

def cmd_user_delete(args):
    client = get_client()
    response = client.delete_user(args.id)
    handle_response(response, f"User {args.id} deleted")

def cmd_user_info(args):
    client = get_client()
    response = client.get_user_info()
    handle_response(response)

def cmd_user_update_password(args):
    client = get_client()
    response = client.update_password(args.password)
    handle_response(response, "Password updated successfully")

def cmd_role_assign(args):
    client = get_client()
    response = client.assign_role(args.user_id, args.role)
    handle_response(response, f"Role '{args.role}' assigned to user {args.user_id} (previous role auto-revoked)")

def cmd_clearance_assign(args):
    client = get_client()
    departments = args.departments.split(",") if args.departments else []
    response = client.assign_clearance(args.user_id, args.level, departments, args.expires_at)
    handle_response(response, f"Clearance assigned to user {args.user_id}")

def cmd_clearance_get(args):
    client = get_client()
    response = client.get_clearance(args.user_id)
    handle_response(response)

def cmd_clearance_revoke(args):
    client = get_client()
    response = client.revoke_clearance(args.user_id, args.token_id)
    handle_response(response, f"Clearance token {args.token_id} revoked for user {args.user_id}")

def cmd_transfer_upload(args):
    client = get_client()

    # Public transfers don't use departments or recipients
    if args.public:
        departments = []
        recipients = []
    else:
        departments = args.departments.split(",") if args.departments else []
        recipients = args.recipients.split(",") if args.recipients else []

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

    recipients_dict = {}
    for r in recipients:
        res = client.get_user_key(r)
        key = res.json().get("public_key",None)
        if key is None:
            continue
        # encrypt key
        ekey = km.encrypt_with_public_key(file_key, key)

        recipients_dict[r] = ekey

    # Determine transfer mode
    if args.public:
        transfer_mode = "public"
        print("Creating public transfer (anyone with link can download)...")
    else:
        transfer_mode = "user"
        print(f"Uploading encrypted file (mode: {transfer_mode})...")
    response = client.upload_transfer(
        file_data,
        file_key,
        nonce,
        strategy_encryption,
        args.classification,
        departments,
        args.expiration,
        transfer_mode,
        recipients_dict,
    )

    data = handle_response(response, "File uploaded and encrypted successfully")

    # For public transfers, show the complete URL with key fragment
    if data and data.get("public_access_token"):
        server = get_config("server", DEFAULT_SERVER)
        file_key_b64 = base64.b64encode(file_key).decode('utf-8')
        public_url = f"{server}/api/public/{data['public_access_token']}#{file_key_b64}"
        print("\nPublic URL (share this link):")
        print(public_url)
        print("\nNote: The key is in the URL fragment (#) and never sent to the server.")

def cmd_transfer_list(args):
    client = get_client()
    response = client.list_transfers()
    handle_response(response)

def cmd_transfer_get(args):
    client = get_client()
    response = client.get_transfer(args.id, args.justification)
    handle_response(response)

def cmd_transfer_download(args):
    client = get_client()

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

    # Decrypt file
    print("Decrypting file...")
    try:
        decrypted_file_data = km.decrypt_file_fernet(encrypted_file_data, file_key)
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
    client = get_client()
    response = client.delete_transfer(args.id)
    handle_response(response, f"Transfer {args.id} deleted")

def cmd_transfer_download_public(args):
    """
    Download public transfer using URL with key in fragment
    Example: https://server/api/public/TOKEN#KEY_BASE64
    """
    import requests
    import urllib.parse

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

    # Remove fragment for actual download
    url_without_fragment = parsed._replace(fragment='').geturl()

    print(f"Downloading from: {url_without_fragment}")

    # Download encrypted file (no auth required)
    try:
        response = requests.get(url_without_fragment, verify=False)
        if response.status_code != 200:
            print(f"Error: {response.status_code}")
            try:
                error_data = response.json()
                print(error_data.get('detail', 'Unknown error'))
            except:
                print(response.text)
            sys.exit(1)

        encrypted_file_data = response.content
    except Exception as e:
        print(f"Error downloading file: {e}")
        sys.exit(1)

    # Decrypt file
    print("Decrypting file...")
    km = KeyManager()
    try:
        decrypted_file_data = km.decrypt_file_fernet(encrypted_file_data, file_key)
    except Exception as e:
        print(f"Error: Failed to decrypt file: {e}")
        sys.exit(1)

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
    client = get_client()
    response = client.get_audit_log()
    handle_response(response)

def cmd_audit_verify(args):
    client = get_client()
    response = client.verify_audit_chain()
    handle_response(response)

def cmd_audit_validate(args):
    client = get_client()
    response = client.add_audit_verification(args.entry_id, args.signature)
    handle_response(response, "Verification added to audit log")

def main():
    parser = argparse.ArgumentParser(
        description="SecureShare CLI - Secure file transfer with MLS and RBAC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sshare config set-server https://localhost:8443
  sshare org create --name "ACME Corp" --admin admin
  sshare activate --username admin --code CODE --password pass123
  sshare login --username admin --password pass123
  sshare dept create --name Engineering
  sshare user create --username alice
  sshare role assign --user-id 2 --role "Security Officer"
  sshare role assign --user-id 2 --role "Standard User"  # To revoke elevated role
  sshare clearance assign --user-id 2 --level "Top Secret" --departments "Engineering,Finance"
  sshare clearance revoke --user-id 2 --token-id 5  # Revoke clearance
  sshare transfer upload --file document.pdf --classification "Secret" --departments "Engineering" --encrypted-keys "2:key123"
  sshare transfer download --id 1
  sshare transfer download --id 1 --output custom_name.pdf
  sshare audit log
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    config_parser = subparsers.add_parser("config", help="Configure client settings")
    config_sub = config_parser.add_subparsers(dest="action")
    config_set = config_sub.add_parser("set-server", help="Set server URL")
    config_set.add_argument("url", help="Server URL")
    config_sub.add_parser("show", help="Show current configuration")
    config_parser.set_defaults(func=cmd_config)

    org_parser = subparsers.add_parser("org", help="Organization management")
    org_sub = org_parser.add_subparsers(dest="action")
    org_create = org_sub.add_parser("create", help="Create organization")
    org_create.add_argument("--name", required=True, help="Organization name")
    org_create.add_argument("--admin", required=True, help="Admin username")
    org_create.set_defaults(func=cmd_org_create)

    activate_parser = subparsers.add_parser("activate", help="Activate user account (generates RSA-4096 keys)")
    activate_parser.add_argument("--username", required=True, help="Username")
    activate_parser.add_argument("--code", required=True, help="Activation code")
    activate_parser.add_argument("--password", required=True, help="Password (also used to encrypt private key)")
    activate_parser.set_defaults(func=cmd_activate)

    login_parser = subparsers.add_parser("login", help="Login to get JWT token")
    login_parser.add_argument("--username", required=True, help="Username")
    login_parser.add_argument("--password", required=True, help="Password")
    login_parser.set_defaults(func=cmd_login)

    logout_parser = subparsers.add_parser("logout", help="Logout and clear token")
    logout_parser.set_defaults(func=cmd_logout)

    dept_parser = subparsers.add_parser("dept", help="Department management")
    dept_sub = dept_parser.add_subparsers(dest="action")
    dept_create = dept_sub.add_parser("create", help="Create department")
    dept_create.add_argument("--name", required=True, help="Department name")
    dept_create.set_defaults(func=cmd_dept_create)
    dept_list = dept_sub.add_parser("list", help="List departments")
    dept_list.set_defaults(func=cmd_dept_list)
    dept_delete = dept_sub.add_parser("delete", help="Delete department")
    dept_delete.add_argument("--id", type=int, required=True, help="Department ID")
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
    user_passwd = user_sub.add_parser("update-password", help="Update password")
    user_passwd.add_argument("--password", required=True, help="New password")
    user_passwd.set_defaults(func=cmd_user_update_password)

    role_parser = subparsers.add_parser("role", help="Role management")
    role_sub = role_parser.add_subparsers(dest="action")
    role_assign = role_sub.add_parser("assign", help="Assign role to user (replaces previous role)")
    role_assign.add_argument("--user-id", type=int, required=True, help="User ID")
    role_assign.add_argument("--role", required=True, choices=["Administrator", "Security Officer", "Trusted Officer", "Standard User", "Auditor"], help="Role name")
    role_assign.set_defaults(func=cmd_role_assign)

    clearance_parser = subparsers.add_parser("clearance", help="Clearance management")
    clearance_sub = clearance_parser.add_subparsers(dest="action")
    clearance_assign = clearance_sub.add_parser("assign", help="Assign clearance to user")
    clearance_assign.add_argument("--user-id", type=int, required=True, help="User ID")
    clearance_assign.add_argument("--level", required=True, choices=["Unclassified", "Confidential", "Secret", "Top Secret"], help="Clearance level")
    clearance_assign.add_argument("--departments", help="Comma-separated department names")
    clearance_assign.add_argument("--expires-at", default="2025-12-31", help="Expiration date (YYYY-MM-DD)")
    clearance_assign.set_defaults(func=cmd_clearance_assign)
    clearance_get = clearance_sub.add_parser("get", help="Get user clearances")
    clearance_get.add_argument("--user-id", type=int, required=True, help="User ID")
    clearance_get.set_defaults(func=cmd_clearance_get)
    clearance_revoke = clearance_sub.add_parser("revoke", help="Revoke clearance token")
    clearance_revoke.add_argument("--user-id", type=int, required=True, help="User ID")
    clearance_revoke.add_argument("--token-id", type=int, required=True, help="Clearance token ID")
    clearance_revoke.set_defaults(func=cmd_clearance_revoke)

    transfer_parser = subparsers.add_parser("transfer", help="File transfer management")
    transfer_sub = transfer_parser.add_subparsers(dest="action")
    transfer_upload = transfer_sub.add_parser("upload", help="Upload encrypted file(s)")
    transfer_upload.add_argument("--files", required=True, help="Comma-separated file paths (multiple files will be zipped)")
    transfer_upload.add_argument("--classification", required=True, choices=["Unclassified", "Confidential", "Secret", "Top Secret"], help="Classification level")
    transfer_upload.add_argument("--departments", help="Comma-separated department names (all users in departments)")
    transfer_upload.add_argument("--recipients", help="Comma-separated user IDs (specific users)")
    transfer_upload.add_argument("--public", action="store_true", help="Create public transfer (anyone with link can access)")
    transfer_upload.add_argument("--expiration", type=int, default=7, help="Expiration days (default: 7)")
    transfer_upload.add_argument("--strategy", type=str, default="GCM", help="Cypher used on encryption (either GCM or XChaCha) (default: GCM)")
    transfer_upload.set_defaults(func=cmd_transfer_upload)
    transfer_list = transfer_sub.add_parser("list", help="List transfers")
    transfer_list.set_defaults(func=cmd_transfer_list)
    transfer_get = transfer_sub.add_parser("get", help="Get transfer info")
    transfer_get.add_argument("--id", type=int, required=True, help="Transfer ID")
    transfer_get.add_argument("--justification", help="Justification for trusted officer access")
    transfer_get.set_defaults(func=cmd_transfer_get)
    transfer_download = transfer_sub.add_parser("download", help="Download transfer file")
    transfer_download.add_argument("--id", type=int, required=True, help="Transfer ID")
    transfer_download.add_argument("--output", help="Output file path (default: uses server-generated UUID)")
    transfer_download.add_argument("--justification", help="Justification for trusted officer access")
    transfer_download.set_defaults(func=cmd_transfer_download)
    transfer_delete = transfer_sub.add_parser("delete", help="Delete transfer")
    transfer_delete.add_argument("--id", type=int, required=True, help="Transfer ID")
    transfer_delete.set_defaults(func=cmd_transfer_delete)
    transfer_public = transfer_sub.add_parser("download-public", help="Download public transfer (no auth required)")
    transfer_public.add_argument("--url", required=True, help="Public URL with key in fragment (e.g., https://server/api/public/TOKEN#KEY)")
    transfer_public.add_argument("--output", help="Output file path (default: uses public token from URL)")
    transfer_public.set_defaults(func=cmd_transfer_download_public)

    audit_parser = subparsers.add_parser("audit", help="Audit log management")
    audit_sub = audit_parser.add_subparsers(dest="action")
    audit_log = audit_sub.add_parser("log", help="View audit log")
    audit_log.set_defaults(func=cmd_audit_log)
    audit_verify = audit_sub.add_parser("verify", help="Verify audit chain integrity")
    audit_verify.set_defaults(func=cmd_audit_verify)
    audit_validate = audit_sub.add_parser("validate", help="Add verification to audit log")
    audit_validate.add_argument("--entry-id", type=int, required=True, help="Entry ID")
    audit_validate.add_argument("--signature", required=True, help="Signature")
    audit_validate.set_defaults(func=cmd_audit_validate)

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
