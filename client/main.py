import click
from api.client import APIClient
from crypto.key_manager import KeyManager
from storage.vault import Vault
import config


@click.group()
def cli():
    """SecureShare Client - Secure File Transfer System"""
    pass


@cli.command()
@click.option("--org-name", prompt="Organization name", help="Name of the organization")
@click.option("--admin-username", prompt="Admin username", help="Username for the administrator")
@click.option("--admin-password", prompt="Admin password", hide_input=True, 
              confirmation_prompt=True, help="Password for the administrator")
def create_org(org_name, admin_username, admin_password):
    """
    Bootstrap: Create a new organization with an administrator account.
    
    This command:
    1. Generates an RSA-4096 keypair
    2. Encrypts the private key with the admin password
    3. Sends the organization data to the server
    4. Saves the encrypted private key locally
    """
    
    click.echo("\n🚀 Creating new organization...\n")
    
    try:
        # 1. Gerar keypair RSA-4096
        click.echo("Step 1/4: Generating cryptographic keys")
        km = KeyManager()
        public_pem, private_der = km.generate_keypair()
        
        # 2. Encriptar private key com password
        click.echo("Step 2/4: Encrypting private key")
        blob = km.create_encrypted_blob(private_der, admin_password)
        
        # 3. Enviar para servidor
        click.echo("Step 3/4: Sending data to server")
        client = APIClient(config.SERVER_URL)
        
        client.post("/organizations", {
            "org_name": org_name,
            "admin_username": admin_username,
            "admin_password": admin_password,
            "admin_public_key": public_pem,
            "admin_private_key_blob": blob
        })
        
        # 4. Guardar blob localmente
        click.echo("Step 4/4: Saving private key to vault")
        vault = Vault(config.VAULT_PATH)
        vault.save_private_key_blob(admin_username, blob)
        
        # Sucesso
        click.echo("Organization created successfully!")
        
        
    except ValueError as e:
        click.echo(f"\nValidation Error: {e}\n", err=True)
        raise click.Abort()
    except Exception as e:
        click.echo(f"\nError: {e}\n", err=True)
        raise click.Abort()


@cli.command()
def list_vault():
    """List users stored in the local vault"""
    vault = Vault(config.VAULT_PATH)
    users = vault.list_users()
    
    if not users:
        click.echo("Vault is empty")
    else:
        click.echo(f"Users in vault ({vault.vault_path}):")
        for username in users:
            click.echo(f"  • {username}")


if __name__ == "__main__":
    cli()