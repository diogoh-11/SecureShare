# SecureShare

## Authors
- [Thiago Vicente (121497)](https://github.com/ThiagoAVicente)
- [Diogo Duarte (120482)](https://github.com/diogoh-11)
- [João Pereira (120010)](https://github.com/JPSP9547)

## Project Overview

A secure file transfer web application with end-to-end encryption, role-based access control (RBAC), and multi-level security (MLS) implementation. The system supports multiple organizations with data isolation between them.

## Project Structure

```bash
sshare/
├── server/                            # Backend API server
│   ├── routers/                       # API route handlers
│   │   ├── api.py                     # Main API router
│   │   ├── authentication.py          # Auth endpoints
│   │   ├── user_management.py         # User CRUD
│   │   ├── department_management.py   # Department CRUD
│   │   ├── file_transfer.py           # File upload/download
│   │   ├── organization_management.py # Org setup
│   │   └── audit.py                   # Audit log access
│   ├── services/                      # Business logic layer
│   │   ├── auth_service.py
│   │   ├── user_service.py
│   │   ├── transfer_service.py
│   │   ├── audit_service.py
│   │   └── seed_service.py
│   ├── models/                        # Database models
│   │   └── models.py
│   ├── schemas/                       # Pydantic schemas
│   ├── utils/                         # Utility functions
│   │   ├── crypto_utils.py            # Cryptographic helpers
│   │   ├── funcs.py                   # General utility functions
│   │   ├── mls_utils.py               # MLS policy enforcement
│   │   └── rbac.py                    # RBAC permission checks
│   ├── main.py                        # Application entry point
│   ├── database.py                    # Database configuration
│   ├── enums.py                       # Role and Clearance enums
│   ├── requirements.txt
│   └── Dockerfile         
│
├── client/                           # Command-line client
│   ├── cli.py                        # Main CLI application
│   ├── api_client.py                 # REST API client wrapper
│   ├── crypto.py                     # Cryptographic operations
│   ├── config.py                     # Client configuration
│   ├── sshare                        # Executable script
│   ├── requirements.txt  
│   └── test/             
│
├── docs/                             
│   └── guiao.pdf                     # Project specification
│
├── setup_test_env.sh                 # Test environment setup script
├── test_tampering_scenario.sh        # Audit tampering tests
└── README.md             
```

## Prerequisites

- Docker
- Docker Compose
- Xca (recommended)

## Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd sshare
```

### 2. Create the certificates and keys

Generate the certificate chain and place root.crt on `client/certs/root.crt` and chain.crt and key.pem in `server/certs/{key.pem, chain.crt}`.

We recommend using Xca to generate the certificate chain. Follow the steps on [our guideline](docs/xca_gen_certs.md)

### 3. Build containers and start server

```bash
# From project root
docker-compose up -d
```

This will:
- Build the server container
- Create certs using `mkcert`
- Start the https server on port 8443

### 4. Use client 

#### Use the docker container (recommended)
Step 2 already built `sshare-client` image.
```bash
# On project root
./sshare config set-server https://localhost:8443
./sshare -h
```

**Important - File Paths:** When specifying file paths for upload/download:
- Use **relative paths** from your current directory (e.g., `./file.txt`, `../../dir/file.pdf`)
- Or use **absolute paths** with `/home/user/` prefix (e.g., `/home/user/Documents/file.txt`)
- Do **NOT** use `~` (tilde) - it won't expand correctly inside the container

#### Run using python  

**Note:** this method is not recommended and to use it you must place  `root.crt` (see step **2**) in your system trusted certificates.

```bash
# install virtualenv
sudo apt install virtualenv

# create venv 
cd client
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt

# check if everything is fine
python3 cli.py config set-server https://localhost:8443
python3 cli.py --help
```

## Configuration

No environment variables required. 

## Workflows

### Start an organization

#### 1. Create organization and admin account

```bash
./sshare org create --name "ACME Corp" --admin admin
# This will print a activation token for the admin account, copy it
```

#### 2. Activate Administrator Account

```bash
./sshare activate --username admin --code <activation_code> --password <password>
```

#### 3. Login

```bash
./sshare login --username admin --password <password>
```

### Create users 
Login as the administrator first.

```bash 
# Create a user
./sshare --as ad user create --username alice
# copy alice user-id

```

### Assign security officer 
Login as the administrator first.

```bash
./sshare --as ad role assign --user-id <alice_user_id> --role so # or "Security Officer"
```

### Assign/revoke Auditors and Trusted Officers 

Just security officers can assign these roles.

```bash
# Create user first :)

./sshare --as so role assign --user-id <user_id> --role to # or "Trusted Officer"
./sshare --as so role assign --user-id <user_id> --role au # or "Auditor"

# list all users to see roles and clearances
./sshare --as <so or ad> user list  # "ad" to act as admin and "so" to act as security officer 

# revoke 
./sshare --as so role revoke --token-id <token_id>
```

### Assign/Revoke clearances 

Just security officers can assign/revoke clearances.

```bash 
# Secret clearance on a specific department 
./sshare --as so clearance assign --user-id <user_id> --level "Secret" --departments deti

# Assign organizational clearance 
./sshare --as so clearance assign --user-id <user_id> --level "Secret" --organizational
```

### Upload files

Need to act as *Trusted officer* or *Standard User*.

#### Upload public file (enforces MLS) 
```bash 
./sshare --as <to or su> --with <clearance_id> transfer upload-public --files <files separed by ","> --departments <department_label> --classification <classification_level>
# This prints a url with the key used for file encryption
```

#### Upload user-specific files 
```bash 
./sshare --as su transfer upload --files <files separed by ","> --recipients <recipients_ids separed by ",">
# This resturns a transfer id used for download
```

### Download files 

Need to act as *Trusted officer* or *Standard User*.

#### Download public file (enforces MLS) 
```bash 
./sshare --as <to or su>  --with <clearance_id> transfer download-public --url <url>
```

#### Download user-specific files 
```bash 
./sshare --as su transfer download --id <transfer_id>
```



### See full chain of Audit Logs
```bash
./sshare --as au audit log
```


### Verify the full chain as an Auditor
```bash
./sshare --as au audit verify
```


### Validate 
```bash
./sshare --as au audit validate
```
