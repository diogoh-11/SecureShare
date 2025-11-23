[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/zUSHElJ8)


## Run app

### Generate TLS Certificates
Before running the server, generate self-signed certificates for TLS:

```bash
# Create a directory for certificates
mkdir -p server/certs

# Generate private key and self-signed certificate (valid for 365 days)
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout server/certs/key.pem \
  -out server/certs/cert.pem \
  -days 365 \
  -subj "/C=PT/ST=State/L=City/O=Organization/CN=localhost"
```

### Run server
```bash
docker build -t sshare-server ./server
docker run -p 8443:8443 --name sshare-server-container \
  -v $(pwd)/server/certs:/app/certs \
  sshare-server
```

### Run the cli
```bash 

```

### Simple test for DB
```bash 

# Health check
curl -k https://localhost:8443/health

# Create ORG
curl -k -X POST https://localhost:8443/organizations \
  -H "Content-Type: application/json" \
  -d '{
    "org_name": "ACME Corp",
    "admin_username": "admin",
    "admin_password": "strongPassword123",
    "admin_public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "admin_private_key_blob": "encryptedPrivateKeyBlob..."
  }'
```


## Check in DB

```bash 
# Enter container
docker exec -it sshare-server-container bash

# Inspect SQLite
sqlite3 sshare.db
.tables
SELECT * FROM roles;
SELECT * FROM clearance_levels;
SELECT * FROM users;
SELECT * FROM organizations;
```


## Docs 

### API endpoints

API endpoints are detailed on `/docs`.
