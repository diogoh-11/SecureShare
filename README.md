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


## Docs 

### API endpoints

API endpoints are detailed on `/docs`.
