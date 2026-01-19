FROM python:3.11-slim

WORKDIR /app

# Install Root CA in system trust store
COPY certs/root.crt /usr/local/share/ca-certificates/secureshare-root.crt
RUN update-ca-certificates

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy client files
COPY cli.py .
COPY api_client.py .
COPY crypto.py .
COPY config.py .

# Create config directory
RUN mkdir -p /root/.sshare

# Set entrypoint to the CLI
ENTRYPOINT ["python3", "cli.py"]
