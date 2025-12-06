FROM python:3.11-slim

WORKDIR /app

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
