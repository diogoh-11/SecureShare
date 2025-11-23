FROM python:3.13-slim

WORKDIR /app


# Instalar dependências do sistema (sqlite3 CLI) para querys em docker
RUN apt-get update && \
    apt-get install -y sqlite3 && \
    rm -rf /var/lib/apt/lists/*


# install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy files
COPY main.py .
COPY database.py .
COPY enums.py .
COPY routers/ ./routers/
COPY schemas/ ./schemas/
COPY models/ ./models/
COPY services/ ./services/
COPY utils/ ./utils/
COPY static/ ./static/
COPY middlewares/ ./middlewares/


RUN mkdir -p transfers
EXPOSE 8443

CMD ["python3", "main.py"]
