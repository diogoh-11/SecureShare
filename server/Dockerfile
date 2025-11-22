FROM python:3.13-slim

WORKDIR /app

# install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy files
COPY main.py .
COPY database.py .
COPY routers/ ./routers/
COPY schemas/ ./schemas/
COPY models/ ./models/
COPY services/ ./services/

RUN mkdir -p transfers
EXPOSE 8000

CMD ["python3", "main.py"]
