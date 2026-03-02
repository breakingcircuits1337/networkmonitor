FROM python:3.11-slim

RUN apt-get update && apt-get install -y tcpdump libpcap-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sensors/passive_fingerprint/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/passive_fingerprint/passive_fingerprint.py .
COPY common /app/common

ENV PYTHONUNBUFFERED=1

CMD ["python", "passive_fingerprint.py"]
