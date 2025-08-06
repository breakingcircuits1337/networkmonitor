FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y nmap python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY asset_discovery.py .
# Copy common config loader
COPY ../../common /app/common

ENV PYTHONUNBUFFERED=1

CMD ["python3", "asset_discovery.py"]