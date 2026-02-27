FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y nmap python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sensors/asset_discovery/requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY sensors/asset_discovery/asset_discovery.py .
COPY common /app/common

ENV PYTHONUNBUFFERED=1

CMD ["python3", "asset_discovery.py"]