FROM python:3.11-slim

RUN apt-get update && apt-get install -y tcpdump libpcap-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sensors/traffic_analysis/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/traffic_analysis/traffic_analysis.py .
COPY common /app/common

ENV PYTHONUNBUFFERED=1

CMD ["python", "traffic_analysis.py"]
