FROM python:3.11-slim
RUN apt-get update && apt-get install -y tcpdump libpcap-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY sensors/encrypted_traffic_analysis/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY sensors/encrypted_traffic_analysis/encrypted_traffic_analysis.py .
COPY common /app/common
ENV PYTHONUNBUFFERED=1
CMD ["python", "encrypted_traffic_analysis.py"]