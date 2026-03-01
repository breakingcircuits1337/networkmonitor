FROM python:3.11-slim
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY services/threat_intel/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/threat_intel/threat_intel.py .
COPY common /app/common
RUN mkdir -p /rules
ENV PYTHONUNBUFFERED=1 \
    SURICATA_CUSTOM_RULES=/rules/netwatch-ioc.rules
EXPOSE 5003
CMD ["python", "threat_intel.py"]
